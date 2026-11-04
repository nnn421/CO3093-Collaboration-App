"""
server/udp_server.py
--------------------
Bộ điều phối và định tuyến UDP trung tâm (Central UDP Server & Message Router) (B1, B4, B7, B8, B10).
Lắng nghe trên cổng UDP 9001.

Nhiệm vụ cốt lõi:
  1. Xử lý bắt tay UDP HELLO (Stream 0): Gắn địa chỉ IP:Port của Client với ConnID đã xác thực.
  2. Báo nhận HELLO_ACK và phát thanh danh sách người dùng trực tuyến (USER_LIST).
  3. Định tuyến tin nhắn Chat trên Stream 1:
     - Tin nhắn phát thanh (MSG_BCAST) tới toàn bộ người dùng online.
     - Tin nhắn trực tiếp (MSG_DM) tới đích danh người nhận.
  4. Duy trì nhịp tim (Heartbeat - Stream 2) và tự động dọn dẹp các phiên quá hạn (15s).
  5. Xử lý ngắt kết nối chủ động (FIN / FIN_ACK) và cập nhật danh sách phòng.
"""

import asyncio
import json
import logging
import struct
import time
from typing import Any, Dict, List, Optional, Set, Tuple

from server.session_manager import ClientSession, SessionManager
from shared.config import (
    DEFAULT_RTO,
    DEFAULT_WINDOW_SIZE,
    HEARTBEAT_INTERVAL,
    HEARTBEAT_TIMEOUT,
    MAX_RETRIES,
    MAX_RTO,
    MIN_RTO,
    STREAM_CHAT,
    STREAM_CONTROL,
    STREAM_FILE_BASE,
    STREAM_HEARTBEAT,
    UDP_TRANSPORT_PORT,
    PacketFlag,
    PacketType,
)
from shared.packet import Packet

log = logging.getLogger("server.udp")


class SessionChannel:
    """Quản lý truyền vận Stop-and-Wait tin cậy riêng biệt cho từng ClientSession."""

    def __init__(self, session: ClientSession, server: "UDPServer"):
        self.session = session
        self.server = server
        self._send_seq: Dict[int, int] = {}
        self._recv_seq: Dict[int, int] = {}
        self._pending_acks: Dict[Tuple[int, int], asyncio.Future] = {}
        self._send_locks: Dict[int, asyncio.Lock] = {}

    def _get_send_lock(self, stream_id: int) -> asyncio.Lock:
        if stream_id not in self._send_locks:
            self._send_locks[stream_id] = asyncio.Lock()
        return self._send_locks[stream_id]

    def handle_ack(self, stream_id: int, ack_seq: int) -> None:
        """Nhận diện gói ACK từ client để giải phóng Future đang chờ."""
        ack_key = (stream_id, ack_seq)
        fut = self._pending_acks.get(ack_key)
        if fut and not fut.done():
            fut.set_result(True)

    async def send_reliable(self, stream_id: int, payload: bytes) -> None:
        """Gửi dữ liệu tin cậy Stop-and-Wait tới Client kèm mã hóa AES-256-GCM."""
        if not self.session.udp_addr:
            return

        lock = self._get_send_lock(stream_id)
        async with lock:
            seq = self._send_seq.get(stream_id, 0)
            expected_ack = (seq + 1) & 0xFFFFFFFF
            ack_key = (stream_id, expected_ack)

            loop = asyncio.get_running_loop()
            retries = 0
            current_rto = DEFAULT_RTO

            while retries <= MAX_RETRIES:
                pkt = Packet(
                    pkt_type=PacketType.DATA,
                    conn_id=self.session.conn_id,
                    stream_id=stream_id,
                    pkt_num=self.session.next_server_pkt_num(),
                    seq=seq,
                    payload=payload
                )

                if retries > 0:
                    pkt.flags |= PacketFlag.RETRANSMIT

                # Mã hóa bằng udp_s2c_key của session này
                pkt.encrypt_payload(self.session.udp_s2c_key)

                ack_future = loop.create_future()
                self._pending_acks[ack_key] = ack_future

                # Gửi gói ra socket
                self.server.send_packet(pkt, self.session.udp_addr)

                try:
                    await asyncio.wait_for(ack_future, timeout=current_rto)
                    # Thành công!
                    self._pending_acks.pop(ack_key, None)
                    self._send_seq[stream_id] = expected_ack
                    return
                except asyncio.TimeoutError:
                    retries += 1
                    current_rto = min(current_rto * 1.5, MAX_RTO)
                finally:
                    self._pending_acks.pop(ack_key, None)

            log.warning(
                f"Client '{self.session.username}' không phản hồi ACK sau {MAX_RETRIES} lần thử "
                f"trên stream {stream_id}, seq {seq}."
            )

    async def send_json_message(self, stream_id: int, msg: dict) -> None:
        """Đóng gói JSON message và gửi qua reliable stream."""
        body = json.dumps(msg, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        # Định dạng framing trên stream: [2 bytes Big-Endian Length][JSON UTF-8]
        framed = struct.pack(">H", len(body)) + body
        await self.send_reliable(stream_id, framed)


class UDPServer(asyncio.DatagramProtocol):
    """Máy chủ UDP đa luồng tiếp nhận, giải mã và định tuyến toàn bộ lưu lượng."""

    def __init__(
        self,
        session_manager: SessionManager,
        host: str = "0.0.0.0",
        port: int = UDP_TRANSPORT_PORT,
        user_db: Optional[Any] = None
    ):
        self.session_manager = session_manager
        self.user_db = user_db
        self.host = host
        self.port = port
        self.transport: Optional[asyncio.DatagramTransport] = None
        self._channels: Dict[int, SessionChannel] = {}  # conn_id -> SessionChannel
        self._heartbeat_task: Optional[asyncio.Task] = None
        self._running: bool = False

        # Quản lý luồng truyền File nhị phân (Stream 3+)
        self._file_transfers: Dict[str, dict] = {}  # transfer_id -> info
        self._file_stream_map: Dict[Tuple[int, int], Tuple[ClientSession, int]] = {}  # (src_conn_id, stream_id) -> (dest_session, dest_stream_id)
        self._next_file_stream_id: int = STREAM_FILE_BASE

    async def start(self) -> None:
        """Khởi chạy UDP Server và vòng quét nhịp tim định kỳ."""
        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(
            lambda: self,
            local_addr=(self.host, self.port)
        )
        self.transport = transport
        self._running = True
        self._heartbeat_task = asyncio.create_task(self._heartbeat_monitor())
        log.info(f"UDP Collaboration Server đang lắng nghe tại {self.host}:{self.port}")

    async def stop(self) -> None:
        """Dừng server và hủy task dọn dẹp."""
        self._running = False
        if self._heartbeat_task:
            self._heartbeat_task.cancel()
            try:
                await self._heartbeat_task
            except asyncio.CancelledError:
                pass
        if self.transport and not self.transport.is_closing():
            self.transport.close()
        log.info("UDP Server đã dừng.")

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        self.transport = transport

    def send_packet(self, packet: Packet, addr: Tuple[str, int]) -> None:
        """Gửi 1 gói tin nhị phân ra socket."""
        if self.transport and not self.transport.is_closing():
            self.transport.sendto(packet.pack(), addr)

    def _get_channel(self, session: ClientSession) -> SessionChannel:
        if session.conn_id not in self._channels:
            self._channels[session.conn_id] = SessionChannel(session, self)
        return self._channels[session.conn_id]

    def datagram_received(self, data: bytes, addr: Tuple[str, int]) -> None:
        """Tiếp nhận và định tuyến datagram UDP."""
        try:
            packet = Packet.unpack(data)
        except Exception as e:
            log.warning(f"Bỏ qua gói tin hỏng hoặc sai CRC32 từ {addr}: {e}")
            return

        conn_id = packet.conn_id
        session = self.session_manager.get_by_conn_id(conn_id)

        # ── 1. BẮT TAY UDP HELLO (Stream 0) ──────────────────────────────
        if packet.pkt_type == PacketType.HELLO:
            if not session:
                log.warning(f"Từ chối UDP HELLO: ConnID={conn_id:#010x} không tồn tại.")
                return

            # Gắn kết địa chỉ UDP
            self.session_manager.bind_udp_addr(conn_id, addr)
            session.update_activity()
            if self.user_db and session.username:
                self.user_db.set_user_online(session.username, True)

            # Phản hồi HELLO_ACK
            ack_pkt = Packet(
                pkt_type=PacketType.HELLO_ACK,
                flags=PacketFlag.ACK,
                conn_id=conn_id,
                stream_id=STREAM_CONTROL,
                pkt_num=session.next_server_pkt_num(),
                ack=packet.seq + 1
            )
            self.send_packet(ack_pkt, addr)
            log.info(f"Đã hoàn tất bắt tay UDP HELLO cho '{session.username}' tại {addr}.")

            # Phát thanh cập nhật danh sách người dùng online
            asyncio.create_task(self.broadcast_user_list())
            return

        if not session:
            return

        session.update_activity()
        channel = self._get_channel(session)

        # ── 2. GÓI TIN ACK ───────────────────────────────────────────────
        if packet.is_ack():
            channel.handle_ack(packet.stream_id, packet.ack)
            return

        # ── 3. NHỊP TIM HEARTBEAT (Stream 2) ────────────────────────────
        if packet.pkt_type == PacketType.HEARTBEAT:
            ack_pkt = Packet(
                pkt_type=PacketType.HEARTBEAT_ACK,
                conn_id=conn_id,
                stream_id=STREAM_HEARTBEAT,
                pkt_num=session.next_server_pkt_num()
            )
            self.send_packet(ack_pkt, addr)
            return

        # ── 4. NGẮT KẾT NỐI FIN (Stream 0) ──────────────────────────────
        if packet.pkt_type == PacketType.FIN:
            ack_pkt = Packet(
                pkt_type=PacketType.FIN_ACK,
                flags=PacketFlag.ACK,
                conn_id=conn_id,
                stream_id=STREAM_CONTROL,
                pkt_num=session.next_server_pkt_num(),
                ack=packet.seq + 1
            )
            self.send_packet(ack_pkt, addr)
            self._handle_client_disconnect(session)
            return

        # ── 5. GÓI DỮ LIỆU TIN CẬY (DATA) ───────────────────────────────
        if packet.pkt_type == PacketType.DATA:
            stream_id = packet.stream_id
            expected_seq = channel._recv_seq.get(stream_id, 0)

            if packet.seq == expected_seq:
                # Giải mã payload
                try:
                    payload = packet.decrypt_payload(session.udp_c2s_key)
                except Exception as e:
                    log.error(f"Lỗi giải mã gói tin từ '{session.username}': {e}")
                    return

                # Tăng seq và gửi ACK
                channel._recv_seq[stream_id] = (expected_seq + 1) & 0xFFFFFFFF
                ack_pkt = Packet(
                    pkt_type=PacketType.ACK,
                    flags=PacketFlag.ACK,
                    conn_id=conn_id,
                    stream_id=stream_id,
                    pkt_num=session.next_server_pkt_num(),
                    ack=channel._recv_seq[stream_id],
                    window=DEFAULT_WINDOW_SIZE
                )
                self.send_packet(ack_pkt, addr)

                # Xử lý nội dung gói tin trên từng Stream
                if stream_id == STREAM_CHAT:
                    self._handle_chat_message(session, payload)
                elif stream_id >= STREAM_FILE_BASE:
                    self._handle_file_chunk(session, stream_id, payload)

            elif packet.seq < expected_seq:
                # Gói trùng lặp: gửi lại ACK
                ack_pkt = Packet(
                    pkt_type=PacketType.ACK,
                    flags=PacketFlag.ACK,
                    conn_id=conn_id,
                    stream_id=stream_id,
                    pkt_num=session.next_server_pkt_num(),
                    ack=channel._recv_seq[stream_id],
                    window=DEFAULT_WINDOW_SIZE
                )
                self.send_packet(ack_pkt, addr)

    def _handle_chat_message(self, sender_session: ClientSession, framed_bytes: bytes) -> None:
        """Giải khung và định tuyến tin nhắn ứng dụng trên Stream 1."""
        if len(framed_bytes) < 2:
            return
        (length,) = struct.unpack(">H", framed_bytes[:2])
        body_bytes = framed_bytes[2:2 + length]

        try:
            msg = json.loads(body_bytes.decode("utf-8"))
        except Exception as e:
            log.warning(f"Tin nhắn JSON lỗi cú pháp từ '{sender_session.username}': {e}")
            return

        msg_type = msg.get("type")
        timestamp = time.time()

        if msg_type == "MSG_BCAST":
            content = msg.get("content", "")
            log.info(f"[BCAST] <{sender_session.username}>: {content}")
            if self.user_db:
                self.user_db.save_message(sender_session.username, None, content, False, timestamp)
            out_msg = {
                "type": "MSG_BCAST",
                "from": sender_session.username,
                "content": content,
                "timestamp": timestamp
            }
            asyncio.create_task(self.broadcast_message(out_msg))

        elif msg_type == "MSG_DM":
            to_user = msg.get("to", "").strip()
            content = msg.get("content", "")
            target_session = self.session_manager.get_by_username(to_user)

            if target_session and target_session.udp_connected:
                log.info(f"[DM] <{sender_session.username} -> {to_user}>: {content}")
                if self.user_db:
                    self.user_db.save_message(sender_session.username, to_user, content, True, timestamp)
                out_msg = {
                    "type": "MSG_DM",
                    "from": sender_session.username,
                    "to": to_user,
                    "content": content,
                    "timestamp": timestamp
                }
                # Gửi tới người nhận
                target_channel = self._get_channel(target_session)
                asyncio.create_task(target_channel.send_json_message(STREAM_CHAT, out_msg))
                # Đồng thời gửi lại cho chính người gửi để hiển thị trên giao diện của họ
                sender_channel = self._get_channel(sender_session)
                asyncio.create_task(sender_channel.send_json_message(STREAM_CHAT, out_msg))
            else:
                err_msg = {
                    "type": "ERROR",
                    "code": 404,
                    "message": f"Người dùng '{to_user}' hiện không trực tuyến."
                }
                sender_channel = self._get_channel(sender_session)
                asyncio.create_task(sender_channel.send_json_message(STREAM_CHAT, err_msg))

        elif msg_type == "GET_USERS":
            asyncio.create_task(self.broadcast_user_list())

        # ── ĐÀM PHÁN TRUYỀN TỆP TIN (FILE TRANSFER NEGOTIATION) ──────────
        elif msg_type == "FILE_OFFER":
            to_user = msg.get("to", "").strip()
            transfer_id = msg.get("transfer_id", "")
            target_session = self.session_manager.get_by_username(to_user)

            if target_session and target_session.udp_connected:
                # Cấp phát Stream ID riêng biệt (>= 3) cho lần truyền tệp này
                file_stream_id = self._next_file_stream_id
                self._next_file_stream_id += 1

                self._file_transfers[transfer_id] = {
                    "sender": sender_session,
                    "receiver": target_session,
                    "stream_id": file_stream_id,
                    "filename": msg.get("filename"),
                    "filesize": msg.get("filesize"),
                    "sha256": msg.get("sha256")
                }

                out_offer = dict(msg)
                out_offer["from"] = sender_session.username
                out_offer["stream_id"] = file_stream_id
                target_channel = self._get_channel(target_session)
                asyncio.create_task(target_channel.send_json_message(STREAM_CHAT, out_offer))
                log.info(
                    f"[FILE] Đã chuyển tiếp FILE_OFFER '{msg.get('filename')}' ({msg.get('filesize')}B) "
                    f"từ '{sender_session.username}' tới '{to_user}' trên Stream {file_stream_id}."
                )
            else:
                err_msg = {
                    "type": "ERROR",
                    "code": 404,
                    "message": f"Không thể gửi file: Người dùng '{to_user}' không online."
                }
                sender_channel = self._get_channel(sender_session)
                asyncio.create_task(sender_channel.send_json_message(STREAM_CHAT, err_msg))

        elif msg_type == "FILE_ACCEPT":
            transfer_id = msg.get("transfer_id", "")
            transfer = self._file_transfers.get(transfer_id)
            if transfer:
                sender_session = transfer["sender"]
                file_stream_id = transfer["stream_id"]

                # Ánh xạ luồng (sender_conn_id, stream_id) -> (receiver_session, stream_id)
                self._file_stream_map[(sender_session.conn_id, file_stream_id)] = (
                    transfer["receiver"],
                    file_stream_id
                )

                out_accept = dict(msg)
                out_accept["from"] = transfer["receiver"].username
                out_accept["stream_id"] = file_stream_id
                sender_channel = self._get_channel(sender_session)
                asyncio.create_task(sender_channel.send_json_message(STREAM_CHAT, out_accept))
                log.info(f"[FILE] '{transfer['receiver'].username}' đã chấp nhận file {transfer_id}.")

        elif msg_type == "FILE_DONE":
            transfer_id = msg.get("transfer_id", "")
            transfer = self._file_transfers.get(transfer_id)
            if transfer:
                sender_session = transfer["sender"]
                receiver_session = transfer["receiver"]
                file_stream_id = transfer["stream_id"]

                out_done = dict(msg)
                out_done["from"] = sender_session.username
                receiver_channel = self._get_channel(receiver_session)
                asyncio.create_task(receiver_channel.send_json_message(STREAM_CHAT, out_done))
                log.info(f"[FILE] Đã chuyển tiếp FILE_DONE cho transfer {transfer_id}.")

                # Dọn dẹp an toàn sau 30s để tránh ngắt giữa chừng các chunk đang bay
                async def _cleanup(tid: str, key: Tuple[int, int]):
                    await asyncio.sleep(30.0)
                    self._file_transfers.pop(tid, None)
                    self._file_stream_map.pop(key, None)

                asyncio.create_task(_cleanup(transfer_id, (sender_session.conn_id, file_stream_id)))

    def _handle_file_chunk(self, sender_session: ClientSession, stream_id: int, chunk_payload: bytes) -> None:
        """Chuyển tiếp (Relay) khối dữ liệu file nhị phân tới người nhận trên Stream chuyên dụng."""
        mapping = self._file_stream_map.get((sender_session.conn_id, stream_id))
        if not mapping:
            log.warning(f"Không tìm thấy luồng chuyển tiếp file cho ConnID={sender_session.conn_id:#010x}, Stream {stream_id}")
            return

        dest_session, dest_stream_id = mapping
        dest_channel = self._get_channel(dest_session)
        # Gửi tin cậy tới bên nhận (Stop-and-Wait tự động mã hóa bằng udp_s2c_key của dest)
        asyncio.create_task(dest_channel.send_reliable(dest_stream_id, chunk_payload))

    async def broadcast_message(self, msg: dict, exclude_conn_id: Optional[int] = None) -> None:
        """Phát thanh một thông điệp JSON tới tất cả người dùng đang trực tuyến."""
        active_sessions = [
            s for s in self.session_manager._by_conn_id.values()
            if s.udp_connected and s.conn_id != exclude_conn_id
        ]
        tasks = [
            self._get_channel(s).send_json_message(STREAM_CHAT, msg)
            for s in active_sessions
        ]
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def broadcast_user_list(self) -> None:
        """Gửi danh sách tất cả người dùng online và offline."""
        active_users = self.session_manager.get_active_users()
        active_set = set(active_users)

        all_users = []
        if self.user_db:
            all_users = self.user_db.get_all_users_status()
            for u in all_users:
                if u["username"] in active_set:
                    u["online"] = True
        else:
            all_users = [{"username": u, "online": True} for u in active_users]

        msg = {
            "type": "USER_LIST",
            "users": active_users,
            "all_users": all_users,
            "count": len(active_users)
        }
        await self.broadcast_message(msg)

    def _handle_client_disconnect(self, session: ClientSession) -> None:
        """Xử lý dọn dẹp khi người dùng ngắt kết nối."""
        log.info(f"Người dùng '{session.username}' đã ngắt kết nối.")
        if self.user_db and session.username:
            self.user_db.set_user_online(session.username, False)
        self._channels.pop(session.conn_id, None)
        self.session_manager.remove_session(session.conn_id)
        asyncio.create_task(self.broadcast_user_list())

    async def _heartbeat_monitor(self) -> None:
        """Tác vụ ngầm quét các phiên quá hạn mỗi 3 giây."""
        while self._running:
            try:
                await asyncio.sleep(3.0)
                expired = self.session_manager.cleanup_expired(HEARTBEAT_TIMEOUT)
                for s in expired:
                    if self.user_db and s.username:
                        self.user_db.set_user_online(s.username, False)
                    self._channels.pop(s.conn_id, None)
                if expired:
                    await self.broadcast_user_list()
            except asyncio.CancelledError:
                break
            except Exception as e:
                log.error(f"Lỗi trong vòng lặp nhịp tim: {e}")
