"""
client/udp_client.py
--------------------
Bộ giao tiếp UDP phía máy khách (Client-side UDP Session & Chat/File Client) (C2, C4, C5).
Chịu trách nhiệm:
  1. Bắt tay UDP HELLO (Stream 0) sử dụng conn_id nhận từ bắt tay TCP.
  2. Gửi và nhận tin nhắn Chat (MSG_BCAST, MSG_DM) trên Stream 1 có mã hóa AES-256-GCM.
  3. Gửi và nhận File nhị phân độc lập trên Stream 3+ (FILE_OFFER, FILE_ACCEPT, FILE_DONE).
  4. Định kỳ phát gói nhịp tim (HEARTBEAT) trên Stream 2 mỗi 5 giây.
  5. Gửi yêu cầu ngắt kết nối an toàn (FIN) khi thoát.
"""

import asyncio
import hashlib
import json
import logging
import os
import secrets
import struct
import time
from typing import Callable, Dict, List, Optional, Tuple

from shared.config import (
    CHUNK_SIZE,
    HEARTBEAT_INTERVAL,
    STREAM_CHAT,
    STREAM_CONTROL,
    STREAM_FILE_BASE,
    STREAM_HEARTBEAT,
    UDP_TRANSPORT_PORT,
    PacketFlag,
    PacketType,
)
from shared.packet import Packet
from transport.lossy import LossyChannel
from transport.udp_transport import UDPConnection, UDPStream, create_udp_endpoint

log = logging.getLogger("client.udp")


class UDPClient:
    """Phiên làm việc UDP hoàn chỉnh của Client bao gồm Chat và Truyền File."""

    def __init__(
        self,
        conn_id: int,
        session_keys: Dict[str, bytes],
        server_host: str = "127.0.0.1",
        server_port: int = UDP_TRANSPORT_PORT,
        downloads_dir: str = "downloads",
        loss_pct: float = 0.0
    ):
        self.conn_id = conn_id
        self.session_keys = session_keys
        self.server_host = server_host
        self.server_port = server_port
        self.downloads_dir = downloads_dir
        self.loss_pct = loss_pct

        os.makedirs(self.downloads_dir, exist_ok=True)

        self.transport: Optional[asyncio.DatagramTransport] = None
        self.connection: Optional[UDPConnection] = None

        self._chat_stream: Optional[UDPStream] = None
        self._heartbeat_task: Optional[asyncio.Task] = None
        self._receiver_task: Optional[asyncio.Task] = None
        self._file_tasks: List[asyncio.Task] = []
        self._running: bool = False

        # Quản lý truyền file nhị phân
        self._pending_file_accepts: Dict[str, asyncio.Future] = {}
        self._incoming_files: Dict[str, dict] = {}

        # Hàng đợi nhận thông điệp ứng dụng
        self.inbox: asyncio.Queue[dict] = asyncio.Queue()
        self.online_users: List[str] = []
        self.all_users: List[dict] = []

    async def connect(self) -> None:
        """
        Khởi tạo socket UDP và thực hiện bắt tay UDP HELLO (Stream 0).
        """
        peer_addr = (self.server_host, self.server_port)

        channel = None
        if self.loss_pct > 0.0:
            channel = LossyChannel(loss_pct=self.loss_pct, delay_ms=5.0, jitter_ms=2.0)
            log.warning(f"Đã kích hoạt giả lập mạng: Tỷ lệ mất gói = {self.loss_pct}%")

        self.transport, self.connection = await create_udp_endpoint(
            local_port=0,
            peer_addr=peer_addr,
            conn_id=self.conn_id,
            encrypt_key=self.session_keys["udp_c2s"],
            decrypt_key=self.session_keys["udp_s2c"],
            channel=channel,
            is_server=False
        )

        # ── BẮT TAY UDP HELLO (STREAM 0) ───────────────────────────────────
        loop = asyncio.get_running_loop()
        hello_future = loop.create_future()

        ack_key = (STREAM_CONTROL, 1)
        self.connection._pending_acks[ack_key] = type(
            "PendingHello", (), {"future": hello_future, "is_retransmitted": False, "send_time": time.time()}
        )()

        hello_pkt = Packet(
            pkt_type=PacketType.HELLO,
            conn_id=self.conn_id,
            stream_id=STREAM_CONTROL,
            pkt_num=self.connection.next_pkt_num(),
            seq=0
        )
        self.connection._send_raw_packet(hello_pkt)

        try:
            await asyncio.wait_for(hello_future, timeout=5.0)
            log.info(f"Bắt tay UDP HELLO thành công với Server {peer_addr}!")
        finally:
            self.connection._pending_acks.pop(ack_key, None)

        self._running = True
        self._chat_stream = await self.connection.open_stream(STREAM_CHAT)

        # Khởi động tác vụ nhận tin nhắn và phát nhịp tim
        self._receiver_task = asyncio.create_task(self._receive_loop())
        self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())

        # Chủ động gửi yêu cầu danh sách người dùng online ngay khi kết nối
        try:
            await self.send_chat_message({"type": "GET_USERS"})
        except Exception:
            pass

    async def _receive_loop(self) -> None:
        """Lắng nghe liên tục các thông điệp đến trên Stream 1."""
        while self._running:
            try:
                framed_data = await self._chat_stream.recv()
                if len(framed_data) < 2:
                    continue
                (length,) = struct.unpack(">H", framed_data[:2])
                body_bytes = framed_data[2:2 + length]
                msg = json.loads(body_bytes.decode("utf-8"))

                msg_type = msg.get("type")

                # Cập nhật danh sách online nếu là USER_LIST
                if msg_type == "USER_LIST":
                    self.online_users = msg.get("users", [])
                    self.all_users = msg.get("all_users", [])

                # Xử lý đàm phán File
                elif msg_type == "FILE_OFFER":
                    # Tự động chấp nhận file (Auto-accept) và mở luồng tiếp nhận
                    transfer_id = msg["transfer_id"]
                    file_stream_id = msg["stream_id"]
                    filesize = int(msg["filesize"])
                    filename = msg["filename"]

                    self._incoming_files[transfer_id] = {
                        "filename": filename,
                        "filesize": filesize,
                        "sha256": msg["sha256"],
                        "from": msg.get("from", "unknown"),
                        "stream_id": file_stream_id,
                        "buffer": bytearray(filesize),
                        "done_event": asyncio.Event()
                    }

                    # Khởi chạy task nhận chunks trên file_stream_id
                    f_task = asyncio.create_task(self._receive_file_stream(transfer_id, file_stream_id))
                    self._file_tasks.append(f_task)

                    # Phản hồi FILE_ACCEPT
                    await self._send_json({
                        "type": "FILE_ACCEPT",
                        "transfer_id": transfer_id,
                        "to": msg.get("from")
                    })

                elif msg_type == "FILE_ACCEPT":
                    transfer_id = msg.get("transfer_id")
                    fut = self._pending_file_accepts.get(transfer_id)
                    if fut and not fut.done():
                        fut.set_result(msg)

                elif msg_type == "FILE_DONE":
                    transfer_id = msg.get("transfer_id")
                    info = self._incoming_files.get(transfer_id)
                    if info:
                        # Báo hiệu đã gửi xong toàn bộ file
                        info["done_event"].set()

                await self.inbox.put(msg)
            except asyncio.CancelledError:
                break
            except Exception as e:
                log.error(f"Lỗi khi đọc tin nhắn chat: {e}")

    async def _receive_file_stream(self, transfer_id: str, stream_id: int) -> None:
        """Đọc liên tục các chunk dữ liệu nhị phân trên luồng tệp riêng biệt."""
        try:
            stream = await self.connection.open_stream(stream_id)
            info = self._incoming_files.get(transfer_id)
            if not info:
                return

            buf: bytearray = info["buffer"]
            total_size: int = info["filesize"]
            received_bytes = 0
            received_offsets = set()

            # Tiếp tục nhận cho đến khi đủ số byte theo thông báo FILE_OFFER
            while self._running and received_bytes < total_size:
                try:
                    chunk_payload = await asyncio.wait_for(stream.recv(), timeout=20.0)
                    if len(chunk_payload) < 4:
                        continue
                    (offset,) = struct.unpack(">I", chunk_payload[:4])
                    chunk_data = chunk_payload[4:]

                    buf[offset:offset + len(chunk_data)] = chunk_data
                    if offset not in received_offsets:
                        received_offsets.add(offset)
                        received_bytes += len(chunk_data)
                except asyncio.TimeoutError:
                    log.warning(f"Quá thời gian chờ nhận chunk tệp '{info['filename']}'.")
                    break

            # Chờ thêm tín hiệu FILE_DONE từ Stream điều khiển (Stream 1) nếu chưa nhận
            if not info["done_event"].is_set():
                try:
                    await asyncio.wait_for(info["done_event"].wait(), timeout=10.0)
                except asyncio.TimeoutError:
                    log.warning(f"Chưa nhận được FILE_DONE cho '{info['filename']}', tiến hành kiểm tra mã băm...")

            # Kiểm tra mã SHA-256 toàn vẹn dữ liệu
            assembled_bytes = bytes(buf[:total_size])
            actual_sha256 = hashlib.sha256(assembled_bytes).hexdigest()

            if actual_sha256.lower() == info["sha256"].lower():
                os.makedirs(self.downloads_dir, exist_ok=True)
                save_path = os.path.join(self.downloads_dir, info["filename"])
                with open(save_path, "wb") as f:
                    f.write(assembled_bytes)
                log.info(f"Đã lưu tệp '{info['filename']}' ({len(assembled_bytes)}B) vào {save_path}.")

                # Lưu metadata kèm thông tin người gửi
                try:
                    meta_file = os.path.join(self.downloads_dir, ".metadata.json")
                    meta_data = {}
                    if os.path.exists(meta_file):
                        try:
                            with open(meta_file, "r", encoding="utf-8") as mf:
                                meta_data = json.load(mf)
                        except Exception:
                            meta_data = {}
                    meta_data[info["filename"]] = {
                        "filename": info["filename"],
                        "sender": info["from"],
                        "size": total_size,
                        "sha256": actual_sha256,
                        "received_at": time.time()
                    }
                    with open(meta_file, "w", encoding="utf-8") as mf:
                        json.dump(meta_data, mf, indent=2, ensure_ascii=False)
                except Exception as me:
                    log.warning(f"Lỗi lưu metadata tệp: {me}")

                # Báo sự kiện FILE_RECEIVED vào hộp thư inbox
                await self.inbox.put({
                    "type": "FILE_RECEIVED",
                    "filename": info["filename"],
                    "path": save_path,
                    "sha256": actual_sha256,
                    "from": info["from"]
                })
            else:
                log.error(
                    f"Sai mã SHA-256 tệp '{info['filename']}': nhận {actual_sha256} != {info['sha256']}. "
                    f"Đã nhận {received_bytes}/{total_size} bytes."
                )
        except asyncio.CancelledError:
            pass
        except Exception as e:
            log.error(f"Lỗi khi nhận chunk tệp trên Stream {stream_id}: {e}")

    async def _heartbeat_loop(self) -> None:
        """Gửi gói tin nhịp tim (Stream 2) định kỳ mỗi HEARTBEAT_INTERVAL."""
        while self._running:
            try:
                await asyncio.sleep(HEARTBEAT_INTERVAL)
                if self.connection and not self.connection._closed:
                    await self.connection.send_heartbeat()
            except asyncio.CancelledError:
                break
            except Exception as e:
                log.error(f"Lỗi gửi nhịp tim: {e}")

    async def send_broadcast(self, content: str) -> None:
        """Gửi tin nhắn phát thanh (MSG_BCAST) tới toàn bộ phòng."""
        msg = {
            "type": "MSG_BCAST",
            "content": content
        }
        await self._send_json(msg)

    async def send_dm(self, to_user: str, content: str) -> None:
        """Gửi tin nhắn riêng (MSG_DM) tới đích danh người dùng."""
        msg = {
            "type": "MSG_DM",
            "to": to_user,
            "content": content
        }
        await self._send_json(msg)

    async def send_file(self, to_user: str, file_bytes: bytes, filename: str) -> str:
        """
        Gửi một tệp tin nhị phân tới người dùng khác:
          1. Tính mã kiểm tra toàn vẹn SHA-256.
          2. Gửi FILE_OFFER trên Stream 1 và chờ FILE_ACCEPT từ người nhận.
          3. Mở Stream chuyên dụng được cấp phát (>= 3).
          4. Cắt file thành các chunk 1000 bytes kèm offset (4B) và gửi Stop-and-Wait tin cậy.
          5. Gửi FILE_DONE trên Stream 1 để báo hiệu kết thúc.
          
        Returns:
            Mã SHA-256 của tệp tin.
        """
        filesize = len(file_bytes)
        file_sha256 = hashlib.sha256(file_bytes).hexdigest()
        transfer_id = secrets.token_hex(8)

        # 1. Đăng ký Future chờ FILE_ACCEPT
        loop = asyncio.get_running_loop()
        accept_future = loop.create_future()
        self._pending_file_accepts[transfer_id] = accept_future

        # 2. Gửi FILE_OFFER trên Stream 1
        offer_msg = {
            "type": "FILE_OFFER",
            "to": to_user,
            "transfer_id": transfer_id,
            "filename": filename,
            "filesize": filesize,
            "sha256": file_sha256
        }
        await self._send_json(offer_msg)

        # 3. Chờ bên nhận chấp nhận
        try:
            accept_msg = await asyncio.wait_for(accept_future, timeout=10.0)
            file_stream_id = int(accept_msg["stream_id"])
        finally:
            self._pending_file_accepts.pop(transfer_id, None)

        log.info(f"Bắt đầu truyền '{filename}' ({filesize}B) trên Stream {file_stream_id}...")

        # 4. Mở luồng vận chuyển riêng biệt trên kết nối UDP
        stream = await self.connection.open_stream(file_stream_id)

        # 5. Cắt file thành các khối CHUNK_SIZE (1000B) và truyền đi
        offset = 0
        while offset < filesize:
            chunk = file_bytes[offset:offset + CHUNK_SIZE]
            chunk_payload = struct.pack(">I", offset) + chunk
            await stream.send(chunk_payload)
            offset += len(chunk)

        # 6. Báo hoàn tất qua Stream 1
        done_msg = {
            "type": "FILE_DONE",
            "to": to_user,
            "transfer_id": transfer_id,
            "stream_id": file_stream_id
        }
        await self._send_json(done_msg)
        log.info(f"Đã hoàn tất truyền tệp '{filename}' tới '{to_user}'.")
        return file_sha256

    async def _send_json(self, msg: dict) -> None:
        """Đóng khung và gửi qua Stream 1."""
        if not self._chat_stream:
            raise ConnectionError("Chưa kết nối UDP với server.")
        body = json.dumps(msg, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        framed = struct.pack(">H", len(body)) + body
        await self._chat_stream.send(framed)

    async def disconnect(self) -> None:
        """Gửi gói FIN và đóng kết nối an toàn."""
        self._running = False
        if self._heartbeat_task:
            self._heartbeat_task.cancel()
        if self._receiver_task:
            self._receiver_task.cancel()
        for t in self._file_tasks:
            t.cancel()

        if self.connection and not self.connection._closed:
            # Gửi gói FIN trên Stream 0
            fin_pkt = Packet(
                pkt_type=PacketType.FIN,
                conn_id=self.conn_id,
                stream_id=STREAM_CONTROL,
                pkt_num=self.connection.next_pkt_num(),
                seq=0
            )
            self.connection._send_raw_packet(fin_pkt)
            await asyncio.sleep(0.05)
            self.connection.close()
        log.info("Client UDP đã ngắt kết nối.")
