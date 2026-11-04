"""
transport/udp_transport.py
--------------------------
Động cơ vận tải UDP tin cậy đa luồng (Multiplexed Reliable UDP Transport) (A1, A3, A4).
Cung cấp:
  1. Giao thức Stop-and-Wait ARQ tin cậy trên các luồng dữ liệu (Stream 0, 1, 3+).
  2. Phân luồng độc lập (Stream Multiplexing) chống Head-of-Line Blocking.
  3. Tính toán RTT & RTO động theo thuật toán chuẩn Jacobson / Karn.
  4. Bộ đếm PktNum tăng đơn điệu mỗi lần truyền tải (kể cả gửi lại) phục vụ Nonce AES-256-GCM.
  5. Luồng nhịp tim (Stream 2) Best-effort không chặn luồng dữ liệu.
  6. Tích hợp tùy chọn kênh nhiễu (LossyChannel) phục vụ kiểm thử chịu lỗi.
"""

import asyncio
import logging
import time
from typing import Callable, Dict, Optional, Set, Tuple

from shared.config import (
    DEFAULT_RTO,
    DEFAULT_WINDOW_SIZE,
    MAX_RETRIES,
    MAX_RTO,
    MIN_RTO,
    STREAM_CONTROL,
    STREAM_HEARTBEAT,
    PacketFlag,
    PacketType,
)
from shared.packet import Packet
from transport.lossy import LossyChannel

log = logging.getLogger("transport.udp")


class TransportError(Exception):
    """Ngoại lệ cơ sở tầng vận tải."""
    pass

class ConnectionLostError(TransportError):
    """Mất kết nối hoặc vượt quá số lần thử lại tối đa (MAX_RETRIES)."""
    pass


class UDPStream:
    """Đại diện cho 1 luồng dữ liệu logic trên kết nối UDP."""

    def __init__(self, stream_id: int, conn: "UDPConnection"):
        self.stream_id = stream_id
        self._conn = conn
        self._recv_queue: asyncio.Queue[bytes] = asyncio.Queue()
        self._closed: bool = False

    async def send(self, data: bytes) -> None:
        """Gửi dữ liệu qua luồng này một cách tin cậy."""
        if self._closed:
            raise ConnectionResetError(f"Stream {self.stream_id} đã bị đóng.")
        await self._conn.send_stream_data(self.stream_id, data)

    async def recv(self) -> bytes:
        """Nhận dữ liệu đến từ luồng này (chờ đến khi có gói tin)."""
        if self._closed and self._recv_queue.empty():
            raise ConnectionResetError(f"Stream {self.stream_id} đã bị đóng.")
        return await self._recv_queue.get()

    def feed_data(self, data: bytes) -> None:
        """Đưa dữ liệu đã xác thực và giải mã vào hàng đợi của luồng."""
        self._recv_queue.put_nowait(data)

    def close(self) -> None:
        """Đóng luồng logic."""
        self._closed = True


class _PendingAck:
    """Trạng thái một gói tin đang chờ phản hồi ACK."""
    def __init__(self, future: asyncio.Future, send_time: float):
        self.future = future
        self.send_time = send_time
        self.is_retransmitted = False


class UDPConnection(asyncio.DatagramProtocol):
    """
    Quản lý một kết nối UDP tin cậy hai chiều giữa Client và Server.
    Hỗ trợ cả môi trường socket thực và kênh mô phỏng LossyChannel.
    """

    def __init__(
        self,
        conn_id: int = 0,
        peer_addr: Optional[Tuple[str, int]] = None,
        encrypt_key: Optional[bytes] = None,
        decrypt_key: Optional[bytes] = None,
        channel: Optional[LossyChannel] = None,
        is_server: bool = False
    ):
        self.conn_id = conn_id
        self.peer_addr = peer_addr
        self.encrypt_key = encrypt_key
        self.decrypt_key = decrypt_key
        self.channel = channel
        self.is_server = is_server

        self.transport: Optional[asyncio.DatagramTransport] = None
        self._closed: bool = False

        # Bộ đếm gói tin truyền tải PktNum (dùng làm Nonce cho AES-GCM)
        self._pkt_num: int = 0

        # Trạng thái theo dõi từng Stream:
        # stream_id -> next_seq (cho chiều gửi)
        self._send_seq: Dict[int, int] = {}
        # stream_id -> expected_seq (cho chiều nhận)
        self._recv_seq: Dict[int, int] = {}
        # Các luồng đang mở
        self._streams: Dict[int, UDPStream] = {}

        # Quản lý hàng đợi chờ ACK: (stream_id, expected_ack_seq) -> _PendingAck
        self._pending_acks: Dict[Tuple[int, int], _PendingAck] = {}
        self._send_locks: Dict[int, asyncio.Lock] = {}

        # Thuật toán Jacobson/Karn tính RTT và RTO động
        self.srtt: Optional[float] = None
        self.rttvar: Optional[float] = None
        self.rto: float = DEFAULT_RTO

        # Thống kê
        self.packets_sent: int = 0
        self.packets_received: int = 0
        self.retransmissions: int = 0
        self.last_activity: float = time.time()

    def next_pkt_num(self) -> int:
        """Sinh PktNum tăng đơn điệu mỗi lần phát gói (kể cả phát lại)."""
        curr = self._pkt_num
        self._pkt_num = (self._pkt_num + 1) & 0xFFFFFFFF
        return curr

    def _get_send_lock(self, stream_id: int) -> asyncio.Lock:
        """Mỗi reliable stream có một Lock để thực thi Stop-and-Wait chuẩn."""
        if stream_id not in self._send_locks:
            self._send_locks[stream_id] = asyncio.Lock()
        return self._send_locks[stream_id]

    # ── Triển khai asyncio.DatagramProtocol ─────────────────────────────
    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        self.transport = transport

    def datagram_received(self, data: bytes, addr: Tuple[str, int]) -> None:
        """Nhận và xử lý gói tin nhị phân từ mạng."""
        self.last_activity = time.time()
        self.packets_received += 1

        # Nếu Server chưa gán địa chỉ Client, học địa chỉ từ gói đầu tiên
        if self.is_server and self.peer_addr is None:
            self.peer_addr = addr

        try:
            packet = Packet.unpack(data)
        except Exception as e:
            log.warning(f"Bỏ qua gói tin lỗi CRC32 hoặc hỏng định dạng từ {addr}: {e}")
            return

        self._process_incoming_packet(packet, addr)

    def error_received(self, exc: Exception) -> None:
        log.error(f"Lỗi tầng mạng UDP: {exc}")

    def connection_lost(self, exc: Optional[Exception]) -> None:
        log.info(f"Socket UDP đã đóng: {exc}")
        self._closed = True

    # ── Xử lý gói tin tiếp nhận ────────────────────────────────────────
    def _process_incoming_packet(self, packet: Packet, addr: Tuple[str, int]) -> None:
        stream_id = packet.stream_id

        # 1. Gói tin ACK
        if packet.is_ack():
            ack_key = (stream_id, packet.ack)
            pending = self._pending_acks.get(ack_key)
            if pending and not pending.future.done():
                # Cập nhật RTT nếu gói này không phải là gói phát lại (Karn's Algorithm)
                if not pending.is_retransmitted:
                    sample_rtt = time.time() - pending.send_time
                    self._update_rtt(sample_rtt)
                pending.future.set_result(packet)
            return

        # 2. Gói tin Nhịp tim (Heartbeat - Stream 2)
        if packet.is_heartbeat():
            if packet.pkt_type == PacketType.HEARTBEAT:
                # Tự động gửi lại HEARTBEAT_ACK
                ack_pkt = Packet(
                    pkt_type=PacketType.HEARTBEAT_ACK,
                    conn_id=self.conn_id,
                    stream_id=STREAM_HEARTBEAT,
                    pkt_num=self.next_pkt_num()
                )
                self._send_raw_packet(ack_pkt, addr)
            return

        # 3. Gói tin Dữ liệu tin cậy (DATA trên Stream 0, 1, 3+)
        if packet.pkt_type == PacketType.DATA:
            expected_seq = self._recv_seq.get(stream_id, 0)

            if packet.seq == expected_seq:
                # Đúng gói mong đợi!
                # Giải mã nếu gói có cờ mã hóa
                payload = packet.payload
                if packet.is_encrypted() and self.decrypt_key:
                    try:
                        payload = packet.decrypt_payload(self.decrypt_key)
                    except Exception as e:
                        log.error(f"Giải mã thất bại trên stream {stream_id}, seq {packet.seq}: {e}")
                        return

                # Chuyển payload vào stream queue (tự động tạo stream nếu gói đến trước khi open_stream)
                if stream_id not in self._streams:
                    self._streams[stream_id] = UDPStream(stream_id, self)
                self._streams[stream_id].feed_data(payload)

                # Tăng expected_seq
                self._recv_seq[stream_id] = (expected_seq + 1) & 0xFFFFFFFF

                # Gửi gói báo nhận ACK
                self._send_ack(stream_id, self._recv_seq[stream_id], addr)

            elif packet.seq < expected_seq:
                # Gói trùng lặp (Duplicate) do ACK bị thất lạc trên mạng
                # Gửi lại ACK ngay để bên gửi không tiếp tục retransmit
                self._send_ack(stream_id, self._recv_seq[stream_id], addr)

            else:
                # Gói đến sớm hơn thứ tự (trong Stop-and-Wait không nhận ngoài luồng)
                # Gửi lại ACK hiện tại
                self._send_ack(stream_id, expected_seq, addr)

    def _send_ack(self, stream_id: int, ack_seq: int, addr: Tuple[str, int]) -> None:
        """Gửi gói ACK độc lập."""
        ack_pkt = Packet(
            pkt_type=PacketType.ACK,
            flags=PacketFlag.ACK,
            conn_id=self.conn_id,
            stream_id=stream_id,
            pkt_num=self.next_pkt_num(),
            ack=ack_seq,
            window=DEFAULT_WINDOW_SIZE
        )
        self._send_raw_packet(ack_pkt, addr)

    def _send_raw_packet(self, packet: Packet, addr: Optional[Tuple[str, int]] = None) -> None:
        """Đóng gói nhị phân và gửi qua socket hoặc kênh LossyChannel."""
        target_addr = addr or self.peer_addr
        if not target_addr:
            return

        wire_bytes = packet.pack()
        self.packets_sent += 1

        if self.channel is not None:
            # Gửi qua kênh mô phỏng mất gói
            def _deliver(data: bytes):
                if self.transport and not self.transport.is_closing():
                    self.transport.sendto(data, target_addr)
            asyncio.create_task(self.channel.forward(wire_bytes, _deliver))
        else:
            # Gửi trực tiếp qua socket
            if self.transport and not self.transport.is_closing():
                self.transport.sendto(wire_bytes, target_addr)

    # ── Thuật toán Jacobson/Karn RTT/RTO ──────────────────────────────
    def _update_rtt(self, sample_rtt: float) -> None:
        """Cập nhật SRTT, RTTVAR và RTO theo chuẩn RFC 6298."""
        if sample_rtt <= 0:
            return
        if self.srtt is None:
            self.srtt = sample_rtt
            self.rttvar = sample_rtt / 2.0
        else:
            self.rttvar = (1.0 - 0.25) * self.rttvar + 0.25 * abs(self.srtt - sample_rtt)
            self.srtt = (1.0 - 0.125) * self.srtt + 0.125 * sample_rtt
        self.rto = min(max(self.srtt + 4.0 * self.rttvar, MIN_RTO), MAX_RTO)

    # ── Gửi dữ liệu Stop-and-Wait tin cậy ──────────────────────────────
    async def send_stream_data(self, stream_id: int, data: bytes) -> None:
        """
        Gửi dữ liệu với bảo đảm Stop-and-Wait ARQ và tự động truyền lại tối đa MAX_RETRIES.
        """
        lock = self._get_send_lock(stream_id)

        async with lock:
            seq = self._send_seq.get(stream_id, 0)
            expected_ack = (seq + 1) & 0xFFFFFFFF
            ack_key = (stream_id, expected_ack)

            loop = asyncio.get_running_loop()
            retries = 0
            current_rto = self.rto

            while retries <= MAX_RETRIES:
                # 1. Tạo gói tin DATA
                pkt = Packet(
                    pkt_type=PacketType.DATA,
                    conn_id=self.conn_id,
                    stream_id=stream_id,
                    pkt_num=self.next_pkt_num(),  # PktNum LUÔN MỚI kể cả retransmit!
                    seq=seq,
                    payload=data
                )

                if retries > 0:
                    pkt.flags |= PacketFlag.RETRANSMIT

                # 2. Mã hóa nếu có khóa bí mật
                if self.encrypt_key:
                    pkt.encrypt_payload(self.encrypt_key)

                # 3. Đăng ký Future chờ ACK
                ack_future = loop.create_future()
                pending = _PendingAck(ack_future, send_time=time.time())
                if retries > 0:
                    pending.is_retransmitted = True
                self._pending_acks[ack_key] = pending

                # 4. Gửi gói tin đi
                self._send_raw_packet(pkt)

                # 5. Chờ phản hồi ACK kèm Timeout
                try:
                    await asyncio.wait_for(ack_future, timeout=current_rto)
                    # Nhận ACK thành công!
                    self._pending_acks.pop(ack_key, None)
                    self._send_seq[stream_id] = expected_ack
                    return
                except asyncio.TimeoutError:
                    # Hết giờ chờ ACK -> Truyền lại
                    retries += 1
                    self.retransmissions += 1
                    current_rto = min(current_rto * 1.5, MAX_RTO)
                    log.debug(
                        f"[StopAndWait] Timeout sau {current_rto:.2f}s trên stream {stream_id}, "
                        f"seq {seq}. Thử lại lần {retries}/{MAX_RETRIES}."
                    )
                finally:
                    self._pending_acks.pop(ack_key, None)

            # Vượt quá số lần thử lại tối đa
            raise ConnectionLostError(
                f"Mất kết nối: Đã thử lại {MAX_RETRIES} lần trên stream {stream_id}, seq {seq} "
                f"nhưng không nhận được ACK từ đối tác."
            )

    # ── Giao tiếp cấp cao (Streams) ───────────────────────────────────
    async def open_stream(self, stream_id: int) -> UDPStream:
        """Mở một luồng dữ liệu logic theo stream_id."""
        if stream_id not in self._streams:
            self._streams[stream_id] = UDPStream(stream_id, self)
        return self._streams[stream_id]

    async def send_heartbeat(self) -> None:
        """Gửi gói tin nhịp tim (Stream 2) Best-effort."""
        pkt = Packet(
            pkt_type=PacketType.HEARTBEAT,
            conn_id=self.conn_id,
            stream_id=STREAM_HEARTBEAT,
            pkt_num=self.next_pkt_num()
        )
        self._send_raw_packet(pkt)

    def close(self) -> None:
        """Đóng kết nối và giải phóng tài nguyên socket."""
        self._closed = True
        for stream in self._streams.values():
            stream.close()
        for pending in self._pending_acks.values():
            if not pending.future.done():
                pending.future.cancel()
        self._pending_acks.clear()
        if self.transport and not self.transport.is_closing():
            self.transport.close()


async def create_udp_endpoint(
    local_port: int = 0,
    local_host: str = "127.0.0.1",
    peer_addr: Optional[Tuple[str, int]] = None,
    conn_id: int = 0,
    encrypt_key: Optional[bytes] = None,
    decrypt_key: Optional[bytes] = None,
    channel: Optional[LossyChannel] = None,
    is_server: bool = False
) -> Tuple[asyncio.DatagramTransport, UDPConnection]:
    """
    Hàm tiện ích khởi tạo socket UDP bất đồng bộ gắn với UDPConnection.
    """
    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: UDPConnection(
            conn_id=conn_id,
            peer_addr=peer_addr,
            encrypt_key=encrypt_key,
            decrypt_key=decrypt_key,
            channel=channel,
            is_server=is_server
        ),
        local_addr=(local_host, local_port)
    )
    return transport, protocol
