"""Tầng UDP thật theo interface mà server B cần (docs/b_handoff.md, protocol_messages.md §4, §9).

!!! BẢN TẠM do B viết để chạy thử toàn hệ thống trên mạng thật. Phần này là việc của Người A
(A1-A10). Khi A có bản chính thức: giữ nguyên các tên dưới đây rồi thay file này.

Interface (giống transport/fake.py):
    ep = await UDPEndpoint.create(host, port, loss=0.0)
    ep.listen(cipher_lookup, on_connection)                 # phía server
    conn = await ep.connect(conn_id, cipher, (host, port))  # phía client: gửi gói HELLO
    conn.conn_id, conn.peer_addr, conn.open_stream(id), await conn.accept_stream(),
    conn.on_disconnect(cb), conn.close();  await stream.send(b), await stream.recv() (b"" khi đóng)

Header 31 byte, Big-Endian:
    Version 1B | Type 1B | Flags 1B | ConnID 4B | StreamID 2B | PktNum 4B | Seq 4B | Ack 4B | Window 4B | Length 2B | Checksum 4B
- Gửi:  header (Checksum = 0) -> ct = AES-GCM(nonce = PktNum ‖ 8 byte 0, payload, AAD = header) -> CRC32(header + ct).
- Nhận: kiểm CRC -> giải mã (AAD = header với Checksum = 0) -> kiểm phát lại theo PktNum.
- Mọi gói đều mã hóa, kể cả HELLO (khóa udp_c2s), ACK, heartbeat, FIN (T1, T6).
- PktNum tăng mỗi lần gửi, kể cả gửi lại, nên nonce không bao giờ lặp (trừ HELLO gửi lại: cùng nội dung rỗng).

Độ tin cậy (đơn giản): mỗi stream một cửa sổ trượt WINDOW_SIZE gói, ACK lũy tiến (Ack = seq tiếp theo
mong đợi), gói tới sớm được giữ lại, hết RTO thì gửi lại; RTO theo Jacobson/Karn. Window trong ACK là
số mảnh bên nhận còn chứa được (rwnd): đầy thì bên gửi chờ (T5). Stream 2 (heartbeat) không tin cậy.
Chưa có: SACK, điều khiển tắc nghẽn, quay vòng số Seq (tệp tối đa ~4 GiB nên không chạm 2^32 mảnh).
"""
from __future__ import annotations

import asyncio
import binascii
import collections
import logging
import random
import struct
import time
from typing import Awaitable, Callable

from shared import config
from shared.crypto import nonce_from_counter

log = logging.getLogger("transport.udp")

HDR = struct.Struct(">BBBIHIIIIHI")         # 31 byte
VERSION = 1
T_HELLO, T_DATA, T_ACK, T_FIN = 0x01, 0x03, 0x04, 0x07
F_RETRANSMIT = 0x10

PIECE = config.MAX_PACKET_PAYLOAD           # 1200 byte dữ liệu mỗi gói (31 + 1200 + 16 < 1472)
RECV_BUFFER_PIECES = 256                    # rwnd: số mảnh tối đa chờ tầng trên đọc, mỗi stream
HEARTBEAT_QUEUE = 16
REPLAY_WINDOW = 4096
MIN_RTO = 0.2
FIRST_RTO = 1.0     # RTO khi chưa có mẫu RTT: 1 giây theo RFC 6298 mục 2.1 (plan G4 ghi INITIAL_RTO = 2, xem docs)
MAX_BACKOFF_RTO = 4.0
TICK = 0.05


def _hdr(typ, flags, conn_id, sid, pkt, seq, ack, win, length, crc=0) -> bytes:
    return HDR.pack(VERSION, typ, flags, conn_id & 0xFFFFFFFF, sid & 0xFFFF, pkt & 0xFFFFFFFF,
                    seq & 0xFFFFFFFF, ack & 0xFFFFFFFF, min(win, 0xFFFFFFFF), length, crc)


def build_packet(cipher, typ, flags, conn_id, sid, pkt, seq, ack, win, payload: bytes) -> bytes:
    length = len(payload) + cipher.overhead
    aad = _hdr(typ, flags, conn_id, sid, pkt, seq, ack, win, length, 0)
    ct = cipher.encrypt(nonce_from_counter(pkt), payload, aad)
    crc = binascii.crc32(aad + ct) & 0xFFFFFFFF
    return aad[:-4] + struct.pack(">I", crc) + ct


def parse_packet(data: bytes):
    """Trả (fields, aad, ct) hoặc None nếu sai khung / sai CRC."""
    if len(data) < HDR.size:
        return None
    f = HDR.unpack_from(data)
    ver, length, crc = f[0], f[9], f[10]
    ct = data[HDR.size:]
    if ver != VERSION or length != len(ct):
        return None
    aad = data[:HDR.size - 4] + b"\x00\x00\x00\x00"
    if binascii.crc32(aad + ct) & 0xFFFFFFFF != crc:
        return None
    return f, aad, ct


class _Replay:
    """Cửa sổ chống phát lại theo PktNum (T2), mỗi chiều một cái."""

    def __init__(self):
        self.top = -1
        self.seen: set[int] = set()

    def accept(self, n: int) -> bool:
        if n <= self.top - REPLAY_WINDOW or n in self.seen:
            return False
        self.seen.add(n)
        if n > self.top:
            self.top = n
        if len(self.seen) > 2 * REPLAY_WINDOW:
            self.seen = {x for x in self.seen if x > self.top - REPLAY_WINDOW}
        return True


async def _race(aw, closed: asyncio.Event) -> bool:
    """Chờ aw; trả False nếu kết nối đóng trước."""
    t = asyncio.ensure_future(aw)
    w = asyncio.ensure_future(closed.wait())
    try:
        done, _ = await asyncio.wait({t, w}, return_when=asyncio.FIRST_COMPLETED)
    except asyncio.CancelledError:
        t.cancel()
        w.cancel()
        raise
    if t in done:
        w.cancel()
        return True
    t.cancel()
    return False


class _Out:
    __slots__ = ("data", "sent", "tries", "rto", "probe")

    def __init__(self, data: bytes):
        self.data, self.sent, self.tries, self.rto, self.probe = data, 0.0, 0, 0.0, False


class Stream:
    def __init__(self, conn: "Connection", sid: int):
        self.conn = conn
        self.stream_id = sid
        self.reliable = sid != config.STREAM_HEARTBEAT
        # nhận
        self._q: collections.deque[bytes] = collections.deque()
        self._has_data = asyncio.Event()
        self._expected = 0
        self._ooo: dict[int, bytes] = {}
        self._zero_advertised = False
        # gửi
        self._next_seq = 0
        self._unacked: dict[int, _Out] = {}
        self._peer_win = RECV_BUFFER_PIECES
        self._room = asyncio.Event()
        self._room.set()
        self._send_lock = asyncio.Lock()     # các mảnh của một lần send() nằm liền nhau

    # ---------------------------------------------------------------- gửi
    def _limit(self) -> int:
        if self._peer_win > 0:
            return min(config.WINDOW_SIZE, self._peer_win)
        return 0 if self._unacked else 1     # rwnd = 0: cho 1 gói thăm dò

    async def send(self, data: bytes) -> None:
        conn = self.conn
        if conn.closed.is_set():
            raise ConnectionError("connection closed")
        if not self.reliable:                # heartbeat: best-effort, không chặn, không gửi lại
            conn._send(T_DATA, 0, self.stream_id, 0, 0, 0, bytes(data))
            return
        async with self._send_lock:
            for i in range(0, len(data), PIECE):
                piece = bytes(data[i:i + PIECE])
                while len(self._unacked) >= self._limit():
                    self._room.clear()
                    if not await _race(self._room.wait(), conn.closed):
                        raise ConnectionError("connection closed")
                if conn.closed.is_set():
                    raise ConnectionError("connection closed")
                seq = self._next_seq
                self._next_seq += 1
                o = _Out(piece)
                o.probe = self._peer_win == 0
                self._unacked[seq] = o
                conn._transmit(self, seq, o, retransmit=False)

    def _on_ack(self, ack: int, win: int) -> None:
        now = time.monotonic()
        for seq in [s for s in self._unacked if s < ack]:
            o = self._unacked.pop(seq)
            if o.tries == 1:                 # Karn: chỉ đo RTT trên gói chưa gửi lại
                self.conn._rtt_sample(now - o.sent)
        self._peer_win = win
        self._room.set()

    # ---------------------------------------------------------------- nhận
    def _free(self) -> int:
        return max(0, RECV_BUFFER_PIECES - len(self._q) - len(self._ooo))

    def _on_data(self, seq: int, payload: bytes) -> None:
        if not self.reliable:
            if len(self._q) < HEARTBEAT_QUEUE:
                self._q.append(payload)
                self._has_data.set()
            return
        if seq >= self._expected and seq not in self._ooo and seq < self._expected + RECV_BUFFER_PIECES:
            if self._free() > 0:
                self._ooo[seq] = payload
                while self._expected in self._ooo:
                    self._q.append(self._ooo.pop(self._expected))
                    self._expected += 1
                self._has_data.set()
        free = self._free()
        if free == 0:
            self._zero_advertised = True
        self.conn._send(T_ACK, 0, self.stream_id, 0, self._expected, free, b"")

    async def recv(self) -> bytes:
        while not self._q:
            if self.conn.closed.is_set():
                return b""
            self._has_data.clear()
            if not await _race(self._has_data.wait(), self.conn.closed):
                return b""
        data = self._q.popleft()
        if self._zero_advertised and self._free() >= RECV_BUFFER_PIECES // 4:
            self._zero_advertised = False      # báo cửa sổ đã mở lại
            self.conn._send(T_ACK, 0, self.stream_id, 0, self._expected, self._free(), b"")
        return data


class Connection:
    def __init__(self, ep: "UDPEndpoint", conn_id: int, cipher, peer_addr, *, first_pkt: int,
                 idle_timeout: float | None):
        self.ep = ep
        self.conn_id = conn_id
        self.cipher = cipher
        self.peer_addr = peer_addr
        self.closed = asyncio.Event()
        self.idle_timeout = idle_timeout
        self.last_rx = time.monotonic()
        self.got_reply = False
        self._pkt = first_pkt
        self._replay = _Replay()
        self._streams: dict[int, Stream] = {}
        self._new_streams: asyncio.Queue = asyncio.Queue()
        self._callbacks: list[Callable] = []
        self._fired = False
        self.srtt: float | None = None
        self.rttvar = 0.0
        self.rto = FIRST_RTO
        self._timer = asyncio.get_running_loop().create_task(self._timer_loop())

    # ---------------------------------------------------------------- API
    def open_stream(self, stream_id: int) -> Stream:
        s = self._streams.get(stream_id)
        if s is None:
            s = self._streams[stream_id] = Stream(self, stream_id)
        return s

    async def accept_stream(self) -> Stream | None:
        if not self._new_streams.empty():
            return self._new_streams.get_nowait()
        t = asyncio.ensure_future(self._new_streams.get())
        if await _race(t, self.closed):
            return t.result()
        return None

    def on_disconnect(self, cb: Callable) -> None:
        self._callbacks.append(cb)

    def close(self) -> None:
        if self.closed.is_set():
            return
        try:
            for _ in range(2):              # FIN best-effort; bên kia còn hạn im lặng làm dự phòng
                self._send(T_FIN, 0, config.STREAM_CONTROL, 0, 0, 0, b"")
        except Exception:
            pass
        self._shutdown("close")

    # ---------------------------------------------------------------- nội bộ
    def _shutdown(self, why: str) -> None:
        if self.closed.is_set():
            return
        self.closed.set()
        self._timer.cancel()
        self.ep._forget(self)
        log.info("kết nối %#010x đóng (%s)", self.conn_id, why)
        if not self._fired:
            self._fired = True
            for cb in self._callbacks:
                try:
                    cb(self)
                except Exception:
                    log.exception("on_disconnect callback lỗi")

    def _next_pkt(self) -> int:
        n = self._pkt
        if n >= config.PKTNUM_LIMIT:
            self.ep.loop.call_soon(self._shutdown, "PktNum sắp tràn")
            raise ConnectionError("PktNum sắp tràn")
        self._pkt += 1
        return n

    def _send(self, typ, flags, sid, seq, ack, win, payload: bytes) -> None:
        if self.closed.is_set() and typ != T_FIN:
            return
        pkt = self._next_pkt()
        self.ep._sendto(build_packet(self.cipher, typ, flags, self.conn_id, sid, pkt, seq, ack, win, payload),
                        self.peer_addr)

    def _transmit(self, st: Stream, seq: int, o: _Out, retransmit: bool) -> None:
        o.sent = time.monotonic()
        o.tries += 1
        o.rto = self.rto if o.tries == 1 else min(o.rto * 2, MAX_BACKOFF_RTO)
        st_free = st._free()
        self._send(T_DATA, F_RETRANSMIT if retransmit else 0, st.stream_id, seq, st._expected, st_free, o.data)

    def _rtt_sample(self, r: float) -> None:
        if self.srtt is None:
            self.srtt, self.rttvar = r, r / 2
        else:
            self.rttvar = 0.75 * self.rttvar + 0.25 * abs(self.srtt - r)
            self.srtt = 0.875 * self.srtt + 0.125 * r
        self.rto = min(max(self.srtt + 4 * self.rttvar, MIN_RTO), float(config.MAX_RTO))

    async def _timer_loop(self) -> None:
        while True:
            await asyncio.sleep(TICK)
            now = time.monotonic()
            if self.idle_timeout and now - self.last_rx > self.idle_timeout:
                self._shutdown(f"{self.idle_timeout:g} giây không nhận được gói nào")
                return
            for st in list(self._streams.values()):
                for seq, o in list(st._unacked.items()):
                    if now - o.sent < o.rto:
                        continue
                    if o.probe and st._peer_win == 0:
                        o.tries = 0          # gói thăm dò cửa sổ 0 không tính vào số lần thử
                    if o.tries > config.MAX_RETRIES:
                        self._shutdown(f"gửi lại quá {config.MAX_RETRIES} lần không có ACK")
                        return
                    self._transmit(st, seq, o, retransmit=True)

    def _retransmit_all(self) -> None:
        for st in list(self._streams.values()):
            for seq, o in list(st._unacked.items()):
                self._transmit(st, seq, o, retransmit=True)

    def _on_packet(self, f, payload: bytes, addr) -> None:
        typ, sid, seq, ack, win = f[1], f[4], f[6], f[7], f[8]
        self.last_rx = time.monotonic()
        self.got_reply = True
        self.peer_addr = addr                 # T3: theo gói hợp lệ mới nhất
        if typ == T_FIN:
            self._shutdown("bên kia gửi FIN")
            return
        if typ == T_ACK:
            st = self._streams.get(sid)
            if st is not None:
                st._on_ack(ack, win)
            return
        if typ != T_DATA:
            return
        is_new = sid not in self._streams
        st = self.open_stream(sid)
        if is_new and sid >= config.STREAM_FILE_BASE:
            self._new_streams.put_nowait(st)
        st._on_data(seq, payload)


class UDPEndpoint(asyncio.DatagramProtocol):
    def __init__(self, loss: float = 0.0):
        self.loss = loss
        self.loop = asyncio.get_running_loop()
        self.transport: asyncio.DatagramTransport | None = None
        self.conns: dict[int, Connection] = {}
        self._cipher_lookup: Callable | None = None
        self._on_connection: Callable[[Connection], Awaitable[None]] | None = None
        self.dropped = 0

    @classmethod
    async def create(cls, host: str, port: int, *, loss: float = 0.0) -> "UDPEndpoint":
        """loss: tỷ lệ 0..1 bỏ gói ngẫu nhiên ở CẢ chiều gửi lẫn chiều nhận của endpoint này (mô phỏng mạng xấu)."""
        ep = cls(loss)
        await ep.loop.create_datagram_endpoint(lambda: ep, local_addr=(host, port))
        return ep

    @property
    def local_addr(self):
        return self.transport.get_extra_info("sockname")

    # ---------------------------------------------------------------- server
    def listen(self, cipher_lookup, on_connection) -> None:
        self._cipher_lookup = cipher_lookup
        self._on_connection = on_connection

    # ---------------------------------------------------------------- client
    async def connect(self, conn_id: int, cipher, peer_addr) -> Connection:
        """Gửi gói HELLO (PktNum 0, payload rỗng mã hóa bằng udp_c2s), lặp lại mỗi 1 s, tối đa 5 lần,
        đến khi nhận được gói đầu tiên của server. Tầng trên chờ USER_LIST để biết đã gắn xong."""
        conn = Connection(self, conn_id, cipher, peer_addr, first_pkt=1, idle_timeout=config.IDLE_TIMEOUT)
        self.conns[conn_id] = conn
        hello = build_packet(cipher, T_HELLO, 0, conn_id, config.STREAM_CONTROL, 0, 0, 0, 0, b"")

        async def _hello_retry():
            for _ in range(config.UDP_HELLO_MAX_TRIES):
                if conn.got_reply or conn.closed.is_set():
                    return
                self._sendto(hello, peer_addr)
                await asyncio.sleep(config.UDP_HELLO_RETRY_INTERVAL)
        self.loop.create_task(_hello_retry())
        return conn

    def close(self) -> None:
        for c in list(self.conns.values()):
            c.close()
        if self.transport is not None:
            self.transport.close()

    # ---------------------------------------------------------------- socket
    def connection_made(self, transport) -> None:
        self.transport = transport

    def error_received(self, exc) -> None:
        log.debug("lỗi socket UDP: %r", exc)       # Windows: ICMP port unreachable -> bỏ qua

    def _forget(self, conn: Connection) -> None:
        if self.conns.get(conn.conn_id) is conn:
            del self.conns[conn.conn_id]

    def _sendto(self, data: bytes, addr) -> None:
        if self.loss and random.random() < self.loss:
            self.dropped += 1
            return
        if self.transport is not None and not self.transport.is_closing():
            self.transport.sendto(data, addr)

    def datagram_received(self, data: bytes, addr) -> None:
        if self.loss and random.random() < self.loss:
            self.dropped += 1
            return
        p = parse_packet(data)
        if p is None:
            return
        f, aad, ct = p
        typ, conn_id, pkt = f[1], f[3], f[5]
        conn = self.conns.get(conn_id)
        if typ == T_HELLO:
            if conn is not None:
                # HELLO lặp lại: KHÔNG gắn lại. Nhưng nó cho biết client chưa nhận được gì (USER_LIST đầu tiên
                # có thể đã mất), nên gửi lại ngay các gói chưa ACK thay vì chờ hết RTO.
                if self._cipher_lookup is not None and addr == conn.peer_addr:
                    try:
                        conn.cipher.decrypt(nonce_from_counter(pkt), ct, aad)
                    except Exception:
                        return
                    conn._retransmit_all()
                return
            if self._cipher_lookup is None:
                return
            cipher = self._cipher_lookup(conn_id)
            if cipher is None:
                return
            try:
                cipher.decrypt(nonce_from_counter(pkt), ct, aad)
            except Exception:
                return                      # không có khóa đúng: bỏ im lặng
            conn = Connection(self, conn_id, cipher, addr, first_pkt=0, idle_timeout=None)
            conn._replay.accept(pkt)
            self.conns[conn_id] = conn
            self.loop.create_task(self._on_connection(conn))
            return
        if conn is None:
            return
        try:
            payload = conn.cipher.decrypt(nonce_from_counter(pkt), ct, aad)
        except Exception:
            return
        if not conn._replay.accept(pkt):
            return
        conn._on_packet(f, payload, addr)
