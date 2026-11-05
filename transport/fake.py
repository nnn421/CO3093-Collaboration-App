"""G5 (BẢN TẠM của B) - Fake transport trong RAM.

!!! File này thuộc trách nhiệm của Người A. B viết bản tối thiểu này chỉ để code + test
tầng server chạy được trước khi A bàn giao. Khi A có bản chính thức: GIỮ NGUYÊN các tên
và hành vi liệt kê trong docs/b_handoff.md mục "Interface B cần từ A", rồi thay file này.

Mô phỏng các tính chất mà tầng server dựa vào:
- mỗi stream là kênh tin cậy, đúng thứ tự, độc lập với stream khác (không HoL);
- hàng đợi có giới hạn => send() bị chặn khi bên nhận đọc chậm (back-pressure, như rwnd = 0);
- payload đi qua Cipher (encrypt bên gửi, decrypt bên nhận) với nonce = PktNum tăng dần,
  nên test bắt được lỗi ghép sai khóa c2s/s2c;
- close() ở một đầu => cả hai đầu gọi các callback on_disconnect đúng một lần;
- connect() mô phỏng gói HELLO (protocol_messages.md §4): mã hóa payload rỗng bằng khóa client,
  server phải giải mã được bằng cipher_lookup(conn_id), không thì từ chối;
- accept_stream() trả về stream tệp (id >= 3) do bên kia mở;
- stream 2 (heartbeat) là best-effort: hàng đợi đầy thì bỏ gói, không chặn.
"""
from __future__ import annotations

import asyncio
import itertools
import struct
from typing import Awaitable, Callable

from shared import config


class Cipher:
    overhead = 0

    def encrypt(self, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
        raise NotImplementedError

    def decrypt(self, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
        raise NotImplementedError


class NullCipher(Cipher):
    def encrypt(self, nonce, plaintext, aad):
        return plaintext

    def decrypt(self, nonce, ciphertext, aad):
        return ciphertext


def _nonce(n: int) -> bytes:
    return struct.pack(">I", n) + b"\x00" * 8


async def _race(coro, closed: asyncio.Event):
    """Chạy coro nhưng bỏ cuộc nếu closed được set. Trả (True, kết quả) hoặc (False, None)."""
    task = asyncio.ensure_future(coro)
    waiter = asyncio.ensure_future(closed.wait())
    try:
        done, _ = await asyncio.wait({task, waiter}, return_when=asyncio.FIRST_COMPLETED)
    except asyncio.CancelledError:
        task.cancel()
        waiter.cancel()
        raise
    if task in done:
        waiter.cancel()
        return True, task.result()
    task.cancel()
    return False, None


class FakeStream:
    def __init__(self, conn: "FakeConnection", stream_id: int, queue_size: int):
        self.conn = conn
        self.stream_id = stream_id
        self._q: asyncio.Queue = asyncio.Queue(maxsize=queue_size)

    async def send(self, data: bytes) -> None:
        conn = self.conn
        if conn.closed.is_set():
            raise ConnectionError("connection closed")
        pkt = conn._next_pktnum()
        aad = b"FAKEHDR" + struct.pack(">IH", pkt, self.stream_id)
        ct = conn.cipher.encrypt(_nonce(pkt), bytes(data), aad)
        peer_stream = conn.peer._open_remote(self.stream_id)
        if self.stream_id == config.STREAM_HEARTBEAT:          # best-effort: đầy thì bỏ, không chặn
            if not peer_stream._q.full():
                peer_stream._q.put_nowait((pkt, ct, aad))
            return
        ok, _ = await _race(peer_stream._q.put((pkt, ct, aad)), conn.closed)
        if not ok:
            raise ConnectionError("connection closed")

    async def recv(self) -> bytes:
        """Trả bytes; trả b'' khi kết nối đã đóng và hết dữ liệu."""
        while True:
            if not self._q.empty():
                item = self._q.get_nowait()
            else:
                if self.conn.closed.is_set():
                    return b""
                ok, item = await _race(self._q.get(), self.conn.closed)
                if not ok:
                    continue
            pkt, ct, aad = item
            try:
                return self.conn.cipher.decrypt(_nonce(pkt), ct, aad)
            except Exception:
                continue  # gói không giải mã được bị bỏ, như transport thật


class FakeConnection:
    def __init__(self, conn_id: int, cipher: Cipher, peer_addr, queue_size: int):
        self.conn_id = conn_id
        self.cipher = cipher
        self.peer_addr = peer_addr
        self.peer: FakeConnection | None = None
        self.closed = asyncio.Event()
        self._streams: dict[int, FakeStream] = {}
        self._new_streams: asyncio.Queue = asyncio.Queue()
        self._callbacks: list[Callable[["FakeConnection"], None]] = []
        self._pktnum = itertools.count()
        self._queue_size = queue_size
        self._fired = False

    def _next_pktnum(self) -> int:
        return next(self._pktnum)

    def open_stream(self, stream_id: int) -> FakeStream:
        s = self._streams.get(stream_id)
        if s is None:
            s = self._streams[stream_id] = FakeStream(self, stream_id, self._queue_size)
        return s

    def _open_remote(self, stream_id: int) -> FakeStream:
        """Bên kia gửi tới stream_id: tạo nếu chưa có, và báo cho accept_stream nếu là stream tệp."""
        is_new = stream_id not in self._streams
        s = self.open_stream(stream_id)
        if is_new and stream_id >= config.STREAM_FILE_BASE:
            self._new_streams.put_nowait(s)
        return s

    async def accept_stream(self) -> FakeStream | None:
        """Chờ stream tệp mới (id >= 3) do bên kia mở. None khi kết nối đóng."""
        if not self._new_streams.empty():
            return self._new_streams.get_nowait()
        ok, s = await _race(self._new_streams.get(), self.closed)
        return s if ok else None

    def on_disconnect(self, cb: Callable[["FakeConnection"], None]) -> None:
        self._callbacks.append(cb)

    def close(self) -> None:
        """Đóng cả hai đầu (mô phỏng FIN hoặc phát hiện timeout)."""
        for c in (self, self.peer):
            if c is not None and not c.closed.is_set():
                c.closed.set()
        for c in (self, self.peer):
            if c is not None:
                c._fire()

    def _fire(self) -> None:
        if self._fired:
            return
        self._fired = True
        for cb in self._callbacks:
            try:
                cb(self)
            except Exception:  # callback lỗi không được làm hỏng transport
                import logging
                logging.getLogger("transport.fake").exception("on_disconnect callback lỗi")


class FakeHub:
    """Thay cho UDPEndpoint trong test: server listen(), client connect()."""

    def __init__(self, queue_size: int = 64):
        self.queue_size = queue_size
        self._cipher_lookup: Callable[[int], Cipher | None] | None = None
        self._on_connection: Callable[[FakeConnection], Awaitable[None]] | None = None
        self._port = itertools.count(50000)
        self.server_conns: dict[int, FakeConnection] = {}

    def listen(self, cipher_lookup, on_connection) -> None:
        self._cipher_lookup = cipher_lookup
        self._on_connection = on_connection

    async def connect(self, conn_id: int, client_cipher: Cipher | None = None) -> FakeConnection:
        if self._cipher_lookup is None:
            raise ConnectionRefusedError("server chưa listen")
        # Mô phỏng gói HELLO: ConnID = conn_id, PktNum = 0, payload rỗng mã hóa bằng khóa của client.
        # UDP thật: HELLO không hợp lệ bị bỏ im lặng (client hết hạn chờ USER_LIST). Bản giả báo lỗi cho dễ test.
        client_cipher = client_cipher or NullCipher()
        server_cipher = self._cipher_lookup(conn_id)
        if server_cipher is None:
            raise ConnectionRefusedError(f"HELLO bị bỏ: conn_id {conn_id} không có trong bảng chờ")
        aad = b"FAKEHELLO" + struct.pack(">I", conn_id)
        try:
            server_cipher.decrypt(_nonce(0), client_cipher.encrypt(_nonce(0), b"", aad), aad)
        except Exception:
            raise ConnectionRefusedError("HELLO bị bỏ: không giải mã được bằng khóa của conn_id") from None
        addr = ("127.0.0.1", next(self._port))
        cli = FakeConnection(conn_id, client_cipher, ("127.0.0.1", config.UDP_PORT), self.queue_size)
        cli._pktnum = itertools.count(1)            # PktNum 0 đã dùng cho HELLO
        srv = FakeConnection(conn_id, server_cipher, addr, self.queue_size)
        cli.peer, srv.peer = srv, cli
        self.server_conns[conn_id] = srv
        asyncio.get_running_loop().create_task(self._on_connection(srv))
        return cli

    def close(self) -> None:
        for c in list(self.server_conns.values()):
            c.close()
