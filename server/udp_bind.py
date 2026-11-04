"""B4 - Gắn kết nối UDP với tài khoản vừa đăng nhập qua TCP (protocol_messages.md §4).

Luồng: LOGIN đúng -> SessionTable cấp conn_id + giữ 2 khóa UDP ở bảng CHỜ (tối đa UDP_BIND_TIMEOUT)
-> client gửi gói HELLO (loại gói transport, ConnID = conn_id, payload rỗng mã hóa bằng udp_c2s)
-> tầng transport (A) hỏi cipher_for(conn_id), giải mã được thì tạo kết nối và gọi on_connection(conn)
-> UdpBinder xóa conn_id khỏi bảng chờ (dùng một lần), tạo Session, đưa vào Registry.
   Registry gửi USER_LIST cho mọi người online, kể cả client mới: đó chính là xác nhận HELLO.

Vì sao an toàn: giải mã được HELLO nghĩa là người gửi có khóa udp_c2s mà chỉ phiên đăng nhập đó có.
Biết conn_id (nằm rõ trong header) thôi thì không giả được.
"""
from __future__ import annotations

import asyncio
import logging
import secrets
import time
from dataclasses import dataclass, field

from shared import config
from shared.crypto import SessionKeys
from transport.cipher import AESGCMCipher
from server.registry import Registry, Session

log = logging.getLogger("server.udp_bind")


@dataclass
class Pending:
    conn_id: int
    username: str
    cipher: AESGCMCipher
    created: float = field(default_factory=time.monotonic)
    bound: asyncio.Event = field(default_factory=asyncio.Event)


class SessionTable:
    """Bảng conn_id đang CHỜ gói HELLO."""

    def __init__(self, registry: Registry, bind_timeout: float = config.UDP_BIND_TIMEOUT):
        self.registry = registry
        self.bind_timeout = bind_timeout
        self.pending: dict[int, Pending] = {}

    def new_conn_id(self) -> int:
        while True:
            cid = secrets.randbits(32)
            if cid != 0 and cid not in self.pending and cid not in self.registry.by_conn:
                return cid

    def add_pending(self, username: str, keys: SessionKeys) -> Pending:
        cid = self.new_conn_id()
        p = Pending(cid, username, AESGCMCipher.for_server(keys))
        self.pending[cid] = p
        return p

    def discard(self, conn_id: int) -> None:
        self.pending.pop(conn_id, None)

    def cipher_for(self, conn_id: int):
        """Tầng A gọi khi nhận gói HELLO. None => bỏ gói im lặng (conn_id lạ, đã dùng, hoặc quá hạn)."""
        p = self.pending.get(conn_id)
        if p is None:
            return None
        if time.monotonic() - p.created > self.bind_timeout:   # hết hạn: kể cả khi TCP chưa kịp dọn
            self.discard(conn_id)
            return None
        return p.cipher


class UdpBinder:
    def __init__(self, table: SessionTable, registry: Registry, start_session):
        self.table = table
        self.registry = registry
        self.start_session = start_session      # callback(Session): khởi động các task của phiên

    async def on_connection(self, conn) -> None:
        """Tầng A gọi (qua create_task) sau khi đã giải mã được gói HELLO của conn.conn_id."""
        p = self.table.pending.pop(conn.conn_id, None)     # pop: mỗi conn_id chỉ gắn được MỘT lần
        if p is None:
            log.warning("HELLO với conn_id %#010x không còn trong bảng chờ -> đóng", conn.conn_id)
            conn.close()
            return
        s = Session(p.username, conn.conn_id, conn, conn.peer_addr)
        conn.on_disconnect(lambda _c, s=s: self.registry.remove(s, "transport disconnect"))
        self.start_session(s)
        self.registry.add(s)                # thay phiên cũ cùng tên nếu có, gửi USER_LIST (= xác nhận HELLO)
        p.bound.set()                       # kênh TCP đang chờ sự kiện này để đóng
        log.info("gắn UDP thành công: %s <- %s", s.username, conn.peer_addr)
