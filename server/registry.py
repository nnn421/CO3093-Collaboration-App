"""B5 - Bảng người dùng trực tuyến.

Thiết kế quan trọng:
1. Mỗi Session có một hàng đợi gửi (outbox) + một task ghi riêng. Router chỉ put_nowait vào outbox,
   không bao giờ await việc gửi -> một client mạng chậm KHÔNG làm chậm broadcast tới người khác.
   Outbox đầy (client chậm quá OUTBOX_MAX thông điệp) => ngắt client đó.
2. remove() chỉ xóa nếu session trong bảng CHÍNH LÀ session đó. Lý do: khi đăng nhập lại, phiên cũ
   bị ngắt; callback on_disconnect của phiên cũ đến muộn không được xóa nhầm phiên mới.
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Callable

from shared import config, messages

log = logging.getLogger("server.registry")


class Session:
    def __init__(self, username: str, conn_id: int, conn, udp_addr, outbox_max: int = config.OUTBOX_MAX):
        self.username = username
        self.conn_id = conn_id
        self.conn = conn
        self.udp_addr = udp_addr
        self.last_seen = time.monotonic()
        self.chat = conn.open_stream(config.STREAM_CHAT)
        self.outbox: asyncio.Queue[bytes] = asyncio.Queue(maxsize=outbox_max)
        self.tasks: list[asyncio.Task] = []
        self.closed = False
        self._next_out_stream = config.STREAM_FILE_BASE   # stream tệp server mở về phía client này (đánh số riêng)

    def __repr__(self):
        return f"<Session {self.username} conn={self.conn_id:#010x} {self.udp_addr}>"

    def enqueue(self, msg: dict) -> bool:
        try:
            self.outbox.put_nowait(messages.frame(messages.encode(msg)))
            return True
        except asyncio.QueueFull:
            return False

    async def writer_loop(self) -> None:
        while True:
            data = await self.outbox.get()
            await self.chat.send(data)       # ConnectionError => task kết thúc, on_disconnect lo phần còn lại

    def alloc_out_stream(self) -> int:
        sid = self._next_out_stream
        if sid > config.STREAM_ID_MAX:
            raise OverflowError("hết Stream ID cho tệp trên kết nối này")
        self._next_out_stream += 1           # không tái sử dụng: tránh dữ liệu cũ lẫn vào phiên mới
        return sid

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        current = asyncio.current_task()
        for t in self.tasks:
            if t is not current:
                t.cancel()
        try:
            self.conn.close()
        except Exception:
            log.exception("đóng kết nối của %s lỗi", self.username)


class Registry:
    def __init__(self, idle_timeout: float = config.IDLE_TIMEOUT,
                 replaced_grace: float = config.SESSION_REPLACED_GRACE):
        self.idle_timeout = idle_timeout
        self.replaced_grace = replaced_grace
        self.sessions: dict[str, Session] = {}
        self.by_conn: dict[int, Session] = {}
        self._removal_listeners: list[Callable[[Session], None]] = []

    # ---------------------------------------------------------------- truy vấn
    def get(self, username: str) -> Session | None:
        return self.sessions.get(username)

    def online(self) -> list[str]:
        return sorted(self.sessions)

    def __len__(self):
        return len(self.sessions)

    def on_removal(self, cb: Callable[[Session], None]) -> None:
        self._removal_listeners.append(cb)

    # ---------------------------------------------------------------- thay đổi
    def add(self, s: Session) -> None:
        old = self.sessions.get(s.username)
        if old is not None:
            # protocol_messages.md §5.4: báo SESSION_REPLACED cho phiên cũ, cho nó một chút thời gian nhận, rồi đóng
            log.info("%s đăng nhập ở nơi khác -> thay phiên cũ %s", s.username, old)
            self._detach(old, "replaced")
            old.enqueue(messages.error(messages.E_SESSION_REPLACED, "tài khoản vừa đăng nhập ở nơi khác"))
            asyncio.get_running_loop().call_later(self.replaced_grace, old.close)
        self.sessions[s.username] = s
        self.by_conn[s.conn_id] = s
        log.info("online: %s (tổng %d)", s, len(self.sessions))
        self.broadcast_user_list()          # gửi cả cho client mới: đây là xác nhận gói HELLO

    def remove(self, s: Session, reason: str, broadcast: bool = True) -> None:
        if self._detach(s, reason) and broadcast:
            self.broadcast_user_list()
        s.close()

    def _detach(self, s: Session, reason: str) -> bool:
        """Xóa khỏi bảng NẾU phiên trong bảng đúng là s (callback muộn của phiên cũ không xóa nhầm phiên mới)."""
        if self.sessions.get(s.username) is not s:
            return False
        del self.sessions[s.username]
        self.by_conn.pop(s.conn_id, None)
        log.info("offline: %s (lý do: %s, còn %d)", s, reason, len(self.sessions))
        for cb in self._removal_listeners:
            try:
                cb(s)
            except Exception:
                log.exception("listener lỗi khi xóa %s", s)
        return True

    def touch(self, s: Session) -> None:
        s.last_seen = time.monotonic()

    # ---------------------------------------------------------------- gửi
    def deliver(self, s: Session, msg: dict) -> bool:
        if s.closed:
            return False
        if s.enqueue(msg):
            return True
        log.warning("outbox của %s đầy (client quá chậm) -> ngắt", s.username)
        self.remove(s, "outbox full")
        return False

    def broadcast(self, msg: dict, exclude: Session | None = None) -> int:
        n = 0
        for s in list(self.sessions.values()):
            if s is not exclude and self.deliver(s, msg):
                n += 1
        return n

    def broadcast_user_list(self) -> None:
        self.broadcast(messages.user_list(self.online()))

    # ---------------------------------------------------------------- quét định kỳ
    def sweep_once(self) -> int:
        now = time.monotonic()
        stale = [s for s in self.sessions.values() if now - s.last_seen > self.idle_timeout]
        for s in stale:
            self.remove(s, f"không có tín hiệu > {self.idle_timeout}s")
        return len(stale)

    def close_all(self, reason: str) -> None:
        for s in list(self.sessions.values()):
            self.remove(s, reason, broadcast=False)
