"""B7 (+ một phần B9) - Đọc Stream 1 và Stream 2 của từng client (protocol_messages.md §5, §6).

- MSG_BCAST: tới mọi người online trừ người gửi.
- MSG_DM: tới đúng người nhận; offline => ERROR USER_OFFLINE (ref = msg_id) về người gửi.
- FILE_*: chuyển cho FileRelay.
- Server dựng thông điệp MỚI, chỉ nhặt các trường cần từ client (danh sách trắng):
  `from` và `ts` luôn do server điền, mọi trường khác client gửi kèm đều rơi mất.
- Thông điệp sai => ERROR BAD_MESSAGE cho client đó, KHÔNG ngắt (trừ khi sai quá MAX_BAD_MESSAGES).
- Heartbeat: mỗi gói nhận được thì trả lại một gói, để client cũng thấy server còn sống.
"""
from __future__ import annotations

import logging

from shared import config, messages
from server.file_relay import FileRelay
from server.registry import Registry, Session

log = logging.getLogger("server.router")

HEARTBEAT_REPLY = b"\x01"


class Router:
    def __init__(self, registry: Registry, relay: FileRelay, max_bad: int = config.MAX_BAD_MESSAGES):
        self.registry = registry
        self.relay = relay
        self.max_bad = max_bad
        self.stats = {"bcast": 0, "dm": 0, "bad": 0}

    def route(self, s: Session, msg: dict) -> None:
        t = msg["type"]
        if t == messages.MSG_BCAST:
            out = {"type": t, "msg_id": msg["msg_id"], "from": s.username, "ts": messages.now_ms(),
                   "text": msg["text"]}
            self.registry.broadcast(out, exclude=s)
            self.stats["bcast"] += 1
        elif t == messages.MSG_DM:
            target = self.registry.get(msg["to"])
            if target is None:
                self.registry.deliver(s, messages.error(messages.E_USER_OFFLINE,
                                                        f"{msg['to']} không online", msg["msg_id"]))
                return
            out = {"type": t, "msg_id": msg["msg_id"], "from": s.username, "to": target.username,
                   "ts": messages.now_ms(), "text": msg["text"]}
            self.registry.deliver(target, out)
            self.stats["dm"] += 1
        else:
            self.relay.handle(s, msg)

    async def session_loop(self, s: Session) -> None:
        reader = messages.FrameReader(s.chat)
        bad = 0
        while True:
            try:
                raw = await reader.read()
            except ConnectionError:
                break
            self.registry.touch(s)
            try:
                msg = messages.validate_c2s(messages.decode(raw), messages.CHAT_C2S)
            except messages.ProtocolError as e:
                bad += 1
                self.stats["bad"] += 1
                self.registry.deliver(s, messages.error(e.code, str(e), e.ref))
                if bad > self.max_bad:
                    self.registry.remove(s, f"gửi quá {self.max_bad} thông điệp sai")
                    break
                continue
            try:
                self.route(s, msg)
            except Exception:   # lỗi xử lý một thông điệp không được giết vòng lặp của client
                log.exception("lỗi khi định tuyến %s từ %s", msg.get("type"), s.username)
                self.registry.deliver(s, messages.error(messages.E_SERVER, "lỗi máy chủ"))
        self.registry.remove(s, "stream chat đóng")


async def heartbeat_loop(registry: Registry, s: Session) -> None:
    """Stream 2: best-effort. Mỗi gói: cập nhật last_seen rồi trả lại một heartbeat (protocol_messages.md §6)."""
    hb = s.conn.open_stream(config.STREAM_HEARTBEAT)
    while True:
        data = await hb.recv()
        if not data:
            return
        registry.touch(s)
        await hb.send(HEARTBEAT_REPLY)
