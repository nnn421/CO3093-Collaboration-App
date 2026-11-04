"""B8 - Trung chuyển tệp giữa hai client (protocol_messages.md §5.5–5.7 và §7).

Thỏa thuận (FILE_OFFER/ACCEPT/DONE) đi Stream 1. Dữ liệu (FILE_CHUNK) đi stream 3+:
  người gửi --[stream do người gửi tự chọn]--> server --[stream do server tự chọn]--> người nhận
Số stream chỉ có nghĩa trên từng chặng, nên KHÔNG nằm trong JSON. Bên nhận một stream mới
(accept_stream) nhận ra nó thuộc phiên nào nhờ transfer_id trong chunk đầu tiên.

Back-pressure: mỗi chunk được `await dst.send()` xong mới đọc chunk tiếp. Người nhận chậm
=> send() của server bị chặn => server ngừng đọc => tầng transport phía người gửi hãm lại.
Server chỉ giữ khoảng 1 chunk mỗi phiên trong RAM.

FILE_DONE chỉ được chuyển tiếp khi server đã chuyển ĐỦ `size` byte: DONE đi stream 1, chunk đi
stream 3+, hai stream không có thứ tự với nhau nên DONE có thể tới trước chunk cuối.
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass

from shared import config, messages
from server.registry import Registry, Session

log = logging.getLogger("server.file_relay")


@dataclass
class Transfer:
    tid: str                 # transfer_id dạng base64, như trong JSON
    tid_bytes: bytes         # 16 byte, như trong FILE_CHUNK
    sender: Session
    receiver: Session
    size: int
    name: str
    state: str = "OFFERED"   # OFFERED -> ACTIVE -> (xong | hủy)
    r_sid: int = 0           # stream server mở về phía người nhận
    attached: bool = False   # đã có stream chunk từ người gửi chưa
    relayed: int = 0
    chunks_done: bool = False
    done_sha: str | None = None
    pump: asyncio.Task | None = None
    timer: asyncio.TimerHandle | None = None


class FileRelay:
    def __init__(self, registry: Registry, offer_timeout: float = config.FILE_OFFER_TIMEOUT):
        self.registry = registry
        self.offer_timeout = offer_timeout
        self.transfers: dict[bytes, Transfer] = {}
        registry.on_removal(self._on_session_removed)

    # ---------------------------------------------------------------- thông điệp Stream 1
    def handle(self, s: Session, msg: dict) -> None:
        t = msg["type"]
        if t == messages.FILE_OFFER:
            self._offer(s, msg)
            return
        tr = self.transfers.get(messages.b64d(msg["transfer_id"]))
        if t == messages.FILE_ACCEPT:
            if tr is None or tr.receiver is not s or tr.state != "OFFERED":
                return self._err(s, messages.E_UNKNOWN_TRANSFER, msg["transfer_id"])
            self._accept(tr)
        elif t == messages.FILE_DONE:
            if tr is None or tr.sender is not s or tr.state != "ACTIVE":
                return self._err(s, messages.E_UNKNOWN_TRANSFER, msg["transfer_id"])
            tr.done_sha = msg["sha256"]
            self._maybe_finish(tr)

    def _err(self, s: Session, code: str, ref: str, detail: str = "") -> None:
        self.registry.deliver(s, messages.error(code, detail, ref))

    def _offer(self, s: Session, msg: dict) -> None:
        tid = msg["transfer_id"]
        tid_bytes = messages.b64d(tid)
        target = self.registry.get(msg["to"])
        if target is None:
            return self._err(s, messages.E_USER_OFFLINE, tid, f"{msg['to']} không online")
        if target is s:
            return self._err(s, messages.E_BAD_MESSAGE, tid, "không gửi tệp cho chính mình")
        if tid_bytes in self.transfers:
            return self._err(s, messages.E_BAD_MESSAGE, tid, "transfer_id trùng một phiên đang chạy")
        tr = Transfer(tid, tid_bytes, s, target, msg["size"], msg["name"])
        self.transfers[tid_bytes] = tr
        tr.timer = asyncio.get_running_loop().call_later(
            self.offer_timeout, lambda: self.abort(tr, "quá hạn chờ người nhận đồng ý") if tr.state == "OFFERED" else None)
        self.registry.deliver(target, {"type": messages.FILE_OFFER, "transfer_id": tid, "from": s.username,
                                       "to": target.username, "name": tr.name, "size": tr.size,
                                       "ts": messages.now_ms()})
        log.info("OFFER %s: %s -> %s, %d byte", tid, s.username, target.username, tr.size)

    def _accept(self, tr: Transfer) -> None:
        tr.state = "ACTIVE"
        if tr.timer:
            tr.timer.cancel()
        try:
            tr.r_sid = tr.receiver.alloc_out_stream()
        except OverflowError:
            return self.abort(tr, "người nhận hết Stream ID")
        self.registry.deliver(tr.sender, {"type": messages.FILE_ACCEPT, "transfer_id": tr.tid,
                                          "from": tr.receiver.username})
        if tr.size == 0:                    # tệp rỗng: không có chunk, chỉ chờ FILE_DONE
            tr.chunks_done = True

    # ---------------------------------------------------------------- stream chunk từ người gửi
    async def accept_loop(self, s: Session) -> None:
        """Task của mỗi phiên: nhận các stream mới mà client mở để gửi chunk."""
        while True:
            st = await s.conn.accept_stream()
            if st is None:
                return
            t = asyncio.get_running_loop().create_task(self._attach(s, st), name=f"chunks-{s.username}")
            s.tasks.append(t)

    async def _attach(self, s: Session, stream) -> None:
        reader = messages.FrameReader(stream)
        try:
            first = await reader.read()
            tid_bytes, _, _ = messages.unpack_chunk(first)
        except ConnectionError:
            return
        except messages.ProtocolError as e:
            return self._err(s, messages.E_BAD_MESSAGE, None, f"chunk đầu tiên không hợp lệ: {e}")
        tr = self.transfers.get(tid_bytes)
        if tr is None or tr.sender is not s or tr.state != "ACTIVE" or tr.attached:
            return self._err(s, messages.E_UNKNOWN_TRANSFER, messages.b64e(tid_bytes))
        tr.attached = True
        tr.pump = asyncio.current_task()
        await self._pump(tr, reader, first)

    async def _pump(self, tr: Transfer, reader: messages.FrameReader, payload: bytes) -> None:
        dst = tr.receiver.conn.open_stream(tr.r_sid)
        try:
            while True:
                self.registry.touch(tr.sender)      # gói nào của client cũng tính là còn sống, kể cả chunk tệp
                ctid, off, data = messages.unpack_chunk(payload)
                if ctid != tr.tid_bytes:
                    raise messages.ProtocolError("chunk mang transfer_id khác")
                if off != tr.relayed or off + len(data) > tr.size:
                    raise messages.ProtocolError(f"offset sai: nhận {off}, cần {tr.relayed}")
                await dst.send(messages.frame(payload))
                tr.relayed += len(data)
                if tr.relayed == tr.size:
                    break
                payload = await reader.read()
            tr.chunks_done = True
            self._maybe_finish(tr)
        except asyncio.CancelledError:
            raise
        except messages.ProtocolError as e:
            log.warning("relay %s hỏng: %s", tr.tid, e)
            self.abort(tr, f"chunk không hợp lệ: {e}")
        except ConnectionError:
            self.abort(tr, "một bên mất kết nối")
        except Exception:
            log.exception("relay %s lỗi", tr.tid)
            self.abort(tr, "lỗi máy chủ")

    def _maybe_finish(self, tr: Transfer) -> None:
        if not (tr.chunks_done and tr.done_sha):
            return
        self.registry.deliver(tr.receiver, {"type": messages.FILE_DONE, "transfer_id": tr.tid,
                                            "sha256": tr.done_sha, "from": tr.sender.username})
        self._cleanup(tr)
        log.info("DONE %s: %d byte", tr.tid, tr.relayed)

    # ---------------------------------------------------------------- hủy / dọn
    def abort(self, tr: Transfer, reason: str) -> None:
        """Gửi ERROR FILE_ABORTED cho cả hai bên còn online."""
        if self.transfers.get(tr.tid_bytes) is not tr:
            return
        self._cleanup(tr)
        if tr.pump and tr.pump is not asyncio.current_task():
            tr.pump.cancel()
        for party in (tr.sender, tr.receiver):
            self.registry.deliver(party, messages.error(messages.E_FILE_ABORTED, reason, tr.tid))
        log.info("ABORT %s: %s", tr.tid, reason)

    def _cleanup(self, tr: Transfer) -> None:
        self.transfers.pop(tr.tid_bytes, None)
        if tr.timer:
            tr.timer.cancel()

    def _on_session_removed(self, s: Session) -> None:
        for tr in [t for t in self.transfers.values() if s in (t.sender, t.receiver)]:
            self.abort(tr, f"{s.username} đã rời mạng")
