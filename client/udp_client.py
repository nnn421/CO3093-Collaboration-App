"""
client/udp_client.py
--------------------
Phiên UDP của client theo docs/protocol_messages.md (§4-§7):
  - HELLO (transport) rồi chờ USER_LIST đầu tiên = server đã gắn UDP.
  - Stream 1: JSON có 2 byte độ dài (MSG_BCAST, MSG_DM, USER_LIST, ERROR, FILE_*).
  - Stream 2: heartbeat 1 byte mỗi 5 giây.
  - Stream 3+: FILE_CHUNK [16B transfer_id][4B offset][≤1000B], mỗi lần truyền một stream.

Các sự kiện đưa lên giao diện (inbox) là chính thông điệp nhận từ server, cộng thêm:
  - bản sao tin mình vừa gửi (server không gửi lại cho người gửi),
  - FILE_RECEIVED khi đã lưu tệp và kiểm SHA-256 khớp,
  - DISCONNECTED khi mất kết nối.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import time

from client.tcp_login import LoginResult, new_msg_id, new_transfer_id
from shared import config, messages
from transport.cipher import AESGCMCipher
from transport.udp_endpoint import UDPEndpoint

log = logging.getLogger("client.udp")

ACCEPT_TIMEOUT = 30          # chờ người nhận đồng ý (người nhận tự đồng ý nên thường rất nhanh)


class FileAborted(Exception):
    pass


class _Incoming:
    def __init__(self, tid: bytes, name: str, size: int, sender: str, part_path: str):
        self.tid, self.name, self.size, self.sender = tid, name, size, sender
        self.part_path = part_path
        self.received = 0
        self.done_sha: bytes | None = None
        self.finished = False


class UDPClient:
    def __init__(self, login: LoginResult, server_host: str, downloads_dir: str = "downloads",
                 loss_pct: float = 0.0):
        self.login = login
        self.username = login.username
        self.server_addr = (server_host, login.udp_port)
        self.downloads_dir = downloads_dir
        self.loss = max(0.0, min(loss_pct, 100.0)) / 100.0
        os.makedirs(downloads_dir, exist_ok=True)

        self.endpoint: UDPEndpoint | None = None
        self.conn = None
        self.chat = None
        self.inbox: asyncio.Queue[dict] = asyncio.Queue()
        self.online_users: list[str] = []
        self.all_users: list[dict] = []          # server B chỉ gửi người online; giữ trường cho giao diện cũ
        self._tasks: list[asyncio.Task] = []
        self._accepts: dict[bytes, asyncio.Future] = {}
        self._aborted: set[bytes] = set()
        self._incoming: dict[bytes, _Incoming] = {}
        self._next_stream = config.STREAM_FILE_BASE
        self._running = False

    # ---------------------------------------------------------------- kết nối
    async def connect(self) -> None:
        self.endpoint = await UDPEndpoint.create("0.0.0.0", 0, loss=self.loss)
        self.conn = await self.endpoint.connect(self.login.conn_id, AESGCMCipher.for_client(self.login.keys),
                                                self.server_addr)
        self.chat = self.conn.open_stream(config.STREAM_CHAT)
        self._reader = messages.FrameReader(self.chat)
        try:
            first = messages.decode(await asyncio.wait_for(self._reader.read(), config.CLIENT_BIND_TIMEOUT))
        except (asyncio.TimeoutError, ConnectionError):
            self.endpoint.close()
            raise ConnectionError("Không gắn được kênh UDP: server không trả USER_LIST "
                                  f"sau {config.CLIENT_BIND_TIMEOUT} giây (kiểm tra tường lửa UDP {self.server_addr[1]}).")
        if first.get("type") != messages.USER_LIST:
            self.endpoint.close()
            raise ConnectionError(f"mong USER_LIST, nhận {first.get('type')}")
        self._running = True
        self.conn.on_disconnect(self._on_lost)
        await self._handle(first)
        loop = asyncio.get_running_loop()
        self._tasks += [loop.create_task(self._chat_loop()), loop.create_task(self._heartbeat_loop()),
                        loop.create_task(self._heartbeat_listen()), loop.create_task(self._accept_loop())]
        log.info("đã gắn UDP %s:%d, ConnID=%#010x", *self.server_addr, self.login.conn_id)

    def _on_lost(self, _conn) -> None:
        if self._running:
            self._running = False
            self.inbox.put_nowait({"type": "DISCONNECTED", "detail": "Mất kết nối với server."})

    # ---------------------------------------------------------------- stream 1
    async def _send_json(self, msg: dict) -> None:
        if self.chat is None or not self._running:
            raise ConnectionError("Chưa kết nối UDP với server.")
        await messages.send_json(self.chat, msg)

    async def _chat_loop(self) -> None:
        while True:
            try:
                raw = await self._reader.read()
            except ConnectionError:
                return
            try:
                await self._handle(messages.decode(raw))
            except Exception:
                log.exception("lỗi xử lý thông điệp từ server")

    async def _handle(self, msg: dict) -> None:
        t = msg.get("type")
        if t == messages.USER_LIST:
            self.online_users = list(msg.get("users", []))
        elif t == messages.FILE_OFFER:
            await self._on_offer(msg)
            return                      # chỉ báo giao diện khi tệp đã lưu xong (FILE_RECEIVED)
        elif t == messages.FILE_ACCEPT:
            fut = self._accepts.get(messages.b64d(msg["transfer_id"]))
            if fut and not fut.done():
                fut.set_result(msg)
            return
        elif t == messages.FILE_DONE:
            inc = self._incoming.get(messages.b64d(msg["transfer_id"]))
            if inc:
                inc.done_sha = messages.b64d(msg["sha256"], 32, "sha256")
                await self._maybe_finish(inc)
            return
        elif t == messages.ERROR:
            await self._on_error(msg)
        await self.inbox.put(msg)

    async def _on_error(self, msg: dict) -> None:
        code, ref = msg.get("code"), msg.get("ref")
        if code == messages.E_FILE_ABORTED and ref:
            tid = messages.b64d(ref)
            self._aborted.add(tid)
            fut = self._accepts.get(tid)
            if fut and not fut.done():
                fut.set_exception(FileAborted(msg.get("detail", "")))
            inc = self._incoming.pop(tid, None)
            if inc:
                await asyncio.to_thread(_remove_quiet, inc.part_path)
        elif code == messages.E_SESSION_REPLACED:
            self._running = False

    # ---------------------------------------------------------------- heartbeat
    async def _heartbeat_loop(self) -> None:
        hb = self.conn.open_stream(config.STREAM_HEARTBEAT)
        while self._running:
            try:
                await hb.send(b"\x01")
            except ConnectionError:
                return
            await asyncio.sleep(config.HEARTBEAT_INTERVAL)

    async def _heartbeat_listen(self) -> None:
        hb = self.conn.open_stream(config.STREAM_HEARTBEAT)
        while await hb.recv():
            pass                         # chỉ cần biết server còn sống; transport đã tính "gói cuối nhận được"

    # ---------------------------------------------------------------- chat
    async def send_broadcast(self, text: str) -> None:
        msg_id = new_msg_id()
        await self._send_json({"type": messages.MSG_BCAST, "msg_id": msg_id, "text": text})
        await self.inbox.put({"type": messages.MSG_BCAST, "msg_id": msg_id, "from": self.username,
                              "ts": messages.now_ms(), "text": text})

    async def send_dm(self, to_user: str, text: str) -> None:
        msg_id = new_msg_id()
        await self._send_json({"type": messages.MSG_DM, "msg_id": msg_id, "to": to_user, "text": text})
        await self.inbox.put({"type": messages.MSG_DM, "msg_id": msg_id, "from": self.username, "to": to_user,
                              "ts": messages.now_ms(), "text": text})

    # ---------------------------------------------------------------- gửi tệp
    async def send_file(self, to_user: str, data: bytes, filename: str) -> str:
        """FILE_OFFER -> chờ FILE_ACCEPT -> chunk trên stream >= 3 tự chọn -> FILE_DONE. Trả SHA-256 (hex)."""
        name = os.path.basename(filename.replace("\\", "/")) or "file.bin"
        if not messages.valid_filename(name):
            raise ValueError("Tên tệp không hợp lệ.")
        tid = new_transfer_id()
        fut = asyncio.get_running_loop().create_future()
        self._accepts[tid] = fut
        try:
            await self._send_json({"type": messages.FILE_OFFER, "transfer_id": messages.b64e(tid), "to": to_user,
                                   "name": name, "size": len(data)})
            try:
                await asyncio.wait_for(fut, ACCEPT_TIMEOUT)
            except asyncio.TimeoutError:
                raise FileAborted(f"{to_user} không đồng ý nhận trong {ACCEPT_TIMEOUT} giây") from None
        finally:
            self._accepts.pop(tid, None)
        sid = self._next_stream
        self._next_stream += 1
        st = self.conn.open_stream(sid)
        for off in range(0, len(data), config.CHUNK_SIZE):
            if tid in self._aborted:
                raise FileAborted("server đã hủy lần truyền")
            await st.send(messages.frame(messages.pack_chunk(tid, off, data[off:off + config.CHUNK_SIZE])))
        sha = hashlib.sha256(data).digest()
        await self._send_json({"type": messages.FILE_DONE, "transfer_id": messages.b64e(tid),
                               "sha256": messages.b64e(sha)})
        log.info("đã gửi '%s' (%d byte) cho %s trên stream %d", name, len(data), to_user, sid)
        return sha.hex()

    # ---------------------------------------------------------------- nhận tệp
    async def _on_offer(self, msg: dict) -> None:
        tid = messages.b64d(msg["transfer_id"], config.TRANSFER_ID_BYTES, "transfer_id")
        name = os.path.basename(str(msg.get("name", "")))       # lọc tên tệp lần nữa trước khi ghi đĩa
        size = int(msg.get("size", -1))
        if not messages.valid_filename(name) or not 0 <= size <= config.MAX_FILE_SIZE:
            log.warning("bỏ qua FILE_OFFER không hợp lệ: %r", msg)
            return
        part = os.path.join(self.downloads_dir, f".{tid.hex()}.part")
        await asyncio.to_thread(_create_empty, part)
        self._incoming[tid] = _Incoming(tid, name, size, msg.get("from", "?"), part)
        await self._send_json({"type": messages.FILE_ACCEPT, "transfer_id": msg["transfer_id"]})   # tự đồng ý

    async def _accept_loop(self) -> None:
        while True:
            st = await self.conn.accept_stream()
            if st is None:
                return
            self._tasks.append(asyncio.get_running_loop().create_task(self._recv_chunks(st)))

    async def _recv_chunks(self, st) -> None:
        reader = messages.FrameReader(st)
        inc = None
        try:
            while inc is None or inc.received < inc.size:
                tid, off, data = messages.unpack_chunk(await reader.read())
                if inc is None:
                    inc = self._incoming.get(tid)
                    if inc is None:
                        log.warning("chunk cho lần truyền lạ, bỏ stream %d", st.stream_id)
                        return
                if self._incoming.get(tid) is not inc:      # đã bị hủy
                    return
                if off != inc.received or off + len(data) > inc.size:
                    log.warning("chunk sai offset %d (mong %d)", off, inc.received)
                    return
                await asyncio.to_thread(_write_at, inc.part_path, off, data)   # ghi theo offset, không giữ cả tệp
                inc.received += len(data)
            await self._maybe_finish(inc)
        except (ConnectionError, messages.ProtocolError) as e:
            log.warning("stream tệp %d dừng: %s", st.stream_id, e)

    async def _maybe_finish(self, inc: _Incoming) -> None:
        if inc.finished or inc.received < inc.size or inc.done_sha is None:
            return
        inc.finished = True
        self._incoming.pop(inc.tid, None)
        actual = await asyncio.to_thread(_sha256_file, inc.part_path)
        if actual != inc.done_sha:
            await asyncio.to_thread(_remove_quiet, inc.part_path)
            await self.inbox.put({"type": messages.ERROR, "code": "SHA_MISMATCH",
                                  "detail": f"Tệp '{inc.name}' từ {inc.sender} sai SHA-256, đã xóa."})
            return
        path = await asyncio.to_thread(_finalize, inc.part_path, self.downloads_dir, inc.name)
        final_name = os.path.basename(path)
        await asyncio.to_thread(_save_meta, self.downloads_dir, final_name, inc.sender, inc.size, actual.hex())
        log.info("đã nhận '%s' (%d byte) từ %s, SHA-256 khớp", final_name, inc.size, inc.sender)
        await self.inbox.put({"type": "FILE_RECEIVED", "filename": final_name, "path": path,
                              "sha256": actual.hex(), "from": inc.sender})

    # ---------------------------------------------------------------- đóng
    async def disconnect(self) -> None:
        self._running = False
        for t in self._tasks:
            t.cancel()
        if self.endpoint is not None:
            self.endpoint.close()        # gửi FIN
        for inc in list(self._incoming.values()):
            await asyncio.to_thread(_remove_quiet, inc.part_path)
        self._incoming.clear()
        log.info("Client UDP đã ngắt kết nối.")


# ---------------------------------------------------------------- việc đĩa (chạy trong thread)
def _create_empty(path: str) -> None:
    with open(path, "wb"):
        pass


def _write_at(path: str, off: int, data: bytes) -> None:
    with open(path, "r+b") as f:
        f.seek(off)
        f.write(data)


def _sha256_file(path: str) -> bytes:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.digest()


def _remove_quiet(path: str) -> None:
    try:
        os.remove(path)
    except OSError:
        pass


def _finalize(part: str, directory: str, name: str) -> str:
    base, ext = os.path.splitext(name)
    path, n = os.path.join(directory, name), 1
    while os.path.exists(path):               # không ghi đè tệp đã có
        path = os.path.join(directory, f"{base} ({n}){ext}")
        n += 1
    os.replace(part, path)
    return path


def _save_meta(directory: str, name: str, sender: str, size: int, sha_hex: str) -> None:
    meta_file = os.path.join(directory, ".metadata.json")
    try:
        with open(meta_file, encoding="utf-8") as f:
            meta = json.load(f)
    except (OSError, ValueError):
        meta = {}
    meta[name] = {"filename": name, "sender": sender, "size": size, "sha256": sha_hex, "received_at": time.time()}
    with open(meta_file, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2, ensure_ascii=False)
