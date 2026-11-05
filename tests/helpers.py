"""Tiện ích dùng chung cho test tầng server (B). Chạy server thật (TCP thật) + FakeHub cho phần UDP."""
from __future__ import annotations

import asyncio
import contextlib
import logging
import time

from client.tcp_login import new_msg_id, tcp_login
from server.main import ChatServer
from shared import config, messages
from transport.cipher import AESGCMCipher
from transport.fake import FakeHub


def run(coro, debug: bool = False):
    return asyncio.run(coro, debug=debug)


@contextlib.asynccontextmanager
async def running_server(tmp_path, queue_size: int = 64, iterations: int = 1000, **kw):
    hub = FakeHub(queue_size=queue_size)
    srv = ChatServer(host="127.0.0.1", tcp_port=0, users_file=str(tmp_path / "users.json"),
                     identity_file=str(tmp_path / "identity.key"),
                     identity_pub_file=str(tmp_path / "identity.pub"),
                     pbkdf2_iterations=iterations, **kw)
    await srv.start(hub)
    try:
        yield srv, hub
    finally:
        await srv.stop()


class TestClient:
    __test__ = False   # không để pytest tưởng là lớp test

    def __init__(self, srv: ChatServer, hub: FakeHub, username: str, password: str = "secret123"):
        self.srv, self.hub = srv, hub
        self.username, self.password = username, password
        self.inbox: asyncio.Queue = asyncio.Queue()
        self.received: list[dict] = []
        self.heartbeats_in = 0
        self.last_users: list[str] | None = None
        self._tasks: list[asyncio.Task] = []

    async def connect(self, register: bool = True) -> "TestClient":
        res = await tcp_login("127.0.0.1", self.srv.login.port, self.username, self.password,
                              register=register, pinned_identity=self.srv.identity_pub)
        self.conn = await self.hub.connect(res.conn_id, AESGCMCipher.for_client(res.keys))   # gói HELLO
        self.chat = self.conn.open_stream(config.STREAM_CHAT)
        self._tasks.append(asyncio.get_running_loop().create_task(self._read()))
        self.first_user_list = await self.expect("USER_LIST", timeout=config.CLIENT_BIND_TIMEOUT)   # xác nhận HELLO
        return self

    async def _read(self):
        reader = messages.FrameReader(self.chat)
        while True:
            try:
                raw = await reader.read()
            except ConnectionError:
                await self.inbox.put(None)
                return
            msg = messages.decode(raw)
            msg["_rx"] = time.perf_counter()
            if msg.get("type") == "USER_LIST":
                self.last_users = msg["users"]
            self.received.append(msg)
            await self.inbox.put(msg)

    async def send(self, msg: dict) -> None:
        if msg.get("type") in (messages.MSG_BCAST, messages.MSG_DM) and "msg_id" not in msg:
            msg = {**msg, "msg_id": new_msg_id()}
        await messages.send_json(self.chat, msg)

    async def send_raw_frame(self, payload: bytes) -> None:
        await self.chat.send(messages.frame(payload))

    async def expect(self, mtype: str, timeout: float = 2.0, pred=None) -> dict:
        """Chờ thông điệp loại mtype (bỏ qua loại khác). None trong inbox = kết nối đóng."""
        deadline = time.monotonic() + timeout
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                raise AssertionError(f"{self.username}: không nhận được {mtype} trong {timeout}s")
            msg = await asyncio.wait_for(self.inbox.get(), left)
            if msg is None:
                raise AssertionError(f"{self.username}: kết nối đóng khi đang chờ {mtype}")
            if msg["type"] == mtype and (pred is None or pred(msg)):
                return msg

    async def wait_users(self, names: list[str], timeout: float = 2.0) -> None:
        """Chờ tới khi USER_LIST mới nhất bằng names, rồi bỏ các USER_LIST cũ còn trong inbox."""
        deadline = time.monotonic() + timeout
        while self.last_users != names:
            if time.monotonic() > deadline:
                raise AssertionError(f"{self.username}: USER_LIST {self.last_users} != {names}")
            await asyncio.sleep(0.01)
        keep = []
        while not self.inbox.empty():
            m = self.inbox.get_nowait()
            if m is None or m.get("type") != "USER_LIST":
                keep.append(m)
        for m in keep:
            self.inbox.put_nowait(m)

    async def expect_none(self, mtype: str, wait: float = 0.3, pred=None) -> None:
        await asyncio.sleep(wait)
        bad = [m for m in self.received if m["type"] == mtype and (pred is None or pred(m))]
        assert not bad, f"{self.username} nhận {mtype} không mong muốn: {bad}"

    def start_heartbeat(self, interval: float) -> None:
        hb = self.conn.open_stream(config.STREAM_HEARTBEAT)

        async def beat():
            while True:
                await hb.send(b"\x01")
                await asyncio.sleep(interval)

        async def listen():
            while await hb.recv():
                self.heartbeats_in += 1

        loop = asyncio.get_running_loop()
        self._tasks += [loop.create_task(beat()), loop.create_task(listen())]

    def close(self) -> None:
        for t in self._tasks:
            t.cancel()
        self.conn.close()


class SlowCallbackCollector(logging.Handler):
    """Bắt cảnh báo của asyncio debug: 'Executing <...> took 0.123 seconds'."""

    def __init__(self):
        super().__init__(logging.WARNING)
        self.records: list[str] = []

    def emit(self, record):
        msg = record.getMessage()
        if "took" in msg and "seconds" in msg:
            self.records.append(msg)

    def __enter__(self):
        logging.getLogger("asyncio").addHandler(self)
        return self

    def __exit__(self, *a):
        logging.getLogger("asyncio").removeHandler(self)
