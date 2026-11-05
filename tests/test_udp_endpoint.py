"""Chạy server B trên UDP THẬT (transport/udp_endpoint.py) thay cho FakeHub: đăng nhập, HELLO, chat,
gửi tệp qua server, mất gói, HELLO giả bị bỏ, FIN báo rời mạng."""
from __future__ import annotations

import asyncio
import contextlib
import hashlib
import os

from client.tcp_login import new_transfer_id, tcp_login
from server.main import ChatServer
from shared import config, messages
from tests.helpers import TestClient, run
from transport.cipher import AESGCMCipher
from transport.udp_endpoint import UDPEndpoint


class _RealHub:
    """Thay FakeHub cho TestClient: mỗi client một socket UDP riêng."""

    def __init__(self, server_addr, loss: float = 0.0):
        self.server_addr, self.loss, self.eps = server_addr, loss, []

    async def connect(self, conn_id, cipher):
        ep = await UDPEndpoint.create("127.0.0.1", 0, loss=self.loss)
        self.eps.append(ep)
        return await ep.connect(conn_id, cipher, self.server_addr)

    def close(self):
        for ep in self.eps:
            ep.close()


@contextlib.asynccontextmanager
async def real_server(tmp_path, client_loss: float = 0.0):
    ep = await UDPEndpoint.create("127.0.0.1", 0)
    srv = ChatServer(host="127.0.0.1", tcp_port=0, users_file=str(tmp_path / "users.json"),
                     identity_file=str(tmp_path / "id.key"), identity_pub_file=str(tmp_path / "id.pub"),
                     pbkdf2_iterations=1000)
    await srv.start(ep)
    hub = _RealHub(ep.local_addr, client_loss)
    try:
        yield srv, hub, ep
    finally:
        hub.close()
        await srv.stop()
        ep.close()


def test_chat_over_real_udp(tmp_path):
    async def go():
        async with real_server(tmp_path) as (srv, hub, _):
            a = await TestClient(srv, hub, "alice").connect()
            b = await TestClient(srv, hub, "bob").connect()
            await a.wait_users(["alice", "bob"])
            await a.send({"type": "MSG_BCAST", "text": "chào"})
            m = await b.expect("MSG_BCAST")
            assert m["from"] == "alice" and m["text"] == "chào"
            await b.send({"type": "MSG_DM", "to": "alice", "text": "x" * 3000})     # nhiều hơn 1 gói UDP
            assert (await a.expect("MSG_DM"))["text"] == "x" * 3000
            b.close()                                   # FIN -> server loại bob ngay
            await a.wait_users(["alice"], timeout=3)
            a.close()
    run(go())


async def _send_file(a: TestClient, b: TestClient, data: bytes, timeout: float):
    tid = new_transfer_id()
    await a.send({"type": "FILE_OFFER", "transfer_id": messages.b64e(tid), "to": "bob", "name": "f.bin",
                  "size": len(data)})
    offer = await b.expect("FILE_OFFER", timeout)
    await b.send({"type": "FILE_ACCEPT", "transfer_id": offer["transfer_id"]})
    await a.expect("FILE_ACCEPT", timeout)
    st = a.conn.open_stream(3)
    for off in range(0, len(data), config.CHUNK_SIZE):
        await st.send(messages.frame(messages.pack_chunk(tid, off, data[off:off + config.CHUNK_SIZE])))
    await a.send({"type": "FILE_DONE", "transfer_id": messages.b64e(tid),
                  "sha256": messages.b64e(hashlib.sha256(data).digest())})
    rs = await asyncio.wait_for(b.conn.accept_stream(), timeout)
    reader, got = messages.FrameReader(rs), bytearray()
    while len(got) < len(data):
        _, off, chunk = messages.unpack_chunk(await asyncio.wait_for(reader.read(), timeout))
        assert off == len(got)
        got += chunk
    done = await b.expect("FILE_DONE", timeout)
    assert messages.b64d(done["sha256"]) == hashlib.sha256(got).digest()
    return bytes(got)


def test_file_relay_over_real_udp_with_loss(tmp_path):
    async def go():
        async with real_server(tmp_path, client_loss=0.1) as (srv, hub, _):   # 10% mỗi chiều, phía client
            a = await TestClient(srv, hub, "alice").connect()
            b = await TestClient(srv, hub, "bob").connect()
            data = os.urandom(300_000)
            assert await _send_file(a, b, data, timeout=30) == data
            assert all(ep.dropped > 0 for ep in hub.eps)
            a.close()
            b.close()
    run(go())


def test_hello_with_wrong_key_is_dropped(tmp_path):
    async def go():
        async with real_server(tmp_path) as (srv, hub, ep):
            res = await tcp_login("127.0.0.1", srv.login.port, "alice", "secret123", register=True,
                                  pinned_identity=srv.identity_pub)
            wrong = AESGCMCipher(os.urandom(32), os.urandom(32))
            conn = await hub.connect(res.conn_id, wrong)
            await asyncio.sleep(1.5)
            assert res.conn_id not in ep.conns and srv.registry.get("alice") is None
            conn.close()
    run(go())
