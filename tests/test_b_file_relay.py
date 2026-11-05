"""Nghiệm thu B8 (protocol_messages.md §5.5–5.7, §7): trung chuyển tệp, giữ FILE_DONE tới khi đủ dữ liệu,
back-pressure, hủy và báo FILE_ABORTED khi có sự cố."""
import asyncio
import hashlib
import secrets
import tracemalloc

from shared import config, messages
from tests.helpers import TestClient, run, running_server

CS = config.CHUNK_SIZE


def chunk_data(seed: bytes, off: int, size: int) -> bytes:
    data = hashlib.sha256(seed + off.to_bytes(8, "big")).digest() * 32   # 1024 byte giả ngẫu nhiên
    return data[:min(CS, size - off)]


async def offer(sender: TestClient, to: str, size: int, name: str = "f.bin") -> bytes:
    tid = secrets.token_bytes(16)
    await sender.send({"type": "FILE_OFFER", "transfer_id": messages.b64e(tid), "to": to, "name": name,
                       "size": size})
    return tid


async def send_chunks(sender: TestClient, tid: bytes, size: int, *, sid: int = 3, seed: bytes = b"") -> str:
    """Gửi chunk trên stream sid do người gửi tự chọn (không báo cho ai). Trả sha256 base64."""
    h, stream = hashlib.sha256(), sender.conn.open_stream(sid)
    for off in range(0, size, CS):
        data = chunk_data(seed, off, size)
        h.update(data)
        await stream.send(messages.frame(messages.pack_chunk(tid, off, data)))
    return messages.b64e(h.digest())


async def send_file(sender: TestClient, to: str, size: int, *, done_first: bool = False, seed: bytes = b"") -> str:
    tid = await offer(sender, to, size)
    await sender.expect("FILE_ACCEPT", timeout=5)
    h = hashlib.sha256()
    for off in range(0, size, CS):
        h.update(chunk_data(seed, off, size))
    sha = messages.b64e(h.digest())
    if done_first:      # thứ tự xấu nhất: DONE tới server trước mọi chunk
        await sender.send({"type": "FILE_DONE", "transfer_id": messages.b64e(tid), "sha256": sha})
    await send_chunks(sender, tid, size, seed=seed)
    if not done_first:
        await sender.send({"type": "FILE_DONE", "transfer_id": messages.b64e(tid), "sha256": sha})
    return sha


async def receive_file(rx: TestClient, *, slow_every: int = 0, hold_until_done: bool = False):
    off_msg = await rx.expect("FILE_OFFER", timeout=5)
    await rx.send({"type": "FILE_ACCEPT", "transfer_id": off_msg["transfer_id"]})
    if hold_until_done:
        done = await rx.expect("FILE_DONE", timeout=10)
    h, got, n = hashlib.sha256(), 0, 0
    if off_msg["size"] > 0:
        stream = await asyncio.wait_for(rx.conn.accept_stream(), 5)     # stream do server tự chọn
        reader = messages.FrameReader(stream)
        while got < off_msg["size"]:
            tid, off, data = messages.unpack_chunk(await reader.read())
            assert messages.b64e(tid) == off_msg["transfer_id"] and off == got
            h.update(data)
            got += len(data)
            n += 1
            if slow_every and n % slow_every == 0:
                await asyncio.sleep(0.005)
    if not hold_until_done:
        done = await rx.expect("FILE_DONE", timeout=10)
    return off_msg, done, messages.b64e(h.digest()), got


def test_relay_1mb_integrity_and_done_held(tmp_path):
    size = 1_048_576 + 123          # không chia hết cho 1000
    async def go():
        # hàng đợi đủ lớn để nhận cả tệp mà không đọc: kiểm tra DONE chỉ tới khi server đã chuyển đủ
        async with running_server(tmp_path, queue_size=2000) as (srv, hub):
            a = await TestClient(srv, hub, "alice").connect()
            b = await TestClient(srv, hub, "bob").connect()
            rx = asyncio.create_task(receive_file(b, hold_until_done=True))
            sha = await send_file(a, "bob", size, done_first=True)
            off_msg, done, got_sha, got = await rx
            assert (off_msg["from"], off_msg["to"], off_msg["size"]) == ("alice", "bob", size)
            assert "stream_id" not in off_msg and isinstance(off_msg["ts"], int)
            assert done["sha256"] == sha == got_sha and got == size
            assert not srv.relay.transfers
    run(go())


def test_zero_byte_file(tmp_path):
    async def go():
        async with running_server(tmp_path) as (srv, hub):
            a = await TestClient(srv, hub, "alice").connect()
            b = await TestClient(srv, hub, "bob").connect()
            rx = asyncio.create_task(receive_file(b))
            sha = await send_file(a, "bob", 0)
            off_msg, done, got_sha, got = await rx
            assert got == 0 and done["sha256"] == sha == "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="
    run(go())


def test_offer_errors(tmp_path):
    async def go():
        async with running_server(tmp_path) as (srv, hub):
            a = await TestClient(srv, hub, "alice").connect()
            b = await TestClient(srv, hub, "bob").connect()
            tid = await offer(a, "ghost", 10)
            e = await a.expect("ERROR")
            assert e["code"] == messages.E_USER_OFFLINE and e["ref"] == messages.b64e(tid)
            await offer(a, "alice", 10)                                            # gửi cho chính mình
            assert (await a.expect("ERROR"))["code"] == messages.E_BAD_MESSAGE
            await a.send({"type": "FILE_ACCEPT", "transfer_id": messages.b64e(b"\x07" * 16)})
            assert (await a.expect("ERROR"))["code"] == messages.E_UNKNOWN_TRANSFER
            for bad_name in ("../../.bashrc", "a/b", "..", "x\\y"):
                await offer(a, "bob", 10, name=bad_name)
                assert (await a.expect("ERROR"))["code"] == messages.E_BAD_MESSAGE
            await b.expect_none("FILE_OFFER", wait=0.1)
            tid = await offer(a, "bob", 10)
            await b.expect("FILE_OFFER")
            await a.send({"type": "FILE_OFFER", "transfer_id": messages.b64e(tid), "to": "bob", "name": "x",
                          "size": 1})
            assert (await a.expect("ERROR"))["code"] == messages.E_BAD_MESSAGE     # trùng transfer_id
    run(go())


def test_receiver_disconnect_aborts_sender(tmp_path):
    async def go():
        async with running_server(tmp_path, queue_size=8) as (srv, hub):
            a = await TestClient(srv, hub, "alice").connect()
            b = await TestClient(srv, hub, "bob").connect()
            tid = await offer(a, "bob", 10_000_000)
            off_msg = await b.expect("FILE_OFFER")
            await b.send({"type": "FILE_ACCEPT", "transfer_id": off_msg["transfer_id"]})
            acc = await a.expect("FILE_ACCEPT")
            assert acc["from"] == "bob"
            sender = asyncio.create_task(send_chunks(a, tid, 10_000_000))
            await asyncio.sleep(0.1)       # bob không đọc -> hàng đợi đầy -> alice bị hãm (back-pressure)
            assert not sender.done()
            b.close()
            e = await a.expect("ERROR", timeout=3, pred=lambda m: m["code"] == messages.E_FILE_ABORTED)
            sender.cancel()                # client thật: nhận FILE_ABORTED thì ngừng gửi
            assert e["ref"] == messages.b64e(tid) and not srv.relay.transfers
            assert srv.registry.get("alice") is not None
    run(go())


def test_bad_chunk_offset_aborts_both(tmp_path):
    async def go():
        async with running_server(tmp_path) as (srv, hub):
            a = await TestClient(srv, hub, "alice").connect()
            b = await TestClient(srv, hub, "bob").connect()
            tid = await offer(a, "bob", 5000)
            off_msg = await b.expect("FILE_OFFER")
            await b.send({"type": "FILE_ACCEPT", "transfer_id": off_msg["transfer_id"]})
            await a.expect("FILE_ACCEPT")
            await a.conn.open_stream(3).send(messages.frame(messages.pack_chunk(tid, 999, b"y" * 10)))
            for x in (a, b):
                assert (await x.expect("ERROR"))["code"] == messages.E_FILE_ABORTED
    run(go())


def test_chunk_for_unaccepted_or_foreign_transfer_rejected(tmp_path):
    async def go():
        async with running_server(tmp_path) as (srv, hub):
            a = await TestClient(srv, hub, "alice").connect()
            b = await TestClient(srv, hub, "bob").connect()
            tid = await offer(a, "bob", 5000)
            await b.expect("FILE_OFFER")
            # chưa ACCEPT mà đã gửi chunk
            await a.conn.open_stream(3).send(messages.frame(messages.pack_chunk(tid, 0, b"z" * 10)))
            assert (await a.expect("ERROR"))["code"] == messages.E_UNKNOWN_TRANSFER
            # người nhận (không phải người gửi) thử gửi chunk cho phiên đó
            await b.conn.open_stream(3).send(messages.frame(messages.pack_chunk(tid, 0, b"z" * 10)))
            assert (await b.expect("ERROR"))["code"] == messages.E_UNKNOWN_TRANSFER
    run(go())


def test_offer_timeout_aborts(tmp_path):
    async def go():
        async with running_server(tmp_path, offer_timeout=0.2) as (srv, hub):
            a = await TestClient(srv, hub, "alice").connect()
            b = await TestClient(srv, hub, "bob").connect()
            tid = await offer(a, "bob", 10)
            for x in (a, b):
                e = await x.expect("ERROR", timeout=1)
                assert e["code"] == messages.E_FILE_ABORTED and e["ref"] == messages.b64e(tid)
    run(go())


def test_relay_memory_server_only(tmp_path):
    """Nghiệm thu B8: 10MB qua server, bên nhận chậm, bên gửi sinh dữ liệu tại chỗ -> đỉnh RAM tăng thêm < 5MB."""
    size = 10 * 1024 * 1024
    async def go():
        async with running_server(tmp_path, queue_size=64) as (srv, hub):
            a = await TestClient(srv, hub, "alice").connect()
            b = await TestClient(srv, hub, "bob").connect()
            tid = await offer(a, "bob", size, name="big.bin")
            off_msg = await b.expect("FILE_OFFER")
            await b.send({"type": "FILE_ACCEPT", "transfer_id": off_msg["transfer_id"]})
            await a.expect("FILE_ACCEPT")

            async def receiver():
                r = messages.FrameReader(await b.conn.accept_stream())
                h, got, n = hashlib.sha256(), 0, 0
                while got < size:
                    _, _, data = messages.unpack_chunk(await r.read())
                    h.update(data)
                    got += len(data)
                    n += 1
                    if n % 200 == 0:
                        await asyncio.sleep(0.005)
                return messages.b64e(h.digest())

            tracemalloc.start()
            base, _ = tracemalloc.get_traced_memory()
            rxt = asyncio.create_task(receiver())
            stream, h = a.conn.open_stream(3), hashlib.sha256()
            block = secrets.token_bytes(CS)
            for off in range(0, size, CS):
                data = block[:min(CS, size - off)]
                h.update(data)
                await stream.send(messages.frame(messages.pack_chunk(tid, off, data)))
            sha = messages.b64e(h.digest())
            await a.send({"type": "FILE_DONE", "transfer_id": messages.b64e(tid), "sha256": sha})
            got_sha = await rxt
            done = await b.expect("FILE_DONE", timeout=10)
            _, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()
            assert got_sha == sha == done["sha256"] and done["from"] == "alice"
            return peak - base
    extra = run(go())
    print(f"\n10MB qua server: đỉnh bộ nhớ tăng thêm {extra/1024:.0f} KB")
    assert extra < 5 * 1024 * 1024
