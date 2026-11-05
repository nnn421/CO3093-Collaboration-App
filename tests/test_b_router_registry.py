"""Nghiệm thu B5 (registry) + B7 (định tuyến)."""
import asyncio
import time

from shared import messages
from tests.helpers import SlowCallbackCollector, TestClient, run, running_server


async def _three(srv, hub):
    a = await TestClient(srv, hub, "alice").connect()
    b = await TestClient(srv, hub, "bob").connect()
    c = await TestClient(srv, hub, "carol").connect()
    for x in (a, b, c):
        await x.wait_users(["alice", "bob", "carol"])
    return a, b, c


def test_broadcast_dm_offline(tmp_path):
    async def go():
        async with running_server(tmp_path) as (srv, hub):
            a, b, c = await _three(srv, hub)
            await a.send({"type": "MSG_BCAST", "msg_id": "m-1", "text": "chào cả nhà"})
            for x in (b, c):
                m = await x.expect("MSG_BCAST")
                assert (m["from"], m["text"], m["msg_id"]) == ("alice", "chào cả nhà", "m-1")
                assert isinstance(m["ts"], int)
            await a.expect_none("MSG_BCAST")                       # người gửi không nhận lại

            await a.send({"type": "MSG_DM", "to": "bob", "text": "bí mật"})
            m = await b.expect("MSG_DM")
            assert (m["from"], m["to"], m["text"]) == ("alice", "bob", "bí mật")
            await c.expect_none("MSG_DM")                          # carol không thấy

            await a.send({"type": "MSG_DM", "msg_id": "m-2", "to": "zed", "text": "?"})
            e = await a.expect("ERROR")
            assert e["code"] == messages.E_USER_OFFLINE and e["ref"] == "m-2"      # ghép được với tin gây lỗi
    run(go(), debug=True)


def test_sender_cannot_spoof_from(tmp_path):
    async def go():
        async with running_server(tmp_path) as (srv, hub):
            a, b, c = await _three(srv, hub)
            await a.send({"type": "MSG_BCAST", "text": "x", "from": "bob", "ts": 1})
            m = await c.expect("MSG_BCAST")
            assert m["from"] == "alice" and m["ts"] != 1
    run(go())


def test_garbage_on_stream1_gets_error_but_session_survives(tmp_path):
    async def go():
        async with running_server(tmp_path) as (srv, hub):
            a, b, c = await _three(srv, hub)
            for raw in (b"\xff\xfe", b"[1,2]", b'{"type":"AUTH_OK"}', b'{"type":"MSG_DM","msg_id":"m","to":"bob"}'):
                await a.send_raw_frame(raw)
                assert (await a.expect("ERROR"))["code"] == messages.E_BAD_MESSAGE
            await a.send({"type": "MSG_DM", "to": "bob", "text": "vẫn sống"})
            assert (await b.expect("MSG_DM"))["text"] == "vẫn sống"
    run(go())


def test_user_list_on_graceful_leave(tmp_path):
    async def go():
        async with running_server(tmp_path) as (srv, hub):
            a, b, c = await _three(srv, hub)
            t0 = time.perf_counter()
            c.close()                                              # mô phỏng FIN -> on_disconnect
            for x in (a, b):
                await x.expect("USER_LIST", pred=lambda m: m["users"] == ["alice", "bob"])
            return time.perf_counter() - t0
    dt = run(go())
    print(f"\ncập nhật USER_LIST khi thoát bình thường: {dt*1000:.1f} ms")
    assert dt < 0.5


def test_idle_client_swept(tmp_path):
    """Thu nhỏ thời gian: idle 0.6s, quét 0.2s (thật: 15s / 5s). b im lặng, a gửi heartbeat."""
    async def go():
        async with running_server(tmp_path, idle_timeout=0.6, sweep_interval=0.2) as (srv, hub):
            a = await TestClient(srv, hub, "alice").connect()
            b = await TestClient(srv, hub, "bob").connect()
            a.start_heartbeat(0.1)
            await a.expect("USER_LIST", pred=lambda m: m["users"] == ["alice", "bob"])
            t0 = srv.registry.get("bob").last_seen       # đo từ lần cuối bob có tín hiệu
            await a.expect("USER_LIST", timeout=3, pred=lambda m: m["users"] == ["alice"])
            dt = time.monotonic() - t0
            assert srv.registry.get("alice") is not None and b.conn.closed.is_set()
            return dt
    dt = run(go())
    print(f"\nclient im lặng bị loại sau {dt:.2f}s (giới hạn 0.6s + một chu kỳ quét 0.2s)")
    assert 0.6 <= dt <= 0.6 + 0.2 + 0.15


def test_sweep_task_survives_exception(tmp_path):
    async def go():
        async with running_server(tmp_path, idle_timeout=0.3, sweep_interval=0.1) as (srv, hub):
            real = srv.registry.sweep_once
            calls = {"n": 0}

            def flaky():
                calls["n"] += 1
                if calls["n"] <= 2:
                    raise RuntimeError("lỗi giả lập")
                return real()
            srv.registry.sweep_once = flaky
            b = await TestClient(srv, hub, "bob").connect()
            for _ in range(30):
                await asyncio.sleep(0.05)
                if srv.registry.get("bob") is None:
                    break
            assert calls["n"] > 2 and srv.registry.get("bob") is None
            b.close()
    run(go())


def test_slow_client_does_not_block_others(tmp_path):
    """bob không đọc gì (hàng đợi transport đầy) -> alice vẫn nhận broadcast; bob bị ngắt khi outbox tràn."""
    async def go():
        async with running_server(tmp_path, queue_size=8) as (srv, hub):
            a, b, c = await _three(srv, hub)
            b._tasks[0].cancel()                        # bob ngừng đọc (task đầu tiên là vòng đọc stream 1)
            srv.registry.get("bob").outbox._maxsize = 50
            t0 = time.perf_counter()
            for i in range(200):
                await c.send({"type": "MSG_BCAST", "text": str(i)})
            for i in range(200):
                assert (await a.expect("MSG_BCAST"))["text"] == str(i)
            dt = time.perf_counter() - t0
            await asyncio.sleep(0.05)
            assert srv.registry.get("bob") is None       # bị ngắt vì quá chậm
            return dt
    dt = run(go())
    print(f"\n200 broadcast khi có client treo: {dt*1000:.0f} ms")


def test_no_slow_callbacks_in_debug_mode(tmp_path):
    async def go():
        async with running_server(tmp_path, iterations=100_000) as (srv, hub):
            a, b, c = await _three(srv, hub)
            for i in range(50):
                await a.send({"type": "MSG_BCAST", "text": str(i)})
            for i in range(50):
                await b.expect("MSG_BCAST")
    with SlowCallbackCollector() as col:
        run(go(), debug=True)
    assert not col.records, col.records


def test_user_list_has_ts_and_includes_receiver(tmp_path):
    async def go():
        async with running_server(tmp_path) as (srv, hub):
            a = await TestClient(srv, hub, "alice").connect()
            assert a.first_user_list["users"] == ["alice"] and isinstance(a.first_user_list["ts"], int)
    run(go())


def test_server_replies_to_heartbeat(tmp_path):
    """protocol_messages.md §6: server trả lời mỗi heartbeat, để client trong phòng im lặng không tự ngắt."""
    async def go():
        async with running_server(tmp_path) as (srv, hub):
            a = await TestClient(srv, hub, "alice").connect()
            a.start_heartbeat(0.05)
            await asyncio.sleep(0.4)
            return a.heartbeats_in
    n = run(go())
    assert n >= 5
