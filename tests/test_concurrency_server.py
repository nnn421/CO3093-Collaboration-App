"""B10 - Kiểm thử tải đồng thời: 20 client, >200 thông điệp, không mất tin, đo độ trễ, kiểm rò rỉ.

GIỚI HẠN: phần UDP đang chạy trên FakeHub (RAM) vì transport thật của A chưa có. Con số độ trễ ở đây
là độ trễ XỬ LÝ của tầng server (+ mã hóa AES-GCM 2 chặng), chưa gồm mạng và sliding window.
Khi A bàn giao UDPEndpoint, chạy lại test này với transport thật.
"""
import asyncio
import statistics
import time

from tests.helpers import SlowCallbackCollector, TestClient, run, running_server

N = 20


async def _wait_counts(clients, want, timeout=15):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if all(want(c) for c in clients):
            return True
        await asyncio.sleep(0.02)
    return False


def test_20_clients_no_loss_low_latency_no_leak(tmp_path):
    async def go():
        async with running_server(tmp_path, iterations=100_000) as (srv, hub):
            base_tasks = len(asyncio.all_tasks())
            t0 = time.perf_counter()
            clients = await asyncio.gather(*(TestClient(srv, hub, f"user{i:02d}").connect() for i in range(N)))
            login_s = time.perf_counter() - t0
            names = sorted(c.username for c in clients)
            for c in clients:
                await c.wait_users(names, timeout=5)

            BC, DM = 10, 5
            for i, c in enumerate(clients):
                for k in range(BC):
                    await c.send({"type": "MSG_BCAST", "text": f"{i}|{k}|{time.perf_counter()}"})
                for k in range(DM):
                    await c.send({"type": "MSG_DM", "to": clients[(i + 1) % N].username,
                                  "text": f"{i}|{k}|{time.perf_counter()}"})
            sent = N * (BC + DM)

            def done(c):
                return (sum(m["type"] == "MSG_BCAST" for m in c.received) == (N - 1) * BC and
                        sum(m["type"] == "MSG_DM" for m in c.received) == DM)
            assert await _wait_counts(clients, done), "có thông điệp bị thất lạc"

            lat = []
            for c in clients:
                seen = set()
                for m in c.received:
                    if m["type"] in ("MSG_BCAST", "MSG_DM"):
                        i, k, ts = m["text"].split("|")
                        key = (m["type"], i, k)
                        assert key not in seen, "nhận trùng"
                        seen.add(key)
                        lat.append(m["_rx"] - float(ts))
            for c in clients:
                c.close()
            await asyncio.sleep(0.2)
            leak = {"online": len(srv.registry), "pending": len(srv.table.pending),
                    "transfers": len(srv.relay.transfers),
                    "extra_tasks": len(asyncio.all_tasks()) - base_tasks}
            return login_s, sent, len(lat), lat, leak

    # Đo độ trễ ở chế độ thường: chế độ debug của asyncio làm mọi thứ chậm ~15 lần (đo được 0,35 ms -> 6 ms)
    # nên con số trễ đo trong debug không có ý nghĩa. Kiểm "bước chậm > 0,1s" chạy riêng ở test dưới.
    login_s, sent, delivered, lat, leak = run(go(), debug=False)
    lat_ms = sorted(x * 1000 for x in lat)
    p95 = lat_ms[int(len(lat_ms) * 0.95)]
    print(f"\n{N} client đăng ký+đăng nhập song song: {login_s:.2f}s | gửi {sent} tin, {delivered} lượt nhận"
          f" | trễ TB {statistics.mean(lat_ms):.2f} ms, trung vị {statistics.median(lat_ms):.2f} ms,"
          f" p95 {p95:.2f} ms | sau khi thoát: {leak}")
    assert sent > 200
    assert leak == {"online": 0, "pending": 0, "transfers": 0, "extra_tasks": 0}
    assert statistics.mean(lat_ms) < 10


def test_chat_latency_unaffected_by_concurrent_logins(tmp_path):
    """Hai client đã online nhắn qua lại trong lúc 20 client khác cùng đăng nhập (PBKDF2 100k)."""
    async def go(d):
        d.mkdir()
        async with running_server(d, iterations=100_000) as (srv, hub):
            a = await TestClient(srv, hub, "pinga").connect()
            b = await TestClient(srv, hub, "pingb").connect()

            async def pingpong(n):
                out = []
                for _ in range(n):
                    t = time.perf_counter()
                    await a.send({"type": "MSG_DM", "to": "pingb", "text": "p"})
                    await b.expect("MSG_DM", timeout=2)
                    out.append(time.perf_counter() - t)
                    await asyncio.sleep(0.005)
                return out

            idle = await pingpong(100)
            logins = asyncio.gather(*(TestClient(srv, hub, f"late{i:02d}").connect() for i in range(N)))
            busy = await pingpong(100)
            await logins
            return idle, busy

    with SlowCallbackCollector() as col:          # lượt 1, debug: không bước nào chiếm event loop > 0,1s
        run(go(tmp_path / "debug"), debug=True)
    assert not col.records, col.records
    idle, busy = run(go(tmp_path / "normal"), debug=False)           # lượt 2, chế độ thường: đo độ trễ
    f = lambda xs: (statistics.mean(xs) * 1000, sorted(xs)[94] * 1000)
    (im, ip), (bm, bp) = f(idle), f(busy)
    print(f"\nDM khi rảnh: TB {im:.2f} ms, p95 {ip:.2f} ms | trong lúc 20 đăng nhập: TB {bm:.2f} ms, p95 {bp:.2f} ms")
    assert bm < 10 and bp < 10
