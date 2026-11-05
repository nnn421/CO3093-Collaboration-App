"""B9 + B1 - Server không sập trước rác/ngắt đột ngột; khởi động và tắt (SIGINT) sạch.

Phần UDP rác (1000 datagram ngẫu nhiên tới cổng 9001) bị chặn ở tầng A (CRC32 + thẻ GCM);
test đó cần UDPEndpoint thật nên chưa có ở đây.
"""
import asyncio
import os
import random
import signal
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path

from shared import messages
from tests.helpers import TestClient, run, running_server

ROOT = Path(__file__).resolve().parent.parent


async def _garbage_conn(port: int, rnd: random.Random) -> None:
    try:
        r, w = await asyncio.open_connection("127.0.0.1", port)
        kind = rnd.randrange(6)
        if kind == 0:
            w.write(os.urandom(rnd.randrange(1, 200)))                       # byte ngẫu nhiên
        elif kind == 1:
            w.write(struct.pack(">I", 2**31) + b"x")                          # khai báo độ dài khổng lồ
        elif kind == 2:
            w.write(struct.pack(">I", 10) + b"{bad json!")                    # JSON hỏng
        elif kind == 3:
            body = messages.encode({"type": "KEY_EXCHANGE", "v": 1, "pubkey": messages.b64e(b"\x00" * 32)})
            w.write(struct.pack(">I", len(body)) + body)                      # khóa bậc thấp
        elif kind == 4:
            body = messages.encode({"type": "KEY_EXCHANGE", "v": 1, "pubkey": messages.b64e(os.urandom(32))})
            w.write(struct.pack(">I", len(body)) + body)
            await w.drain()
            await r.readexactly(4)                                            # nhận khóa server
            w.write(struct.pack(">I", 40) + os.urandom(40))                   # rồi gửi ciphertext rác
        else:
            pass                                                              # mở rồi đóng ngay
        await w.drain()
        if rnd.random() < 0.5:
            w.transport.abort()                                               # RST thay vì FIN
        else:
            w.close()
    except (ConnectionError, asyncio.IncompleteReadError, OSError):
        pass


def test_1000_garbage_connections_then_normal_service(tmp_path):
    async def go():
        async with running_server(tmp_path) as (srv, hub):
            a = await TestClient(srv, hub, "alice").connect()
            rnd = random.Random(42)
            for _ in range(10):
                await asyncio.gather(*(_garbage_conn(srv.login.port, rnd) for _ in range(100)))
            await asyncio.sleep(0.3)
            b = await TestClient(srv, hub, "bob").connect()          # server vẫn nhận đăng nhập mới
            await a.send({"type": "MSG_DM", "to": "bob", "text": "còn sống"})
            assert (await b.expect("MSG_DM"))["text"] == "còn sống"
            return dict(srv.login.stats)
    stats = run(go())
    print(f"\nthống kê kênh TCP sau 1000 kết nối rác: {stats}")
    assert stats["connections"] >= 1002


def test_garbage_flood_on_chat_stream_isolated(tmp_path):
    async def go():
        async with running_server(tmp_path) as (srv, hub):
            a = await TestClient(srv, hub, "alice").connect()
            b = await TestClient(srv, hub, "bob").connect()
            evil = await TestClient(srv, hub, "mallory").connect()
            for _ in range(1000):
                try:
                    await evil.send_raw_frame(os.urandom(random.randrange(0, 300)))
                except ConnectionError:
                    break
            await asyncio.sleep(0.1)
            assert srv.registry.get("mallory") is None            # bị ngắt sau ngưỡng rác
            await a.send({"type": "MSG_BCAST", "text": "ok"})
            assert (await b.expect("MSG_BCAST"))["text"] == "ok"
    run(go())


def test_handler_exception_does_not_kill_session(tmp_path):
    async def go():
        async with running_server(tmp_path) as (srv, hub):
            a = await TestClient(srv, hub, "alice").connect()
            b = await TestClient(srv, hub, "bob").connect()
            srv.relay.handle = lambda s, m: 1 / 0                 # lỗi lập trình giả lập
            await a.send({"type": "FILE_ACCEPT", "transfer_id": messages.b64e(b"\xab" * 16)})
            assert (await a.expect("ERROR"))["code"] == messages.E_SERVER
            await a.send({"type": "MSG_DM", "to": "bob", "text": "vẫn chạy"})
            assert (await b.expect("MSG_DM"))["text"] == "vẫn chạy"
    run(go())


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# Windows không gửi được SIGINT sang tiến trình khác (Popen.send_signal báo "Unsupported signal: 2").
# Khi đó tiến trình server tự phát SIGINT cho chính nó ngay khi cổng đã mở, giống người dùng bấm Ctrl+C.
_SELF_SIGINT = """
import signal, socket, sys, threading, time
sys.path.insert(0, sys.argv[1])
from server import main as m
port = int(sys.argv[2])
def fire():
    end = time.time() + 10
    while time.time() < end:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            break
        except OSError:
            time.sleep(0.1)
    signal.raise_signal(signal.SIGINT)
threading.Thread(target=fire, daemon=True).start()
m.main(sys.argv[3:])
"""


def test_main_starts_and_stops_cleanly_on_sigint(tmp_path, self_signal=sys.platform == "win32"):
    port = _free_port()
    args = ["--host", "127.0.0.1", "--tcp-port", str(port), "--users-file", str(tmp_path / "u.json"),
            "--identity-file", str(tmp_path / "id.key"), "--identity-pub-file", str(tmp_path / "id.pub")]
    cmd = ([sys.executable, "-c", _SELF_SIGINT, str(ROOT), str(port), *args] if self_signal
           else [sys.executable, str(ROOT / "server" / "main.py"), *args])
    p = subprocess.Popen(cmd, cwd=tmp_path, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                         encoding="utf-8", errors="replace")
    try:
        deadline = time.time() + 10
        while time.time() < deadline:
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.1)
        if not self_signal:
            p.send_signal(signal.SIGINT)
        out, _ = p.communicate(timeout=5)
    finally:
        if p.poll() is None:
            p.kill()
    print("\n" + out)
    assert p.returncode == 0
    assert f"127.0.0.1:{port}" in out and "đã dừng sạch" in out and "Traceback" not in out
