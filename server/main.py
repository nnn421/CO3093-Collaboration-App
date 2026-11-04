"""B1 + B9 - Điểm vào máy chủ.

Chạy:  python server/main.py [--host 0.0.0.0] [--tcp-port 9000] [--udp-port 9001] [--debug]

Quy tắc chung cho mọi code asyncio (B1): không có lệnh chặn trong event loop. Việc tốn CPU
(PBKDF2, băm tệp) -> run_in_executor; chờ -> await asyncio.sleep. Chạy --debug để asyncio
cảnh báo bước nào chiếm event loop quá 0,1 giây.
"""
from __future__ import annotations

import argparse
import asyncio
import inspect
import logging
import signal
import sys
from pathlib import Path

if __package__ in (None, ""):                      # cho phép `python server/main.py` từ gốc repo
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from shared import config, crypto                   # noqa: E402
from server.auth import UserStore                   # noqa: E402
from server.file_relay import FileRelay             # noqa: E402
from server.registry import Registry, Session       # noqa: E402
from server.router import Router, heartbeat_loop    # noqa: E402
from server.tcp_server import LoginServer           # noqa: E402
from server.udp_bind import SessionTable, UdpBinder  # noqa: E402

log = logging.getLogger("server")


async def resilient_loop(name: str, fn, interval: float) -> None:
    """B9: tác vụ nền lỗi một lượt thì ghi log và chạy lượt sau, không chết âm thầm."""
    while True:
        try:
            r = fn()
            if inspect.isawaitable(r):
                await r
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("tác vụ nền '%s' lỗi một lượt, sẽ chạy lại", name)
        await asyncio.sleep(interval)


def _log_task_end(task: asyncio.Task) -> None:
    if task.cancelled():
        return
    exc = task.exception()
    if exc and not isinstance(exc, ConnectionError):
        log.error("task %s kết thúc vì lỗi: %r", task.get_name(), exc)


class ChatServer:
    def __init__(self, *, host: str = config.BIND_HOST, tcp_port: int = config.TCP_PORT,
                 udp_port: int = config.UDP_PORT, users_file: str = config.USERS_FILE,
                 identity_file: str = config.SERVER_IDENTITY_FILE,
                 identity_pub_file: str | None = config.SERVER_IDENTITY_PUB_FILE,
                 pbkdf2_iterations: int = config.PBKDF2_ITERATIONS,
                 idle_timeout: float = config.IDLE_TIMEOUT,
                 sweep_interval: float = config.REGISTRY_SWEEP_INTERVAL,
                 bind_timeout: float = config.UDP_BIND_TIMEOUT,
                 read_timeout: float = config.TCP_READ_TIMEOUT,
                 auth_timeout: float = config.AUTH_TIMEOUT,
                 offer_timeout: float = config.FILE_OFFER_TIMEOUT,
                 replaced_grace: float = config.SESSION_REPLACED_GRACE):
        self.users = UserStore(users_file, pbkdf2_iterations)
        self.registry = Registry(idle_timeout, replaced_grace)
        self.table = SessionTable(self.registry, bind_timeout)
        self.relay = FileRelay(self.registry, offer_timeout)
        self.router = Router(self.registry, self.relay)
        self.binder = UdpBinder(self.table, self.registry, self._start_session)
        identity = crypto.load_or_create_identity(identity_file, identity_pub_file)   # bắt buộc
        self.identity_pub = crypto.identity_pub_bytes(identity)
        self.login = LoginServer(self.users, self.table, identity, host=host, port=tcp_port,
                                 udp_port=udp_port, read_timeout=read_timeout, auth_timeout=auth_timeout,
                                 bind_timeout=bind_timeout)
        self.sweep_interval = sweep_interval
        self._bg: list[asyncio.Task] = []

    def _start_session(self, s: Session) -> None:
        loop = asyncio.get_running_loop()
        for name, coro in (("writer", s.writer_loop()),
                           ("router", self.router.session_loop(s)),
                           ("heartbeat", heartbeat_loop(self.registry, s)),
                           ("chunks", self.relay.accept_loop(s))):
            t = loop.create_task(coro, name=f"{name}-{s.username}")
            t.add_done_callback(_log_task_end)
            s.tasks.append(t)

    async def start(self, transport) -> None:
        """transport: đối tượng có listen(cipher_lookup, on_connection) - UDPEndpoint (A1) hoặc FakeHub."""
        port = await self.login.start()
        if transport is not None:
            transport.listen(self.table.cipher_for, self.binder.on_connection)
        self._bg.append(asyncio.get_running_loop().create_task(
            resilient_loop("registry-sweep", lambda: self.registry.sweep_once(), self.sweep_interval),
            name="sweep"))
        log.info("TCP đăng nhập lắng nghe tại %s:%d", self.login.host, port)

    async def stop(self) -> None:
        log.info("đang dừng máy chủ...")
        await self.login.stop()
        self.registry.close_all("server shutdown")
        for t in self._bg:
            t.cancel()
        await asyncio.gather(*self._bg, return_exceptions=True)
        await asyncio.sleep(0)      # cho các task phiên nhận CancelledError
        log.info("đã dừng sạch")


def parse_args(argv=None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="CO3093 - máy chủ chat/file")
    p.add_argument("--host", default=config.BIND_HOST)
    p.add_argument("--tcp-port", type=int, default=config.TCP_PORT)
    p.add_argument("--udp-port", type=int, default=config.UDP_PORT)
    p.add_argument("--users-file", default=config.USERS_FILE)
    p.add_argument("--identity-file", default=config.SERVER_IDENTITY_FILE)
    p.add_argument("--identity-pub-file", default=config.SERVER_IDENTITY_PUB_FILE)
    p.add_argument("--debug", action="store_true", help="asyncio debug + log DEBUG")
    return p.parse_args(argv)


async def amain(args: argparse.Namespace) -> None:
    server = ChatServer(host=args.host, tcp_port=args.tcp_port, udp_port=args.udp_port,
                        users_file=args.users_file, identity_file=args.identity_file,
                        identity_pub_file=args.identity_pub_file)
    transport = None
    try:
        from transport.udp_endpoint import UDPEndpoint     # A1
        transport = await UDPEndpoint.create(args.host, args.udp_port)
        log.info("UDP streaming lắng nghe tại %s:%d", args.host, args.udp_port)
    except ImportError:
        log.error("Chưa có transport/udp_endpoint.py (việc A1): chỉ chạy kênh TCP đăng nhập.")

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, getattr(signal, "SIGTERM", None)):
        if sig is None:
            continue
        try:
            loop.add_signal_handler(sig, stop.set)
        except (NotImplementedError, RuntimeError, ValueError):
            pass    # Windows: không có add_signal_handler; Ctrl+C đi qua KeyboardInterrupt của asyncio.run
    await server.start(transport)
    log.info("khóa danh tính Ed25519 (client ghim giá trị này vào config.SERVER_IDENTITY_PUB): %s",
             server.identity_pub.hex())
    try:
        await stop.wait()
    finally:
        await server.stop()
        if transport is not None and hasattr(transport, "close"):
            transport.close()


def main(argv=None) -> None:
    args = parse_args(argv)
    for stream in (sys.stdout, sys.stderr):      # console Windows mặc định không phải UTF-8 -> log tiếng Việt vỡ chữ
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO, format=config.LOG_FORMAT)
    try:
        asyncio.run(amain(args), debug=args.debug)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
