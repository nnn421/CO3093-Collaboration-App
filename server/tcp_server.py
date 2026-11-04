"""B2 + B3 + B4 - Kênh TCP (protocol_messages.md §3):
KEY_EXCHANGE (client gửi trước, server trả kèm chữ ký) -> REGISTER/LOGIN (mã hóa) -> AUTH_OK{conn_id}
-> chờ client gửi gói HELLO qua UDP -> đóng TCP.

Mọi lỗi của MỘT kết nối chỉ đóng kết nối đó; không bao giờ lan ra server (B9).
"""
from __future__ import annotations

import asyncio
import logging
import time

from cryptography.exceptions import InvalidTag

from shared import config, crypto, messages
from server.auth import UserStore
from server.udp_bind import SessionTable

log = logging.getLogger("server.tcp")


class LoginServer:
    def __init__(self, users: UserStore, table: SessionTable, identity, *, host: str = config.BIND_HOST,
                 port: int = config.TCP_PORT, udp_port: int = config.UDP_PORT,
                 read_timeout: float = config.TCP_READ_TIMEOUT, auth_timeout: float = config.AUTH_TIMEOUT,
                 bind_timeout: float = config.UDP_BIND_TIMEOUT, max_attempts: int = config.MAX_LOGIN_ATTEMPTS):
        if identity is None:
            raise ValueError("server bắt buộc có khóa danh tính Ed25519 (protocol_messages.md §3.2)")
        self.users, self.table, self.identity = users, table, identity
        self.host, self.port, self.udp_port = host, port, udp_port
        self.read_timeout, self.auth_timeout = read_timeout, auth_timeout
        self.bind_timeout, self.max_attempts = bind_timeout, max_attempts
        self.server: asyncio.base_events.Server | None = None
        self._handlers: set[asyncio.Task] = set()
        self.stats = {"connections": 0, "logins": 0, "failed": 0, "errors": 0}

    async def start(self) -> int:
        self.server = await asyncio.start_server(self._handle, self.host, self.port)
        self.port = self.server.sockets[0].getsockname()[1]   # hỗ trợ port=0 trong test
        return self.port

    async def stop(self) -> None:
        if self.server:
            self.server.close()           # ngừng nhận kết nối mới
        for t in list(self._handlers):    # hủy các phiên đang dở TRƯỚC wait_closed (3.12+ chờ hết client)
            t.cancel()
        if self._handlers:
            await asyncio.gather(*self._handlers, return_exceptions=True)
        if self.server:
            await self.server.wait_closed()

    # ---------------------------------------------------------------- mỗi kết nối
    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = asyncio.current_task()
        self._handlers.add(task)
        peer = writer.get_extra_info("peername")
        self.stats["connections"] += 1
        try:
            # AUTH_TIMEOUT: giới hạn tổng cho cả giai đoạn TCP (chặn kiểu gửi nhỏ giọt để giữ kết nối)
            await asyncio.wait_for(self._session(reader, writer, peer), self.auth_timeout)
        except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError, ConnectionAbortedError):
            log.info("%s ngắt kết nối giữa chừng", peer)
        except asyncio.TimeoutError:
            log.info("%s quá thời gian chờ trên kênh TCP", peer)
        except (messages.ProtocolError, InvalidTag, ValueError, OverflowError) as e:
            self.stats["errors"] += 1
            log.warning("%s gửi dữ liệu không hợp lệ: %s: %s", peer, type(e).__name__, e)
        except asyncio.CancelledError:
            pass
        except Exception:
            self.stats["errors"] += 1
            log.exception("lỗi không lường trước với %s", peer)
        finally:
            self._handlers.discard(task)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def _read(self, coro):
        """TCP_READ_TIMEOUT: hạn đọc đủ MỘT thông điệp."""
        return await asyncio.wait_for(coro, self.read_timeout)

    async def _session(self, reader, writer, peer) -> None:
        t0 = time.perf_counter()
        # 1) KEY_EXCHANGE: client gửi trước (thông điệp rõ)
        kx = messages.validate_c2s(messages.decode(await self._read(messages.read_message(reader))),
                                   {messages.KEY_EXCHANGE})
        if kx["v"] != config.PROTOCOL_VERSION:
            raise messages.ProtocolError(f"phiên bản giao thức không hỗ trợ: {kx['v']}")
        client_pub = messages.b64d(kx["pubkey"], crypto.X25519_PUB_BYTES, "pubkey")

        priv = crypto.new_x25519()
        server_pub = crypto.x25519_pub_bytes(priv)
        keys = crypto.derive_session_keys(priv, client_pub, client_pub, server_pub)   # ValueError nếu khóa bậc thấp
        sig = crypto.sign_kx(self.identity, client_pub, server_pub)
        await messages.write_message(writer, messages.encode(
            {"type": messages.KEY_EXCHANGE, "v": config.PROTOCOL_VERSION,
             "pubkey": messages.b64e(server_pub), "sig": messages.b64e(sig)}))
        ch = crypto.TcpSecureChannel(reader, writer, send_key=keys.tcp_s2c, recv_key=keys.tcp_c2s)
        log.debug("%s: trao khóa xong sau %.1f ms", peer, (time.perf_counter() - t0) * 1000)

        # 2) REGISTER / LOGIN (đã mã hóa)
        failures = 0
        while True:
            msg = await self._read(ch.recv())
            action = str(msg.get("type"))
            try:
                msg = messages.validate_c2s(msg, {messages.REGISTER, messages.LOGIN})
            except messages.ProtocolError as e:
                code, detail = messages.E_BAD_MESSAGE, str(e)
            else:
                user, pw = msg["username"], msg["password"]
                if action == messages.REGISTER:
                    ok, code = await self.users.register(user, pw)
                    if ok:
                        await ch.send({"type": messages.AUTH_OK, "action": action, "username": user})
                        continue
                    detail = ""
                elif await self.users.verify(user, pw):
                    await self._finish_login(ch, user, keys, peer)
                    return
                else:
                    self.stats["failed"] += 1
                    log.info("%s đăng nhập sai cho tài khoản %r", peer, user)
                    code, detail = messages.E_BAD_CREDENTIALS, "Sai tên hoặc mật khẩu"
            failures += 1
            await ch.send(messages.auth_fail(action, code, detail))
            if failures >= self.max_attempts:
                await ch.send(messages.auth_fail(action, messages.E_TOO_MANY_ATTEMPTS,
                                                 f"thất bại {failures} lần, đóng kết nối"))
                return

    async def _finish_login(self, ch, user, keys, peer) -> None:
        p = self.table.add_pending(user, keys)
        await ch.send({"type": messages.AUTH_OK, "action": messages.LOGIN, "username": user,
                       "conn_id": p.conn_id, "udp_port": self.udp_port})
        self.stats["logins"] += 1
        log.info("%s đăng nhập OK: %s, conn_id=%#010x, chờ gói HELLO", peer, user, p.conn_id)
        try:
            await asyncio.wait_for(p.bound.wait(), self.bind_timeout)
            log.info("%s (%s) đã gắn UDP -> đóng TCP", user, peer)
        except asyncio.TimeoutError:
            self.table.discard(p.conn_id)
            log.warning("%s không gửi HELLO trong %ss -> hủy conn_id", user, self.bind_timeout)
