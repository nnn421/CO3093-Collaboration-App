"""
server/tcp_auth.py
------------------
Máy chủ TCP chuyên trách Bắt tay Trao đổi Khóa X25519 và Xác thực Đăng ký / Đăng nhập (B2, B5).
Chạy trên cổng TCP 9000.

Quy trình:
  1. Client kết nối TCP.
  2. Trao đổi Public Key X25519 (mã hóa base64 trong JSON).
  3. Hai bên dùng HKDF phái sinh 4 chìa khóa AES-256 (tcp_c2s, tcp_s2c, udp_c2s, udp_s2c).
  4. Kích hoạt mã hóa AES-256-GCM trên luồng TCP.
  5. Tiếp nhận yêu cầu REGISTER hoặc LOGIN từ Client.
  6. Server cấp phát conn_id và lưu thông tin phiên vào SessionManager.
  7. Phản hồi AUTH_OK (hoặc AUTH_FAIL) và đóng kết nối TCP.
"""

import asyncio
import base64
import logging
from typing import Optional

from server.session_manager import SessionManager
from server.user_db import UserDB
from shared.config import TCP_PORT
from shared.crypto import (
    derive_session_keys,
    derive_shared_secret,
    generate_x25519_keypair,
)
from shared.framing import recv_framed_msg, send_framed_msg

log = logging.getLogger("server.tcp_auth")


class TCPAuthServer:
    """Máy chủ xác thực và bắt tay khóa qua TCP."""

    def __init__(
        self,
        user_db: UserDB,
        session_manager: SessionManager,
        host: str = "0.0.0.0",
        port: int = TCP_PORT
    ):
        self.user_db = user_db
        self.session_manager = session_manager
        self.host = host
        self.port = port
        self._server: Optional[asyncio.Server] = None

    async def start(self) -> None:
        """Khởi động máy chủ TCP."""
        self._server = await asyncio.start_server(
            self._handle_client,
            self.host,
            self.port
        )
        log.info(f"TCP Auth Server đang lắng nghe tại {self.host}:{self.port}")

    async def stop(self) -> None:
        """Dừng máy chủ TCP."""
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            log.info("TCP Auth Server đã dừng.")

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter
    ) -> None:
        """Xử lý từng kết nối TCP của Client từ đầu đến cuối."""
        peer_addr = writer.get_extra_info("peername")
        log.info(f"Kết nối TCP mới từ {peer_addr}")

        try:
            # ── BƯỚC 1: TRAO ĐỔI KHÓA X25519 (ECDH) ────────────────────────
            # Nhận Public Key của Client
            req = await recv_framed_msg(reader)
            if req.get("type") != "KEY_EXCHANGE" or "client_pub" not in req:
                log.warning(f"Từ chối kết nối {peer_addr}: Thông điệp đầu tiên không phải KEY_EXCHANGE.")
                return

            client_pub_bytes = base64.b64decode(req["client_pub"])
            if len(client_pub_bytes) != 32:
                log.warning(f"Từ chối kết nối {peer_addr}: Public Key của Client không đủ 32B.")
                return

            # Server sinh cặp khóa tạm thời (ephemeral)
            server_priv, server_pub_bytes = generate_x25519_keypair()

            # Server tính toán shared_secret và phái sinh 4 chìa khóa bằng HKDF
            shared_secret = derive_shared_secret(server_priv, client_pub_bytes)
            keys = derive_session_keys(shared_secret)

            # Phản hồi Public Key của Server cho Client
            await send_framed_msg(writer, {
                "type": "KEY_EXCHANGE_ACK",
                "server_pub": base64.b64encode(server_pub_bytes).decode("ascii")
            })

            # Kể từ thời điểm này, mọi thông điệp TCP tiếp theo được mã hóa:
            # Server giải mã dữ liệu Client gửi bằng `tcp_c2s`
            # Server mã hóa dữ liệu gửi cho Client bằng `tcp_s2c`
            tcp_c2s = keys["tcp_c2s"]
            tcp_s2c = keys["tcp_s2c"]

            # ── BƯỚC 2: TIẾP NHẬN YÊU CẦU XÁC THỰC (REGISTER / LOGIN) ──────
            auth_msg = await recv_framed_msg(reader, key=tcp_c2s)
            msg_type = auth_msg.get("type")
            username = str(auth_msg.get("username", "")).strip()
            password = str(auth_msg.get("password", ""))

            if not username or not password:
                await send_framed_msg(writer, {
                    "type": "AUTH_FAIL",
                    "reason": "Tên đăng nhập hoặc mật khẩu không được để trống."
                }, key=tcp_s2c)
                return

            if msg_type == "REGISTER":
                success = await self.user_db.register(username, password)
                if not success:
                    await send_framed_msg(writer, {
                        "type": "AUTH_FAIL",
                        "reason": f"Tài khoản '{username}' đã tồn tại trong hệ thống."
                    }, key=tcp_s2c)
                    return
            elif msg_type == "LOGIN":
                success = await self.user_db.authenticate(username, password)
                if not success:
                    await send_framed_msg(writer, {
                        "type": "AUTH_FAIL",
                        "reason": "Tài khoản hoặc mật khẩu không chính xác."
                    }, key=tcp_s2c)
                    return
            else:
                await send_framed_msg(writer, {
                    "type": "AUTH_FAIL",
                    "reason": f"Loại yêu cầu '{msg_type}' không được hỗ trợ."
                }, key=tcp_s2c)
                return

            # ── BƯỚC 3: CẤP PHÁT PHIÊN VÀ PHẢN HỒI CONN_ID ─────────────────
            session = self.session_manager.create_session(
                username=username,
                udp_c2s_key=keys["udp_c2s"],
                udp_s2c_key=keys["udp_s2c"],
                tcp_c2s_key=tcp_c2s,
                tcp_s2c_key=tcp_s2c
            )

            await send_framed_msg(writer, {
                "type": "AUTH_OK",
                "conn_id": session.conn_id,
                "username": username
            }, key=tcp_s2c)
            log.info(f"Xác thực thành công cho '{username}' [ConnID={session.conn_id:#010x}].")

        except Exception as e:
            log.error(f"Lỗi khi xử lý TCP client {peer_addr}: {e}")
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
