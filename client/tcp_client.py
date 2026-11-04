"""
client/tcp_client.py
--------------------
Phụ trách Bắt tay Trao đổi Khóa X25519 và Xác thực Đăng ký / Đăng nhập
phía máy khách (Client-side TCP Handshake) (C6 / B2).

Kết nối tới cổng TCP 9000, thực hiện thỏa thuận khóa, gửi thông tin tài khoản
đã mã hóa, nhận conn_id và 4 chìa khóa phiên, sau đó đóng kết nối TCP.
"""

import asyncio
import base64
import logging
from typing import Dict, Tuple

from shared.config import TCP_PORT
from shared.crypto import (
    derive_session_keys,
    derive_shared_secret,
    generate_x25519_keypair,
)
from shared.framing import recv_framed_msg, send_framed_msg

log = logging.getLogger("client.tcp")


class AuthenticationError(Exception):
    """Ngoại lệ khi đăng ký hoặc đăng nhập thất bại."""
    pass


async def perform_tcp_handshake(
    host: str,
    port: int = TCP_PORT,
    action: str = "LOGIN",  # "LOGIN" hoặc "REGISTER"
    username: str = "",
    password: str = ""
) -> Tuple[int, Dict[str, bytes]]:
    """
    Thực hiện trọn gói chu trình bắt tay TCP:
      1. Kết nối tới TCP Server.
      2. Trao đổi khóa bí mật X25519 (ECDH).
      3. Dùng HKDF phái sinh 4 chìa khóa AES-256.
      4. Gửi yêu cầu REGISTER hoặc LOGIN (đã mã hóa bằng tcp_c2s).
      5. Nhận phản hồi AUTH_OK (hoặc báo lỗi AUTH_FAIL).
      6. Đóng kết nối TCP và trả về (conn_id, dictionary 4 chìa khóa).
      
    Returns:
        Tuple: (conn_id: int, session_keys: dict)
        session_keys chứa: tcp_c2s, tcp_s2c, udp_c2s, udp_s2c
    """
    reader, writer = await asyncio.open_connection(host, port)

    try:
        # 1. Sinh khóa tạm thời phía Client và gửi Public Key lên Server
        client_priv, client_pub_bytes = generate_x25519_keypair()
        await send_framed_msg(writer, {
            "type": "KEY_EXCHANGE",
            "client_pub": base64.b64encode(client_pub_bytes).decode("ascii")
        })

        # 2. Nhận Public Key của Server
        resp = await recv_framed_msg(reader)
        if resp.get("type") != "KEY_EXCHANGE_ACK" or "server_pub" not in resp:
            raise AuthenticationError("Bắt tay thất bại: Server không gửi lại KEY_EXCHANGE_ACK hợp lệ.")

        server_pub_bytes = base64.b64decode(resp["server_pub"])

        # 3. Tính toán Shared Secret và phái sinh 4 khóa
        shared_secret = derive_shared_secret(client_priv, server_pub_bytes)
        keys = derive_session_keys(shared_secret)

        tcp_c2s = keys["tcp_c2s"]
        tcp_s2c = keys["tcp_s2c"]

        # 4. Gửi yêu cầu Đăng ký hoặc Đăng nhập (Mã hóa bằng tcp_c2s)
        await send_framed_msg(writer, {
            "type": action.upper(),
            "username": username,
            "password": password
        }, key=tcp_c2s)

        # 5. Nhận kết quả xác thực từ Server (Giải mã bằng tcp_s2c)
        auth_resp = await recv_framed_msg(reader, key=tcp_s2c)
        if auth_resp.get("type") != "AUTH_OK":
            reason = auth_resp.get("reason", "Lỗi xác thực không xác định.")
            raise AuthenticationError(reason)

        conn_id = int(auth_resp["conn_id"])
        log.info(f"Đăng nhập thành công! Được cấp ConnID={conn_id:#010x}")
        return conn_id, keys

    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
