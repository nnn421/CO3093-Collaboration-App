"""Phía client của giao thức đăng nhập (protocol_messages.md §3, §4). B viết sẵn để C3 dùng trong ClientAgent.

    res = await tcp_login(config.SERVER_HOST, config.TCP_PORT, "alice", "secret123", register=True)
    conn = await <UDP transport của A>.connect(res.conn_id, AESGCMCipher.for_client(res.keys))  # gửi gói HELLO
    users = await await_bind(conn)          # chờ USER_LIST đầu tiên = server đã gắn UDP
"""
from __future__ import annotations

import asyncio
import secrets
from dataclasses import dataclass

from shared import config, crypto, messages


class AuthError(Exception):
    def __init__(self, code: str, detail: str = ""):
        super().__init__(f"{code}: {detail}")
        self.code = code


@dataclass
class LoginResult:
    username: str
    conn_id: int
    keys: crypto.SessionKeys
    udp_port: int


async def _handshake(host, port, pinned_identity: bytes, timeout: float):
    """Client gửi KEY_EXCHANGE trước; kiểm chữ ký của server trên transcript; sai thì dừng, không gửi gì thêm."""
    reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
    try:
        priv = crypto.new_x25519()
        cpub = crypto.x25519_pub_bytes(priv)
        await messages.write_message(writer, messages.encode(
            {"type": messages.KEY_EXCHANGE, "v": config.PROTOCOL_VERSION, "pubkey": messages.b64e(cpub)}))
        reply = messages.decode(await asyncio.wait_for(messages.read_message(reader), timeout))
        if reply.get("type") != messages.KEY_EXCHANGE or reply.get("v") != config.PROTOCOL_VERSION:
            raise AuthError(messages.E_BAD_MESSAGE, "server không trả KEY_EXCHANGE đúng phiên bản")
        spub = messages.b64d(reply.get("pubkey"), crypto.X25519_PUB_BYTES, "pubkey")
        sig = messages.b64d(reply.get("sig"), config.ED25519_SIG_BYTES, "sig")
        if not crypto.verify_kx(pinned_identity, sig, cpub, spub):
            raise AuthError("BAD_SIGNATURE", "chữ ký khóa server sai: có thể đang bị MITM")
        keys = crypto.derive_session_keys(priv, spub, cpub, spub)
    except BaseException:
        writer.close()
        raise
    return reader, writer, keys, crypto.TcpSecureChannel(reader, writer, keys.tcp_c2s, keys.tcp_s2c)


async def tcp_login(host: str, port: int, username: str, password: str, *, register: bool = False,
                    pinned_identity: bytes | None = None,
                    timeout: float = config.CLIENT_TCP_TIMEOUT) -> LoginResult:
    """Đăng nhập (và đăng ký trước nếu register=True). Mỗi lần gọi là một kết nối và một lần bắt tay mới."""
    if pinned_identity is None:
        pinned_identity = crypto.pinned_identity_from_config()
    reader, writer, keys, ch = await _handshake(host, port, pinned_identity, timeout)
    try:
        if register:
            await ch.send({"type": messages.REGISTER, "username": username, "password": password})
            r = await asyncio.wait_for(ch.recv(), timeout)
            if r["type"] != messages.AUTH_OK:      # kể cả USER_EXISTS: báo đúng lỗi, không âm thầm đăng nhập
                raise AuthError(r.get("code", "?"), r.get("detail", ""))
        await ch.send({"type": messages.LOGIN, "username": username, "password": password})
        r = await asyncio.wait_for(ch.recv(), timeout)
        if r["type"] != messages.AUTH_OK:
            raise AuthError(r.get("code", "?"), r.get("detail", ""))
        return LoginResult(username, int(r["conn_id"]), keys, int(r.get("udp_port", config.UDP_PORT)))
    finally:
        writer.close()      # protocol_messages.md §4: client đóng TCP ngay sau AUTH_OK


async def await_bind(conn, timeout: float = config.CLIENT_BIND_TIMEOUT) -> list[str]:
    """Chờ USER_LIST đầu tiên trên stream 1: tín hiệu server đã gắn UDP (xác nhận gói HELLO).

    Trả về danh sách người online. Dùng chung FrameReader với phần còn lại của client thì
    truyền thông điệp này tiếp cho bộ xử lý USER_LIST bình thường.
    """
    reader = messages.FrameReader(conn.open_stream(config.STREAM_CHAT))
    msg = messages.decode(await asyncio.wait_for(reader.read(), timeout))
    if msg.get("type") != messages.USER_LIST:
        raise AuthError(messages.E_BAD_MESSAGE, f"mong USER_LIST, nhận {msg.get('type')}")
    return msg["users"]


def new_msg_id() -> str:
    return "m-" + secrets.token_hex(6)


def new_transfer_id() -> bytes:
    return secrets.token_bytes(config.TRANSFER_ID_BYTES)
