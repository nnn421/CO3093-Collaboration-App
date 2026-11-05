"""G2 - Danh mục thông điệp ứng dụng + framing. Đặc tả: docs/protocol_messages.md.

- encode/decode JSON theo quy ước chung (UTF-8, không ensure_ascii, separators gọn).
- validate_c2s(): kiểm tra kiểu và trường bắt buộc; mọi dữ liệu client gửi lên đều phải qua đây.
- Framing TCP (4B) và framing stream (2B).
"""
from __future__ import annotations

import asyncio
import base64
import binascii
import json
import re
import struct
import time

from shared import config

# ------------------------------------------------------------------ loại thông điệp
# TCP (đăng nhập)
KEY_EXCHANGE = "KEY_EXCHANGE"
REGISTER = "REGISTER"
LOGIN = "LOGIN"
AUTH_OK = "AUTH_OK"
AUTH_FAIL = "AUTH_FAIL"
# UDP stream 1
MSG_BCAST = "MSG_BCAST"
MSG_DM = "MSG_DM"
USER_LIST = "USER_LIST"
ERROR = "ERROR"
FILE_OFFER = "FILE_OFFER"
FILE_ACCEPT = "FILE_ACCEPT"
FILE_DONE = "FILE_DONE"
# UDP stream 3+: FILE_CHUNK là nhị phân, không phải JSON. HELLO là loại gói transport, không phải JSON.

CHAT_C2S = {MSG_BCAST, MSG_DM, FILE_OFFER, FILE_ACCEPT, FILE_DONE}

# Mã lỗi (AUTH_FAIL trên TCP, ERROR trên stream 1)
E_BAD_CREDENTIALS = "BAD_CREDENTIALS"
E_USER_EXISTS = "USER_EXISTS"
E_INVALID_INPUT = "INVALID_INPUT"
E_BAD_MESSAGE = "BAD_MESSAGE"
E_TOO_MANY_ATTEMPTS = "TOO_MANY_ATTEMPTS"
E_USER_OFFLINE = "USER_OFFLINE"
E_UNKNOWN_TRANSFER = "UNKNOWN_TRANSFER"
E_FILE_ABORTED = "FILE_ABORTED"
E_SESSION_REPLACED = "SESSION_REPLACED"
E_SERVER = "SERVER_ERROR"          # lỗi nội bộ server (không nằm trong bảng của spec, chỉ để báo lỗi lập trình)


class ProtocolError(ValueError):
    """Thông điệp sai định dạng. `code` để trả lời client, `ref` để ghép với thông điệp gây lỗi."""

    def __init__(self, detail: str, code: str = E_BAD_MESSAGE, ref: str | None = None):
        super().__init__(detail)
        self.code = code
        self.ref = ref


# ------------------------------------------------------------------ JSON
def encode(msg: dict) -> bytes:
    return json.dumps(msg, **config.JSON_DUMPS_KWARGS).encode("utf-8")


def decode(data: bytes) -> dict:
    try:
        msg = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise ProtocolError(f"không phải JSON UTF-8 hợp lệ: {e}") from None
    if not isinstance(msg, dict):
        raise ProtocolError("JSON phải là object")
    return msg


def now_ms() -> int:
    return int(time.time() * 1000)


# ------------------------------------------------------------------ base64 (mọi trường nhị phân)
def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def b64d(s, expected_len: int | None = None, field: str = "trường nhị phân") -> bytes:
    if not isinstance(s, str):
        raise ProtocolError(f"{field} phải là chuỗi base64")
    try:
        b = base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError):
        raise ProtocolError(f"{field} không phải base64 hợp lệ") from None
    if expected_len is not None and len(b) != expected_len:
        raise ProtocolError(f"{field} phải dài {expected_len} byte, nhận {len(b)}")
    return b


# ------------------------------------------------------------------ validate
_USERNAME_RE = re.compile(config.USERNAME_PATTERN)

# type -> {trường bắt buộc: kiểu}. Chỉ kiểm thông điệp client gửi lên; server tự dựng thông điệp của nó.
_SCHEMA_C2S: dict[str, dict[str, type]] = {
    KEY_EXCHANGE: {"v": int, "pubkey": str},
    REGISTER: {"username": str, "password": str},
    LOGIN: {"username": str, "password": str},
    MSG_BCAST: {"msg_id": str, "text": str},
    MSG_DM: {"msg_id": str, "to": str, "text": str},
    FILE_OFFER: {"transfer_id": str, "to": str, "name": str, "size": int},
    FILE_ACCEPT: {"transfer_id": str},
    FILE_DONE: {"transfer_id": str, "sha256": str},
}


def valid_username(name: str) -> bool:
    return bool(_USERNAME_RE.fullmatch(name))   # fullmatch: "$" của match() vẫn khớp trước "\n" cuối chuỗi


def valid_filename(name: str) -> bool:
    """Chỉ tên tệp, không đường dẫn: chặn ghi đè tệp ngoài thư mục tải về (path traversal)."""
    if not name or name in (".", "..") or len(name.encode()) > config.MAX_FILENAME_BYTES:
        return False
    if "/" in name or "\\" in name:
        return False
    return not any(ord(c) < 32 or ord(c) == 127 for c in name)


def validate_c2s(msg: dict, allowed: set[str]) -> dict:
    t = msg.get("type")
    ref = msg.get("msg_id") if isinstance(msg.get("msg_id"), str) else \
        msg.get("transfer_id") if isinstance(msg.get("transfer_id"), str) else None
    if t not in allowed:
        raise ProtocolError(f"loại thông điệp không hợp lệ ở kênh này: {t!r}", ref=ref)
    for field, typ in _SCHEMA_C2S[t].items():
        v = msg.get(field)
        # bool là lớp con của int trong Python -> chặn riêng
        if not isinstance(v, typ) or (typ is int and isinstance(v, bool)):
            raise ProtocolError(f"{t}: thiếu hoặc sai kiểu trường '{field}'", ref=ref)
    if t in (MSG_BCAST, MSG_DM):
        if not msg["msg_id"] or len(msg["msg_id"].encode()) > config.MAX_MSG_ID_BYTES:
            raise ProtocolError("msg_id rỗng hoặc quá dài", ref=None)
        if len(msg["text"].encode()) > config.MAX_TEXT_BYTES:
            raise ProtocolError("tin nhắn quá dài", ref=ref)
    if "transfer_id" in _SCHEMA_C2S[t]:
        b64d(msg["transfer_id"], config.TRANSFER_ID_BYTES, "transfer_id")
    if t == FILE_OFFER:
        if not 0 <= msg["size"] <= config.MAX_FILE_SIZE:
            raise ProtocolError("kích thước tệp không hợp lệ", ref=ref)
        if not valid_filename(msg["name"]):
            raise ProtocolError("tên tệp không hợp lệ (chỉ tên tệp, không đường dẫn)", ref=ref)
    if t == FILE_DONE:
        b64d(msg["sha256"], config.SHA256_BYTES, "sha256")
    return msg


# ------------------------------------------------------------------ builders (server -> client)
def error(code: str, detail: str = "", ref: str | None = None) -> dict:
    m = {"type": ERROR, "code": code, "detail": detail}
    if ref is not None:
        m["ref"] = ref
    return m


def auth_fail(action: str, code: str, detail: str = "") -> dict:
    return {"type": AUTH_FAIL, "action": action, "code": code, "detail": detail}


def user_list(users: list[str]) -> dict:
    return {"type": USER_LIST, "users": users, "ts": now_ms()}


# ------------------------------------------------------------------ framing TCP (4 byte)
async def read_message(reader: asyncio.StreamReader, max_size: int = config.TCP_FRAME_MAX) -> bytes:
    """Đọc một thông điệp có tiền tố độ dài 4B Big-Endian.

    Kiểm độ dài TRƯỚC khi đọc body: 0 hoặc quá max_size thì ném ProtocolError, không cấp bộ nhớ.
    EOF giữa chừng thì ném asyncio.IncompleteReadError.
    """
    header = await reader.readexactly(config.TCP_LEN_BYTES)
    (n,) = struct.unpack(">I", header)
    if n == 0 or n > max_size:
        raise ProtocolError(f"độ dài frame TCP không hợp lệ: {n}")
    return await reader.readexactly(n)


async def write_message(writer: asyncio.StreamWriter, data: bytes) -> None:
    if not 0 < len(data) <= config.TCP_FRAME_MAX:
        raise ProtocolError("thông điệp TCP rỗng hoặc quá lớn")
    writer.write(struct.pack(">I", len(data)) + data)
    await writer.drain()


# ------------------------------------------------------------------ framing stream (2 byte)
def frame(payload: bytes) -> bytes:
    if len(payload) > config.MAX_FRAME:
        raise ProtocolError("frame quá 65535 byte")
    return struct.pack(">H", len(payload)) + payload


class FrameReader:
    """Tách frame từ một stream byte. Chịu được cả transport trả từng mảnh lẫn trả nguyên frame."""

    def __init__(self, stream, initial: bytes = b""):
        self._stream = stream
        self._buf = bytearray(initial)

    async def read(self) -> bytes:
        while True:
            if len(self._buf) >= 2:
                (n,) = struct.unpack_from(">H", self._buf)
                if len(self._buf) >= 2 + n:
                    out = bytes(self._buf[2:2 + n])
                    del self._buf[:2 + n]
                    return out
            data = await self._stream.recv()
            if not data:
                raise ConnectionError("stream đã đóng")
            self._buf += data


async def send_json(stream, msg: dict) -> None:
    await stream.send(frame(encode(msg)))


# ------------------------------------------------------------------ FILE_CHUNK
_CHUNK_HDR = struct.Struct(">16sI")


def pack_chunk(transfer_id: bytes, offset: int, data: bytes) -> bytes:
    return _CHUNK_HDR.pack(transfer_id, offset) + data


def unpack_chunk(payload: bytes) -> tuple[bytes, int, bytes]:
    if len(payload) < _CHUNK_HDR.size:
        raise ProtocolError("FILE_CHUNK ngắn hơn 20 byte")
    tid, off = _CHUNK_HDR.unpack_from(payload)
    data = payload[_CHUNK_HDR.size:]
    if not 0 < len(data) <= config.CHUNK_SIZE:
        raise ProtocolError("FILE_CHUNK rỗng hoặc vượt CHUNK_SIZE")
    return tid, off, data
