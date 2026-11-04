"""B2 + B6 - Trao đổi khóa X25519, HKDF tách 4 khóa, kênh TCP mã hóa, chữ ký Ed25519 bắt buộc.

Vì sao 4 khóa: mỗi (kênh, chiều) một khóa riêng -> bộ đếm nonce của kênh này
không bao giờ đụng nonce của kênh kia, kể cả khi cả hai bắt đầu từ 0.
"""
from __future__ import annotations

import hashlib
import os
import struct
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from shared import config, messages

KEY_LABELS = ("tcp_c2s", "tcp_s2c", "udp_c2s", "udp_s2c")
X25519_PUB_BYTES = config.X25519_PUB_BYTES

__all__ = ["InvalidTag", "SessionKeys", "derive_session_keys", "new_x25519", "x25519_pub_bytes",
           "nonce_from_counter", "TcpSecureChannel", "load_or_create_identity", "identity_pub_bytes",
           "kx_transcript", "sign_kx", "verify_kx", "pinned_identity_from_config"]


@dataclass(frozen=True)
class SessionKeys:
    tcp_c2s: bytes
    tcp_s2c: bytes
    udp_c2s: bytes
    udp_s2c: bytes


def new_x25519() -> X25519PrivateKey:
    return X25519PrivateKey.generate()


def x25519_pub_bytes(priv: X25519PrivateKey) -> bytes:
    return priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def derive_session_keys(my_priv: X25519PrivateKey, peer_pub: bytes,
                        client_pub: bytes, server_pub: bytes) -> SessionKeys:
    """Hai bên gọi với cùng (client_pub, server_pub) sẽ ra cùng 4 khóa.

    salt = SHA-256(client_pub || server_pub): gắn khóa vào đúng cặp khóa công khai của phiên này.
    ValueError nếu peer_pub là điểm bậc thấp (shared secret toàn 0) - thư viện tự chặn.
    """
    if len(peer_pub) != X25519_PUB_BYTES:
        raise ValueError("khóa công khai X25519 phải 32 byte")
    shared = my_priv.exchange(X25519PublicKey.from_public_bytes(peer_pub))
    salt = hashlib.sha256(client_pub + server_pub).digest()
    keys = {}
    for label in KEY_LABELS:
        keys[label] = HKDF(algorithm=hashes.SHA256(), length=config.AES_KEY_BYTES,
                           salt=salt, info=label.encode()).derive(shared)
    return SessionKeys(**keys)


def nonce_from_counter(counter: int) -> bytes:
    """Nonce 12 byte = counter (4B Big-Endian) + 8 byte 0. Dùng cho cả PktNum (UDP) và bộ đếm TCP."""
    if not 0 <= counter < 2**32:
        raise OverflowError("bộ đếm nonce tràn 32-bit: phải đóng kết nối và đăng nhập lại")
    return struct.pack(">I", counter) + b"\x00" * 8


class TcpSecureChannel:
    """Kênh TCP sau KEY_EXCHANGE: mỗi thông điệp = 4B độ dài + AES-GCM(JSON) (protocol_messages.md §3.3).

    Nonce = bộ đếm theo từng chiều, không gửi lên dây vì TCP đảm bảo thứ tự. AAD rỗng.
    Lệch bộ đếm (thông điệp bị phát lại, bị xóa, bị chèn) => giải mã thất bại => đóng kết nối.
    """

    def __init__(self, reader, writer, send_key: bytes, recv_key: bytes):
        self._r, self._w = reader, writer
        self._send = AESGCM(send_key)
        self._recv = AESGCM(recv_key)
        self._send_ctr = 0
        self._recv_ctr = 0

    async def send(self, msg: dict) -> None:
        ct = self._send.encrypt(nonce_from_counter(self._send_ctr), messages.encode(msg), b"")
        self._send_ctr += 1
        await messages.write_message(self._w, ct)

    async def recv(self) -> dict:
        ct = await messages.read_message(self._r)
        pt = self._recv.decrypt(nonce_from_counter(self._recv_ctr), ct, b"")   # InvalidTag nếu sai
        self._recv_ctr += 1
        return messages.decode(pt)


# ------------------------------------------------------------------ Ed25519: danh tính server (bắt buộc)
def load_or_create_identity(path: str = config.SERVER_IDENTITY_FILE,
                            pub_path: str | None = config.SERVER_IDENTITY_PUB_FILE) -> Ed25519PrivateKey:
    """Đọc khóa danh tính dài hạn của server; lần đầu chạy thì tạo và lưu (quyền 600).

    Đồng thời ghi bản công khai dạng hex ra pub_path để client chạy cùng máy đọc được.
    """
    if os.path.exists(path):
        with open(path, "rb") as f:
            key = Ed25519PrivateKey.from_private_bytes(f.read())
    else:
        key = Ed25519PrivateKey.generate()
        raw = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                serialization.NoEncryption())
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(raw)
    if pub_path:
        with open(pub_path, "w", encoding="ascii") as f:
            f.write(identity_pub_bytes(key).hex() + "\n")
    return key


def identity_pub_bytes(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def kx_transcript(client_pub: bytes, server_pub: bytes, identity_pub: bytes) -> bytes:
    """Chuỗi được ký khi trao khóa (protocol_messages.md §3.2).

    Có khóa client => chữ ký chỉ đúng cho đúng một lần kết nối (phát lại vô dụng).
    Có khóa danh tính và nhãn giao thức => không dùng lẫn sang server hay giao thức khác.
    """
    return config.KX_LABEL + client_pub + server_pub + identity_pub


def sign_kx(identity: Ed25519PrivateKey, client_pub: bytes, server_pub: bytes) -> bytes:
    return identity.sign(kx_transcript(client_pub, server_pub, identity_pub_bytes(identity)))


def verify_kx(pinned_identity_pub: bytes, sig: bytes, client_pub: bytes, server_pub: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(pinned_identity_pub).verify(
            sig, kx_transcript(client_pub, server_pub, pinned_identity_pub))
        return True
    except (InvalidSignature, ValueError):
        return False


def pinned_identity_from_config() -> bytes:
    """Khóa danh tính server mà client ghim: config.SERVER_IDENTITY_PUB, hoặc file server ghi ra (cùng máy)."""
    hex_pub = config.SERVER_IDENTITY_PUB.strip()
    if not hex_pub and os.path.exists(config.SERVER_IDENTITY_PUB_FILE):
        with open(config.SERVER_IDENTITY_PUB_FILE, encoding="ascii") as f:
            hex_pub = f.read().strip()
    if not hex_pub:
        raise RuntimeError("chưa ghim khóa danh tính server: điền config.SERVER_IDENTITY_PUB")
    pub = bytes.fromhex(hex_pub)
    if len(pub) != 32:
        raise RuntimeError("khóa danh tính server phải dài 32 byte (64 ký tự hex)")
    return pub
