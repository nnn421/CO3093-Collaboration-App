"""
shared/framing.py
-----------------
Cung cấp cơ chế đóng khung thông điệp (Length-prefix framing) qua luồng TCP
và chuẩn hóa dữ liệu JSON trao đổi giữa Client và Server (G2).

Định dạng luồng TCP:
  [4 bytes: Big-Endian Length (I)][Body (JSON Plaintext hoặc AES-GCM Ciphertext)]

Nếu có mã hóa bằng khóa AES-256:
  Body = [12 bytes: Nonce ngẫu nhiên][Ciphertext + 16 bytes GCM Tag]
"""

import asyncio
import json
import os
import struct
from typing import Any, Dict, Optional

from shared.config import AES_GCM_NONCE_SIZE, AES_KEY_SIZE
from shared.crypto import aes_gcm_decrypt, aes_gcm_encrypt


class FramingError(Exception):
    """Ngoại lệ khi đóng khung hoặc giải khung dữ liệu TCP thất bại."""
    pass


async def send_framed_msg(
    writer: asyncio.StreamWriter,
    data: Dict[str, Any],
    key: Optional[bytes] = None
) -> None:
    """
    Đóng gói thông điệp JSON và gửi qua luồng TCP.
    
    Args:
        writer: StreamWriter của kết nối TCP.
        data: Dict dữ liệu cần gửi.
        key: Khóa AES-256 (32 bytes) nếu muốn mã hóa; None nếu gửi plaintext (như bắt tay ban đầu).
    """
    json_bytes = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")

    if key is not None:
        if len(key) != AES_KEY_SIZE:
            raise ValueError(f"Khóa AES phải đúng {AES_KEY_SIZE} bytes.")
        nonce = os.urandom(AES_GCM_NONCE_SIZE)
        ciphertext = aes_gcm_encrypt(key, nonce, json_bytes)
        body = nonce + ciphertext
    else:
        body = json_bytes

    # Tiền tố độ dài 4 bytes Big-Endian
    header = struct.pack(">I", len(body))
    writer.write(header + body)
    await writer.drain()


async def recv_framed_msg(
    reader: asyncio.StreamReader,
    key: Optional[bytes] = None
) -> Dict[str, Any]:
    """
    Đọc một thông điệp hoàn chỉnh từ luồng TCP.
    
    Returns:
        Dict dữ liệu JSON đã giải mã.
    """
    # 1. Đọc đúng 4 bytes tiền tố độ dài
    try:
        header = await reader.readexactly(4)
    except asyncio.IncompleteReadError as e:
        raise FramingError("Kết nối TCP bị đóng đột ngột khi đang đọc header.") from e

    (length,) = struct.unpack(">I", header)
    if length > 10 * 1024 * 1024:  # Giới hạn an toàn 10MB cho thông điệp điều khiển
        raise FramingError(f"Kích thước thông điệp quá lớn: {length} bytes.")

    # 2. Đọc chính xác toàn bộ body
    try:
        body = await reader.readexactly(length)
    except asyncio.IncompleteReadError as e:
        raise FramingError(f"Dữ liệu body bị thiếu ({len(e.partial)}/{length}B).") from e

    # 3. Giải mã nếu có khóa bí mật
    if key is not None:
        if len(body) < AES_GCM_NONCE_SIZE + 16:
            raise FramingError("Dữ liệu mã hóa quá ngắn không chứa đủ Nonce và Tag.")
        nonce = body[:AES_GCM_NONCE_SIZE]
        ciphertext = body[AES_GCM_NONCE_SIZE:]
        plaintext_bytes = aes_gcm_decrypt(key, nonce, ciphertext)
    else:
        plaintext_bytes = body

    try:
        return json.loads(plaintext_bytes.decode("utf-8"))
    except Exception as e:
        raise FramingError(f"Lỗi giải mã cú pháp JSON: {e}") from e
