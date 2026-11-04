"""
shared/crypto.py
----------------
Module cung cấp toàn bộ tiện ích bảo mật và mật mã học cho hệ thống CO3093:
  1. Băm và kiểm tra mật khẩu người dùng: PBKDF2-HMAC-SHA256 (100,000 vòng lặp).
  2. Trao đổi khóa bảo mật trên đường truyền: X25519 ECDH (Elliptic Curve Diffie-Hellman).
  3. Dẫn xuất khóa phiên an toàn: HKDF-SHA256 (phái sinh 4 khóa AES-256 32B riêng biệt).
  4. Mã hóa dòng xác thực: AES-256-GCM với Nonce 12B và AAD (Additional Authenticated Data).
"""

import hashlib
import hmac
import os
from typing import Dict, Tuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from shared.config import (
    AES_KEY_SIZE,
    AES_GCM_NONCE_SIZE,
    PBKDF2_ITERATIONS,
    PBKDF2_SALT_SIZE,
)

# ============================================================================
# CÁC NGOẠI LỆ MẬT MÃ ĐẶC THÙ
# ============================================================================
class CryptoError(Exception):
    """Ngoại lệ cơ sở cho các lỗi mật mã."""
    pass

class CryptoDecryptionError(CryptoError):
    """Giải mã thất bại do sai chìa khóa, sai Nonce, hoặc dữ liệu bị sửa đổi (InvalidTag)."""
    pass

class CryptoKeyExchangeError(CryptoError):
    """Lỗi trong quá trình thỏa thuận khóa bí mật X25519."""
    pass


# ============================================================================
# 1. BĂM VÀ XÁC THỰC MẬT KHẨU (PBKDF2-HMAC-SHA256)
# ============================================================================
def hash_password(password: str, salt: bytes = None) -> Tuple[str, str]:
    """
    Băm mật khẩu người dùng bằng PBKDF2-HMAC-SHA256 với 100,000 vòng lặp.
    
    Args:
        password: Chuỗi mật khẩu dạng văn bản gốc (plaintext).
        salt: Chuỗi muối 16 bytes ngẫu nhiên (nếu None sẽ tự sinh ngẫu nhiên).
        
    Returns:
        Tuple (salt_hex, hash_hex) để lưu trữ an toàn trong users.json.
    """
    if salt is None:
        salt = os.urandom(PBKDF2_SALT_SIZE)
        
    derived_key = hashlib.pbkdf2_hmac(
        hash_name="sha256",
        password=password.encode("utf-8"),
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
        dklen=32  # 256 bits
    )
    return salt.hex(), derived_key.hex()


def verify_password(password: str, salt_hex: str, expected_hash_hex: str) -> bool:
    """
    Xác thực mật khẩu người dùng nhập vào so với mã băm đã lưu trữ.
    Sử dụng hmac.compare_digest để ngăn chặn tấn công Timing Attack.
    """
    try:
        salt = bytes.fromhex(salt_hex)
        _, computed_hash_hex = hash_password(password, salt=salt)
        return hmac.compare_digest(computed_hash_hex, expected_hash_hex)
    except Exception:
        return False


# ============================================================================
# 2. TRAO ĐỔI KHÓA BẢO MẬT (X25519 ECDH)
# ============================================================================
def generate_x25519_keypair() -> Tuple[x25519.X25519PrivateKey, bytes]:
    """
    Sinh cặp khóa X25519 tạm thời (ephemeral) cho phiên bắt tay.
    
    Returns:
        Tuple (private_key, raw_public_key_32_bytes)
    """
    private_key = x25519.X25519PrivateKey.generate()
    public_key_bytes = private_key.public_key().public_bytes(
        encoding=Encoding.Raw,
        format=PublicFormat.Raw
    )
    return private_key, public_key_bytes


def derive_shared_secret(
    private_key: x25519.X25519PrivateKey,
    peer_public_key_bytes: bytes
) -> bytes:
    """
    Tính toán bí mật chung (32 bytes) từ khóa riêng của bản thân và khóa công khai của đối tác.
    """
    if len(peer_public_key_bytes) != 32:
        raise CryptoKeyExchangeError(
            f"Khóa công khai X25519 phải có độ dài đúng 32 bytes, nhận được: {len(peer_public_key_bytes)}B"
        )
    try:
        peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_public_key_bytes)
        shared_key = private_key.exchange(peer_public_key)
        return shared_key
    except Exception as e:
        raise CryptoKeyExchangeError(f"Lỗi trao đổi khóa X25519: {e}") from e


# ============================================================================
# 3. DẪN XUẤT KHÓA PHIÊN (HKDF-SHA256)
# ============================================================================
# Định nghĩa các nhãn ngữ cảnh để phái sinh 4 chìa khóa hoàn toàn tách biệt:
INFO_TCP_C2S = b"co3093-tcp-client-to-server-key"
INFO_TCP_S2C = b"co3093-tcp-server-to-client-key"
INFO_UDP_C2S = b"co3093-udp-client-to-server-key"
INFO_UDP_S2C = b"co3093-udp-server-to-client-key"

def derive_session_keys(shared_secret: bytes, salt: bytes = None) -> Dict[str, bytes]:
    """
    Dẫn xuất 4 chìa khóa AES-256 (32 bytes mỗi khóa) từ bí mật chung bằng HKDF-SHA256:
      - tcp_c2s: Mã hóa dữ liệu Client gửi lên Server qua kênh TCP
      - tcp_s2c: Mã hóa dữ liệu Server gửi về Client qua kênh TCP
      - udp_c2s: Mã hóa dữ liệu Client gửi lên Server qua kênh UDP
      - udp_s2c: Mã hóa dữ liệu Server gửi về Client qua kênh UDP
    """
    def _expand(info: bytes) -> bytes:
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=AES_KEY_SIZE,  # 32 bytes
            salt=salt,
            info=info
        )
        return hkdf.derive(shared_secret)

    return {
        "tcp_c2s": _expand(INFO_TCP_C2S),
        "tcp_s2c": _expand(INFO_TCP_S2C),
        "udp_c2s": _expand(INFO_UDP_C2S),
        "udp_s2c": _expand(INFO_UDP_S2C),
    }


# ============================================================================
# 4. MÃ HÓA & GIẢI MÃ XÁC THỰC (AES-256-GCM)
# ============================================================================
def aes_gcm_encrypt(
    key: bytes,
    nonce: bytes,
    plaintext: bytes,
    aad: bytes = b""
) -> bytes:
    """
    Mã hóa dữ liệu bằng AES-256-GCM.
    
    Args:
        key: Khóa 32 bytes (256-bit).
        nonce: Nonce 12 bytes chuẩn NIST.
        plaintext: Dữ liệu cần mã hóa.
        aad: Dữ liệu xác thực bổ sung (Header 31 bytes với Checksum=0).
        
    Returns:
        Ciphertext kèm 16 bytes Authentication Tag ở đuôi (theo chuẩn của cryptography AESGCM).
    """
    if len(key) != AES_KEY_SIZE:
        raise ValueError(f"Khóa AES phải có kích thước đúng {AES_KEY_SIZE} bytes.")
    if len(nonce) != AES_GCM_NONCE_SIZE:
        raise ValueError(f"Nonce AES-GCM phải có kích thước đúng {AES_GCM_NONCE_SIZE} bytes.")

    aesgcm = AESGCM(key)
    return aesgcm.encrypt(nonce, plaintext, aad)


def aes_gcm_decrypt(
    key: bytes,
    nonce: bytes,
    ciphertext_with_tag: bytes,
    aad: bytes = b""
) -> bytes:
    """
    Giải mã và xác thực dữ liệu bằng AES-256-GCM.
    
    Nếu ciphertext, khóa, nonce hoặc AAD bị thay đổi dù chỉ 1 bit,
    hàm sẽ ném ngoại lệ CryptoDecryptionError.
    """
    if len(key) != AES_KEY_SIZE:
        raise ValueError(f"Khóa AES phải có kích thước đúng {AES_KEY_SIZE} bytes.")
    if len(nonce) != AES_GCM_NONCE_SIZE:
        raise ValueError(f"Nonce AES-GCM phải có kích thước đúng {AES_GCM_NONCE_SIZE} bytes.")

    try:
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext_with_tag, aad)
    except InvalidTag as e:
        raise CryptoDecryptionError(
            "Xác thực thất bại (InvalidTag): Dữ liệu mã hóa hoặc Header AAD đã bị sửa đổi, "
            "hoặc sai chìa khóa/Nonce."
        ) from e
