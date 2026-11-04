"""B6 - Cipher AES-256-GCM cho tầng transport (thay NullCipher).

Hợp đồng với tầng A (thứ tự xử lý, xem plan B6):
  GỬI : header(Checksum=0) -> ct = cipher.encrypt(nonce(PktNum), payload, aad=header) -> CRC32(header+ct) -> ghi Checksum
  NHẬN: kiểm CRC -> đặt Checksum=0 -> pt = cipher.decrypt(nonce(PktNum), ct, aad=header)  (InvalidTag => bỏ gói)
Mọi gói sau handshake (DATA, ACK có SACK, Heartbeat, FIN) đều qua đây.

Một đối tượng AESGCMCipher gắn với MỘT đầu kết nối: encrypt dùng khóa chiều đi, decrypt dùng khóa chiều về.
"""
from __future__ import annotations

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from shared.crypto import SessionKeys, nonce_from_counter

try:  # interface do A định nghĩa ở G5; nếu chưa có thì dùng bản tối thiểu dưới đây
    from transport.fake import Cipher, NullCipher  # type: ignore
except ImportError:  # pragma: no cover
    class Cipher:
        overhead = 0

        def encrypt(self, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
            raise NotImplementedError

        def decrypt(self, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
            raise NotImplementedError

    class NullCipher(Cipher):
        def encrypt(self, nonce, plaintext, aad):
            return plaintext

        def decrypt(self, nonce, ciphertext, aad):
            return ciphertext


class AESGCMCipher(Cipher):
    overhead = 16   # thẻ GCM: tầng A cộng vào trường Length

    def __init__(self, send_key: bytes, recv_key: bytes):
        if len(send_key) != 32 or len(recv_key) != 32:
            raise ValueError("AES-256 cần khóa 32 byte")
        if send_key == recv_key:
            raise ValueError("hai chiều phải dùng hai khóa khác nhau")
        self._enc = AESGCM(send_key)
        self._dec = AESGCM(recv_key)

    @classmethod
    def for_server(cls, keys: SessionKeys) -> "AESGCMCipher":
        return cls(send_key=keys.udp_s2c, recv_key=keys.udp_c2s)

    @classmethod
    def for_client(cls, keys: SessionKeys) -> "AESGCMCipher":
        return cls(send_key=keys.udp_c2s, recv_key=keys.udp_s2c)

    def encrypt(self, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
        return self._enc.encrypt(nonce, plaintext, aad)

    def decrypt(self, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
        return self._dec.decrypt(nonce, ciphertext, aad)   # cryptography.exceptions.InvalidTag nếu sai

    @staticmethod
    def nonce(pkt_num: int) -> bytes:
        return nonce_from_counter(pkt_num)
