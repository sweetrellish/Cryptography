"""Reusable AES helpers for the MATH 447 starter project."""

import base64
import os
from typing import Any

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("utf-8")


def b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("utf-8"))


def random_key(size_bits: int) -> bytes:
    if size_bits not in (128, 192, 256):
        raise ValueError("Key size must be 128, 192, or 256 bits")
    return os.urandom(size_bits // 8)


def random_iv(mode_name: str) -> bytes:
    if mode_name == "CBC":
        return os.urandom(16)
    if mode_name == "GCM":
        return os.urandom(12)
    raise ValueError("Unsupported AES mode")


def key_length_valid(key: bytes) -> bool:
    return len(key) in (16, 24, 32)


def validate_iv_for_mode(iv: bytes, mode_name: str) -> None:
    if mode_name == "CBC" and len(iv) != 16:
        raise ValueError("CBC requires a 16-byte IV (32 hex chars)")
    if mode_name == "GCM" and len(iv) < 12:
        raise ValueError("GCM nonce should be at least 12 bytes (24 hex chars)")


def parse_hex_or_raise(label: str, value: str) -> bytes:
    text = value.strip()
    if not text:
        raise ValueError(f"{label} is required")
    try:
        return bytes.fromhex(text)
    except ValueError as exc:
        raise ValueError(f"{label} must be a valid hex string") from exc


def aes_encrypt(plaintext: str, key: bytes, iv: bytes, mode_name: str, aad: bytes) -> dict[str, Any]:
    backend = default_backend()

    if mode_name == "CBC":
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(128).padder()
        padded = padder.update(plaintext.encode("utf-8")) + padder.finalize()
        ciphertext = encryptor.update(padded) + encryptor.finalize()
        return {
            "mode": "CBC",
            "iv": b64e(iv),
            "ciphertext": b64e(ciphertext),
            "tag": None,
            "aad": None,
        }

    if mode_name == "GCM":
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=backend)
        encryptor = cipher.encryptor()
        if aad:
            encryptor.authenticate_additional_data(aad)
        ciphertext = encryptor.update(plaintext.encode("utf-8")) + encryptor.finalize()
        return {
            "mode": "GCM",
            "iv": b64e(iv),
            "ciphertext": b64e(ciphertext),
            "tag": b64e(encryptor.tag),
            "aad": b64e(aad) if aad else None,
        }

    raise ValueError("Unsupported mode in encryption request")


def aes_decrypt(packet: dict[str, Any], key: bytes) -> str:
    backend = default_backend()
    mode_name = packet.get("mode")
    iv = b64d(packet["iv"])
    ciphertext = b64d(packet["ciphertext"])

    if mode_name == "CBC":
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        return plaintext.decode("utf-8")

    if mode_name == "GCM":
        if not packet.get("tag"):
            raise ValueError("Missing GCM tag in packet")
        tag = b64d(packet["tag"])
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=backend)
        decryptor = cipher.decryptor()
        aad_b64 = packet.get("aad")
        if aad_b64:
            decryptor.authenticate_additional_data(b64d(aad_b64))
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext.decode("utf-8")

    raise ValueError("Unsupported mode in packet")


def _pkcs7_pad(data: bytes) -> bytes:
    padder = padding.PKCS7(128).padder()
    return padder.update(data) + padder.finalize()


def _encrypt_ecb(plaintext: bytes, key: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(_pkcs7_pad(plaintext)) + encryptor.finalize()


def _block_stats(ciphertext: bytes, block_size: int = 16) -> dict[str, int]:
    if block_size <= 0:
        raise ValueError("block_size must be positive")

    blocks = [ciphertext[i : i + block_size] for i in range(0, len(ciphertext), block_size)]
    total = len(blocks)
    unique = len(set(blocks))
    repeated = total - unique

    return {
        "total_blocks": total,
        "unique_blocks": unique,
        "repeated_blocks": repeated,
    }


def mode_pattern_report(sample_text: str, key: bytes, cbc_iv: bytes, gcm_iv: bytes) -> dict[str, Any]:
    """Return block repetition stats to compare ECB/CBC/GCM behavior.

    This is a teaching helper for visualizing pattern leakage across modes.
    """
    if not key_length_valid(key):
        raise ValueError("AES key must be 16, 24, or 32 bytes")

    validate_iv_for_mode(cbc_iv, "CBC")
    validate_iv_for_mode(gcm_iv, "GCM")

    plaintext = sample_text.encode("utf-8")

    ecb_ciphertext = _encrypt_ecb(plaintext, key)
    cbc_packet = aes_encrypt(sample_text, key, cbc_iv, "CBC", b"")
    gcm_packet = aes_encrypt(sample_text, key, gcm_iv, "GCM", b"")

    cbc_ciphertext = b64d(cbc_packet["ciphertext"])
    gcm_ciphertext = b64d(gcm_packet["ciphertext"])

    return {
        "sample_length": len(plaintext),
        "ecb": _block_stats(ecb_ciphertext),
        "cbc": _block_stats(cbc_ciphertext),
        "gcm": _block_stats(gcm_ciphertext),
    }
