"""Process-focused AES-128 (Rijndael) helpers for teaching.

This module is intentionally explicit about AES round operations so students can
see the transformation flow used during encryption and decryption.
"""

import base64
from typing import Any


S_BOX = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

INV_S_BOX = (
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
)

RCON = (
    0x00,
    0x01,
    0x02,
    0x04,
    0x08,
    0x10,
    0x20,
    0x40,
    0x80,
    0x1B,
    0x36,
)


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("utf-8")


def b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("utf-8"))


def _bytes_to_matrix(block: bytes) -> list[list[int]]:
    return [list(block[i : i + 4]) for i in range(0, len(block), 4)]


def _matrix_to_bytes(matrix: list[list[int]]) -> bytes:
    return bytes(sum(matrix, []))


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b, strict=True))


def _xtime(value: int) -> int:
    return (((value << 1) ^ 0x1B) & 0xFF) if (value & 0x80) else (value << 1)


def _mix_single_column(column: list[int]) -> None:
    t = column[0] ^ column[1] ^ column[2] ^ column[3]
    u = column[0]
    column[0] ^= t ^ _xtime(column[0] ^ column[1])
    column[1] ^= t ^ _xtime(column[1] ^ column[2])
    column[2] ^= t ^ _xtime(column[2] ^ column[3])
    column[3] ^= t ^ _xtime(column[3] ^ u)


def _sub_bytes(state: list[list[int]]) -> None:
    for i in range(4):
        for j in range(4):
            state[i][j] = S_BOX[state[i][j]]


def _inv_sub_bytes(state: list[list[int]]) -> None:
    for i in range(4):
        for j in range(4):
            state[i][j] = INV_S_BOX[state[i][j]]


def _shift_rows(state: list[list[int]]) -> None:
    state[0][1], state[1][1], state[2][1], state[3][1] = state[1][1], state[2][1], state[3][1], state[0][1]
    state[0][2], state[1][2], state[2][2], state[3][2] = state[2][2], state[3][2], state[0][2], state[1][2]
    state[0][3], state[1][3], state[2][3], state[3][3] = state[3][3], state[0][3], state[1][3], state[2][3]


def _inv_shift_rows(state: list[list[int]]) -> None:
    state[0][1], state[1][1], state[2][1], state[3][1] = state[3][1], state[0][1], state[1][1], state[2][1]
    state[0][2], state[1][2], state[2][2], state[3][2] = state[2][2], state[3][2], state[0][2], state[1][2]
    state[0][3], state[1][3], state[2][3], state[3][3] = state[1][3], state[2][3], state[3][3], state[0][3]


def _mix_columns(state: list[list[int]]) -> None:
    for i in range(4):
        _mix_single_column(state[i])


def _inv_mix_columns(state: list[list[int]]) -> None:
    for i in range(4):
        u = _xtime(_xtime(state[i][0] ^ state[i][2]))
        v = _xtime(_xtime(state[i][1] ^ state[i][3]))
        state[i][0] ^= u
        state[i][1] ^= v
        state[i][2] ^= u
        state[i][3] ^= v
    _mix_columns(state)


def _add_round_key(state: list[list[int]], round_key: list[list[int]]) -> None:
    for i in range(4):
        for j in range(4):
            state[i][j] ^= round_key[i][j]


def _expand_key_128(key: bytes) -> list[list[list[int]]]:
    if len(key) != 16:
        raise ValueError("This teaching module supports AES-128 keys only (16 bytes)")

    columns = _bytes_to_matrix(key)
    iteration_size = 4
    round_constant_index = 1

    while len(columns) < 44:
        word = list(columns[-1])

        if len(columns) % iteration_size == 0:
            word.append(word.pop(0))
            word = [S_BOX[value] for value in word]
            word[0] ^= RCON[round_constant_index]
            round_constant_index += 1

        word = [a ^ b for a, b in zip(word, columns[-iteration_size], strict=True)]
        columns.append(word)

    return [columns[4 * i : 4 * (i + 1)] for i in range(11)]


def _state_hex(state: list[list[int]]) -> str:
    return _matrix_to_bytes(state).hex()


def _encrypt_block_internal(block: bytes, key: bytes, include_trace: bool) -> tuple[bytes, list[dict[str, Any]]]:
    if len(block) != 16:
        raise ValueError("AES operates on 16-byte blocks")

    round_keys = _expand_key_128(key)
    state = _bytes_to_matrix(block)
    trace: list[dict[str, Any]] = []

    def maybe_trace(round_number: int, step: str) -> None:
        if include_trace:
            trace.append({"round": round_number, "step": step, "state_hex": _state_hex(state)})

    maybe_trace(0, "initial_state")
    _add_round_key(state, round_keys[0])
    maybe_trace(0, "add_round_key")

    for round_number in range(1, 10):
        _sub_bytes(state)
        maybe_trace(round_number, "sub_bytes")
        _shift_rows(state)
        maybe_trace(round_number, "shift_rows")
        _mix_columns(state)
        maybe_trace(round_number, "mix_columns")
        _add_round_key(state, round_keys[round_number])
        maybe_trace(round_number, "add_round_key")

    _sub_bytes(state)
    maybe_trace(10, "sub_bytes")
    _shift_rows(state)
    maybe_trace(10, "shift_rows")
    _add_round_key(state, round_keys[10])
    maybe_trace(10, "add_round_key")

    return _matrix_to_bytes(state), trace


def _decrypt_block_internal(block: bytes, key: bytes, include_trace: bool) -> tuple[bytes, list[dict[str, Any]]]:
    if len(block) != 16:
        raise ValueError("AES operates on 16-byte blocks")

    round_keys = _expand_key_128(key)
    state = _bytes_to_matrix(block)
    trace: list[dict[str, Any]] = []

    def maybe_trace(round_number: int, step: str) -> None:
        if include_trace:
            trace.append({"round": round_number, "step": step, "state_hex": _state_hex(state)})

    maybe_trace(10, "initial_state")
    _add_round_key(state, round_keys[10])
    maybe_trace(10, "add_round_key")
    _inv_shift_rows(state)
    maybe_trace(10, "inv_shift_rows")
    _inv_sub_bytes(state)
    maybe_trace(10, "inv_sub_bytes")

    for round_number in range(9, 0, -1):
        _add_round_key(state, round_keys[round_number])
        maybe_trace(round_number, "add_round_key")
        _inv_mix_columns(state)
        maybe_trace(round_number, "inv_mix_columns")
        _inv_shift_rows(state)
        maybe_trace(round_number, "inv_shift_rows")
        _inv_sub_bytes(state)
        maybe_trace(round_number, "inv_sub_bytes")

    _add_round_key(state, round_keys[0])
    maybe_trace(0, "add_round_key")

    return _matrix_to_bytes(state), trace


def encrypt_block(block: bytes, key: bytes) -> bytes:
    ciphertext, _ = _encrypt_block_internal(block, key, include_trace=False)
    return ciphertext


def decrypt_block(block: bytes, key: bytes) -> bytes:
    plaintext, _ = _decrypt_block_internal(block, key, include_trace=False)
    return plaintext


def encrypt_block_with_trace(block: bytes, key: bytes) -> dict[str, Any]:
    ciphertext, trace = _encrypt_block_internal(block, key, include_trace=True)
    return {"ciphertext_hex": ciphertext.hex(), "trace": trace}


def decrypt_block_with_trace(block: bytes, key: bytes) -> dict[str, Any]:
    plaintext, trace = _decrypt_block_internal(block, key, include_trace=True)
    return {"plaintext_hex": plaintext.hex(), "trace": trace}


def _pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def _pkcs7_unpad(data: bytes, block_size: int = 16) -> bytes:
    if not data or len(data) % block_size != 0:
        raise ValueError("Invalid padded data length")
    pad_len = data[-1]
    if pad_len == 0 or pad_len > block_size:
        raise ValueError("Invalid PKCS#7 padding")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Invalid PKCS#7 padding")
    return data[:-pad_len]


def aes_cbc_encrypt_process(plaintext: str, key: bytes, iv: bytes, include_trace: bool = False) -> dict[str, Any]:
    if len(key) != 16:
        raise ValueError("This teaching module supports AES-128 keys only (16 bytes)")
    if len(iv) != 16:
        raise ValueError("CBC requires a 16-byte IV")

    data = _pkcs7_pad(plaintext.encode("utf-8"), 16)
    prev = iv
    encrypted_blocks: list[bytes] = []
    block_trace: list[dict[str, Any]] = []

    for idx in range(0, len(data), 16):
        block = data[idx : idx + 16]
        xored = _xor_bytes(block, prev)
        ciphertext_block, round_trace = _encrypt_block_internal(xored, key, include_trace)
        encrypted_blocks.append(ciphertext_block)
        prev = ciphertext_block

        if include_trace:
            block_trace.append(
                {
                    "block_index": idx // 16,
                    "plaintext_block_hex": block.hex(),
                    "after_xor_hex": xored.hex(),
                    "ciphertext_block_hex": ciphertext_block.hex(),
                    "round_trace": round_trace,
                }
            )

    packet: dict[str, Any] = {
        "algorithm": "AES-128 (Rijndael)",
        "mode": "CBC",
        "iv": b64e(iv),
        "ciphertext": b64e(b"".join(encrypted_blocks)),
        "tag": None,
        "aad": None,
    }

    if include_trace:
        packet["trace"] = block_trace

    return packet


def aes_cbc_decrypt_process(packet: dict[str, Any], key: bytes, include_trace: bool = False) -> dict[str, Any]:
    if len(key) != 16:
        raise ValueError("This teaching module supports AES-128 keys only (16 bytes)")
    if packet.get("mode") != "CBC":
        raise ValueError("This teaching module only supports CBC packets")

    iv = b64d(packet["iv"])
    ciphertext = b64d(packet["ciphertext"])

    if len(iv) != 16:
        raise ValueError("CBC requires a 16-byte IV")
    if len(ciphertext) == 0 or len(ciphertext) % 16 != 0:
        raise ValueError("Ciphertext length must be a positive multiple of 16 bytes")

    prev = iv
    decrypted_blocks: list[bytes] = []
    block_trace: list[dict[str, Any]] = []

    for idx in range(0, len(ciphertext), 16):
        cblock = ciphertext[idx : idx + 16]
        decrypted_block, round_trace = _decrypt_block_internal(cblock, key, include_trace)
        plaintext_block = _xor_bytes(decrypted_block, prev)
        decrypted_blocks.append(plaintext_block)
        prev = cblock

        if include_trace:
            block_trace.append(
                {
                    "block_index": idx // 16,
                    "ciphertext_block_hex": cblock.hex(),
                    "after_block_decrypt_hex": decrypted_block.hex(),
                    "plaintext_block_hex": plaintext_block.hex(),
                    "round_trace": round_trace,
                }
            )

    unpadded = _pkcs7_unpad(b"".join(decrypted_blocks), 16)
    result: dict[str, Any] = {"plaintext": unpadded.decode("utf-8")}

    if include_trace:
        result["trace"] = block_trace

    return result
