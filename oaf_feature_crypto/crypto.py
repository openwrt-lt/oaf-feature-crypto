"""FWXB：24 字节头 + XTEA-CTR 密文。"""

from __future__ import annotations

import secrets
import struct
from typing import Optional

MAGIC = b"FWXB"
FORMAT_VERSION = 1
ALGORITHM_XTEA_CTR = 1
HEADER_SIZE = 24
MAX_PLAIN_SIZE = 20 * 1024 * 1024

FEATURE_KEY = (0x8F4C29A1, 0x73B6D502, 0xC14E87F3, 0x2AD95B60)


def _u32(x: int) -> int:
    return x & 0xFFFFFFFF


def feature_crc32(data: bytes) -> int:
    crc = 0xFFFFFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ (0xEDB88320 & -(crc & 1))
    return (~crc) & 0xFFFFFFFF


def xtea_encrypt_block(v0: int, v1: int) -> tuple[int, int]:
    sum_ = 0
    delta = 0x9E3779B9
    for _ in range(32):
        v0 = _u32(
            v0
            + (
                _u32((_u32(v1 << 4) ^ _u32(v1 >> 5)) + v1)
                ^ _u32(sum_ + FEATURE_KEY[sum_ & 3])
            )
        )
        sum_ = _u32(sum_ + delta)
        v1 = _u32(
            v1
            + (
                _u32((_u32(v0 << 4) ^ _u32(v0 >> 5)) + v0)
                ^ _u32(sum_ + FEATURE_KEY[(sum_ >> 11) & 3])
            )
        )
    return v0, v1


def xtea_ctr_crypt(data: bytearray, nonce: int) -> None:
    offset = 0
    counter = nonce & 0xFFFFFFFFFFFFFFFF
    while offset < len(data):
        v0 = _u32(counter)
        v1 = _u32(counter >> 32)
        v0, v1 = xtea_encrypt_block(v0, v1)
        stream = struct.pack("<II", v0, v1)
        for b in stream:
            if offset >= len(data):
                break
            data[offset] ^= b
            offset += 1
        counter = (counter + 1) & 0xFFFFFFFFFFFFFFFF


def build_header(plain_len: int, crc: int, nonce: int) -> bytes:
    hdr = bytearray(HEADER_SIZE)
    hdr[0:4] = MAGIC
    hdr[4] = FORMAT_VERSION
    hdr[5] = ALGORITHM_XTEA_CTR
    struct.pack_into("<H", hdr, 6, HEADER_SIZE)
    struct.pack_into("<I", hdr, 8, plain_len)
    struct.pack_into("<I", hdr, 12, crc)
    struct.pack_into("<Q", hdr, 16, nonce)
    return bytes(hdr)


def parse_header(blob: bytes) -> tuple[int, int, int]:
    if len(blob) < HEADER_SIZE:
        raise ValueError("文件过短")
    if blob[:4] != MAGIC:
        raise ValueError("魔数不是 FWXB")
    if blob[4] != FORMAT_VERSION:
        raise ValueError(f"不支持的格式版本: {blob[4]}")
    if blob[5] != ALGORITHM_XTEA_CTR:
        raise ValueError(f"不支持的算法: {blob[5]}")
    if struct.unpack_from("<H", blob, 6)[0] != HEADER_SIZE:
        raise ValueError("头长度不是 24")
    plain_len = struct.unpack_from("<I", blob, 8)[0]
    crc = struct.unpack_from("<I", blob, 12)[0]
    nonce = struct.unpack_from("<Q", blob, 16)[0]
    if plain_len == 0 or plain_len > MAX_PLAIN_SIZE:
        raise ValueError(f"明文长度非法: {plain_len}")
    return plain_len, crc, nonce


def encrypt_plaintext(plain: bytes, nonce: Optional[int] = None) -> bytes:
    if not plain:
        raise ValueError("明文为空")
    if len(plain) > MAX_PLAIN_SIZE:
        raise ValueError("明文超过 20MB 上限")
    if nonce is None:
        nonce = secrets.randbits(64)
    crc = feature_crc32(plain)
    body = bytearray(plain)
    xtea_ctr_crypt(body, nonce)
    return build_header(len(plain), crc, nonce) + bytes(body)


def decrypt_blob(blob: bytes) -> bytes:
    plain_len, expected_crc, nonce = parse_header(blob)
    if len(blob) != HEADER_SIZE + plain_len:
        raise ValueError(
            f"文件大小不符: 期望 {HEADER_SIZE + plain_len} 实际 {len(blob)}"
        )
    plain = bytearray(blob[HEADER_SIZE : HEADER_SIZE + plain_len])
    xtea_ctr_crypt(plain, nonce)
    if feature_crc32(bytes(plain)) != expected_crc:
        raise ValueError("CRC32 校验失败")
    return bytes(plain)


def encrypt_file(
    in_path: str, out_path: str, nonce: Optional[int] = None
) -> None:
    with open(in_path, "rb") as f:
        plain = f.read()
    out = encrypt_plaintext(plain, nonce)
    with open(out_path, "wb") as f:
        f.write(out)


def decrypt_file(in_path: str, out_path: str) -> None:
    with open(in_path, "rb") as f:
        blob = f.read()
    plain = decrypt_blob(blob)
    with open(out_path, "wb") as f:
        f.write(plain)
