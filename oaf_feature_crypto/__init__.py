"""FWXB feature.bin 加解密。"""

from oaf_feature_crypto.crypto import (
    ALGORITHM_XTEA_CTR,
    FORMAT_VERSION,
    HEADER_SIZE,
    MAGIC,
    MAX_PLAIN_SIZE,
    build_header,
    decrypt_blob,
    decrypt_file,
    encrypt_file,
    encrypt_plaintext,
    feature_crc32,
    parse_header,
    xtea_ctr_crypt,
)

__all__ = [
    "ALGORITHM_XTEA_CTR",
    "FORMAT_VERSION",
    "HEADER_SIZE",
    "MAGIC",
    "MAX_PLAIN_SIZE",
    "build_header",
    "decrypt_blob",
    "decrypt_file",
    "encrypt_file",
    "encrypt_plaintext",
    "feature_crc32",
    "parse_header",
    "xtea_ctr_crypt",
]
