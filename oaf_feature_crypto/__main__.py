#!/usr/bin/env python3
"""FWXB 加解密 CLI。"""

from __future__ import annotations

import argparse
import os
import sys

from oaf_feature_crypto.crypto import (
    HEADER_SIZE,
    decrypt_blob,
    decrypt_file,
    encrypt_file,
    parse_header,
)


def main() -> int:
    p = argparse.ArgumentParser(description="FWXB feature.bin 加解密")
    sub = p.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("decrypt", help="FWXB -> 明文 cfg")
    d.add_argument("input", help="feature.bin")
    d.add_argument("-o", "--output", required=True, help="输出明文文件")

    e = sub.add_parser("encrypt", help="明文 cfg -> FWXB")
    e.add_argument("input", help="明文特征文件")
    e.add_argument("-o", "--output", required=True, help="输出 feature.bin")
    e.add_argument(
        "--nonce",
        type=lambda s: int(s, 0),
        help="固定 64 位 nonce（十六进制 0x.. 或十进制），默认随机",
    )

    t = sub.add_parser("info", help="查看 FWXB 头信息")
    t.add_argument("input")

    v = sub.add_parser("verify", help="解密并校验，可选与参考明文逐字节对比")
    v.add_argument("input", help="feature.bin")
    v.add_argument("--plain", help="期望的明文文件")

    args = p.parse_args()

    try:
        if args.cmd == "decrypt":
            decrypt_file(args.input, args.output)
            print(f"已解密 -> {args.output}")
        elif args.cmd == "encrypt":
            encrypt_file(args.input, args.output, args.nonce)
            print(f"已加密 -> {args.output} ({os.path.getsize(args.output)} 字节)")
        elif args.cmd == "info":
            blob = open(args.input, "rb").read()
            pl, crc, nonce = parse_header(blob)
            print(f"文件: {args.input}")
            print(f"总大小: {len(blob)} = 头 {HEADER_SIZE} + 密文 {pl}")
            print(f"明文长度: {pl}")
            print(f"CRC32: {crc:08x}")
            print(f"nonce: {nonce:016x}")
        elif args.cmd == "verify":
            plain = decrypt_blob(open(args.input, "rb").read())
            print(f"解密 OK, 明文 {len(plain)} 字节, CRC 通过")
            if args.plain:
                ref = open(args.plain, "rb").read()
                if plain == ref:
                    print("与参考明文完全一致")
                else:
                    print(f"与参考明文不一致 (参考 {len(ref)} 字节)", file=sys.stderr)
                    return 1
        return 0
    except (ValueError, OSError) as exc:
        print(f"错误: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
