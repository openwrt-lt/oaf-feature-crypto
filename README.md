# oaf-feature-crypto

`feature.bin`（FWXB）加解密，与 `fwx_feature.c` 行为一致。

## 格式

| 偏移 | 长度 | 说明 |
|------|------|------|
| 0 | 4 | `FWXB` |
| 4 | 1 | 版本 `1` |
| 5 | 1 | 算法 `1`（XTEA-CTR） |
| 6 | 2 | 头长 `24`（LE） |
| 8 | 4 | 明文长度（LE） |
| 12 | 4 | 明文 CRC32（IEEE） |
| 16 | 8 | nonce（LE，64 位） |
| 24 | N | 密文，N = 明文长度 |

Python ≥ 3.10，无第三方依赖。

## CLI

```bash
python -m oaf_feature_crypto decrypt feature.bin -o feature.cfg
python -m oaf_feature_crypto encrypt feature.cfg -o feature.bin
python -m oaf_feature_crypto info feature.bin
python -m oaf_feature_crypto verify feature.bin --plain feature.cfg
```

`encrypt` 可选 `--nonce 0x...`（默认随机）。

## API

```python
from oaf_feature_crypto import decrypt_blob, encrypt_plaintext

plain = decrypt_blob(data)
blob = encrypt_plaintext(plain)
```
