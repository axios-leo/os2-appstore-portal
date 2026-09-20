#!/bin/sh
# =============================================================================
# tools/sign_artifact.sh — build 签名（CERT_MANAGEMENT.md §4）
# 对制品摘要（sha256 十六进制串）用签发者私钥签名，产出二进制签名文件。
# 用法：sh tools/sign_artifact.sh <sha256hex> <signer.key> <out.sig>
# 机器自动执行：打包流水线的一步，无人工介入。后并入 os2-pack 清单（签名件=pack 产物）。
# =============================================================================
set -eu
DIGEST="$1"; KEY="$2"; OUT="$3"
printf '%s' "$DIGEST" | openssl dgst -sha256 -sign "$KEY" -out "$OUT"
echo "signed $DIGEST -> $OUT"
