#!/bin/sh
# =============================================================================
# tools/verify_artifact.sh — 商店检查 / 下载运行验证（CERT_MANAGEMENT.md §5/§6）
# 对制品摘要验：①签发者证书链+有效期（根 CA 验签发者证书）②签名（证书公钥验 .sig）。
# 二者全过退出 0；任一失败非 0（chain=2 / signature=3 / 用法=64）。机器自动执行。
# 用法：sh tools/verify_artifact.sh <sha256hex> <sig> <signer.crt> <ca.crt>
# =============================================================================
set -eu
[ "$#" -eq 4 ] || { echo "usage: verify_artifact.sh <sha256> <sig> <signer.crt> <ca.crt>" >&2; exit 64; }
DIGEST="$1"; SIG="$2"; CERT="$3"; CA="$4"

# ① 证书链 + 有效期
openssl verify -CAfile "$CA" "$CERT" >/dev/null 2>&1 || { echo "chain/validity FAIL" >&2; exit 2; }

# ② 签名（证书公钥验摘要签名）
# 临时公钥落在签名同目录（跨环境可解析；避免 /tmp 在部分原生 openssl 下不可读）
PUB="${SIG}.pub.$$"; trap 'rm -f "$PUB"' EXIT
openssl x509 -pubkey -noout -in "$CERT" > "$PUB" 2>/dev/null
printf '%s' "$DIGEST" | openssl dgst -sha256 -verify "$PUB" -signature "$SIG" >/dev/null 2>&1 \
  || { echo "signature FAIL" >&2; exit 3; }

echo "OK"
