#!/bin/sh
# =============================================================================
# tools/gen_certs.sh — 生成演示 PKI（根 CA + 签发者证书）到 <outdir>
# 机器自动执行、可复现（CERT_MANAGEMENT.md §2 预置管理）。
# 铁律：私钥（*.key）永不入库——deploy/certs/*.key 已 gitignore。
# 用法：sh tools/gen_certs.sh [outdir=deploy/certs]
# 环境：需 openssl（Git Bash 3.x 实测；WSL 缺省无，故本目标不入 WSL CTest 门禁）。
# =============================================================================
set -eu
export MSYS_NO_PATHCONV=1  # Git Bash：阻止 -subj "/O=..." 被 MSYS 误转为路径（Linux 无害）
OUT="${1:-deploy/certs}"
CA_DAYS="${CA_DAYS:-3650}"
SIGNER_DAYS="${SIGNER_DAYS:-825}"
mkdir -p "$OUT"

# 根 CA（自签，信任锚）——须显式 CA:TRUE，否则 openssl verify 拒链
openssl req -x509 -newkey rsa:3072 -nodes -keyout "$OUT/ca.key" -out "$OUT/ca.crt" \
  -days "$CA_DAYS" -subj "/O=OS2/CN=OS2 Demo Root CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null

# 签发者证书（由根 CA 签发；构建侧持 signer.key）——叶子 CA:FALSE + 数字签名用途
EXT="$OUT/.signer.ext"
printf 'basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\n' > "$EXT"
openssl req -newkey rsa:2048 -nodes -keyout "$OUT/signer.key" -out "$OUT/signer.csr" \
  -subj "/O=OS2/CN=OS2 Artifact Signer" 2>/dev/null
openssl x509 -req -in "$OUT/signer.csr" -CA "$OUT/ca.crt" -CAkey "$OUT/ca.key" \
  -CAcreateserial -out "$OUT/signer.crt" -days "$SIGNER_DAYS" -extfile "$EXT" 2>/dev/null
rm -f "$OUT/signer.csr" "$OUT/ca.srl" "$EXT"

echo "certs generated in $OUT: ca.crt signer.crt (+ *.key, gitignored)"
