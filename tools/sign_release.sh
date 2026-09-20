#!/bin/sh
# =============================================================================
# tools/sign_release.sh — build 签名（文件版，CERT_MANAGEMENT.md §4）
# 对制品文件的 sha256 签名 → <sign_dir>/<basename>.sig（与商店验签同一"签名覆盖 sha256"口径）。
# 用法：sh tools/sign_release.sh <artifact_file> [sign_dir=deploy/certs]
# =============================================================================
set -eu
FILE="$1"; DIR="${2:-deploy/certs}"
DIG=$(openssl dgst -sha256 -r "$FILE" | cut -d' ' -f1)
sh tools/sign_artifact.sh "$DIG" "$DIR/signer.key" "$DIR/$(basename "$FILE").sig"
