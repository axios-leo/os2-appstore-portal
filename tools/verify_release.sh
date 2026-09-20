#!/bin/sh
# =============================================================================
# tools/verify_release.sh — 下载运行验证 · 部署边界门（CERT_MANAGEMENT.md §6）
# 拉起/分发制品前，在具 openssl 的部署编排/宿主侧复验制品文件签名（链+有效期+签名）；
# 任一不过退出非 0——阻断拉起。容器镜像保持零第三方运行时依赖（验签不入容器）。
# 用法：sh tools/verify_release.sh <artifact_file> [sign_dir=deploy/certs]
# =============================================================================
set -eu
FILE="$1"; DIR="${2:-deploy/certs}"
DIG=$(openssl dgst -sha256 -r "$FILE" | cut -d' ' -f1)
sh tools/verify_artifact.sh "$DIG" "$DIR/$(basename "$FILE").sig" "$DIR/signer.crt" "$DIR/ca.crt"
