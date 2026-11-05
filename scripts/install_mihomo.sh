#!/usr/bin/env bash
# 安装 mihomo 内核(默认始终取最新发行版,带 SHA256 校验)并预热地理库缓存。
#
# 用法:bash scripts/install_mihomo.sh
# 环境变量:
#   MIHOMO_VERSION  指定版本标签(如 v1.19.33);留空或 latest 表示自动取最新版
#   MIHOMO_CACHE    内核缓存目录(默认 ~/.cache/mihomo)
#   MIHOMO_DIR      地理库工作目录(默认 ./.cache/geo)
#   GH_PROXY        可选 GitHub 镜像前缀(如 https://ghproxy.net)
# 输出(追加到 $GITHUB_ENV):
#   MIHOMO_BIN   内核可执行文件路径
#   MIHOMO_DIR   地理库工作目录(可被 actions/cache 缓存)
#   MIHOMO_GATE  1=可做 mihomo -t 门禁,0=地理库不可用,跳过门禁
set -uo pipefail

REQUESTED="${MIHOMO_VERSION:-latest}"
CACHE="${MIHOMO_CACHE:-$HOME/.cache/mihomo}"
GEO_DIR="${MIHOMO_DIR:-$PWD/.cache/geo}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

case "$(uname -m)" in
  x86_64 | amd64) ARCH=amd64 ;;
  aarch64 | arm64) ARCH=arm64 ;;
  *)
    echo "::error::不支持的架构: $(uname -m)(请手动安装 mihomo 并设置 MIHOMO_BIN)"
    exit 1
    ;;
esac

PY=""
for c in python3 python; do
  if command -v "$c" >/dev/null 2>&1; then PY="$c"; break; fi
done

# 读 release API:输出 "<tag> <asset名> <sha256或->"
read_release() {
  [ -n "$PY" ] || return 1
  "$PY" - "$ARCH" <<'PY'
import json
import sys
import urllib.request

arch = sys.argv[1]
try:
    req = urllib.request.Request(
        "https://api.github.com/repos/MetaCubeX/mihomo/releases/latest",
        headers={"User-Agent": "proxy-node-bot/1.0"},
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        d = json.load(r)
except Exception:
    sys.exit(1)
tag = d.get("tag_name") or ""
if not tag:
    sys.exit(1)
name = "mihomo-linux-%s-%s.gz" % (arch, tag)
digest = "-"
for a in d.get("assets") or []:
    if a.get("name") == name:
        digest = (a.get("digest") or "").replace("sha256:", "") or "-"
        break
print(tag, name, digest)
PY
}

VERSION=""
DIGEST="-"
if [ "$REQUESTED" = "latest" ] || [ -z "$REQUESTED" ]; then
  echo "[INFO] 查询 mihomo 最新版本..."
  if out="$(read_release 2>/dev/null)" && [ -n "$out" ]; then
    VERSION="$(printf '%s\n' "$out" | awk '{print $1}')"
    DIGEST="$(printf '%s\n' "$out" | awk '{print $3}')"
  fi
  if [ -z "$VERSION" ]; then
    # 网络/API 不可用时退回离线表里最后一条(scripts/mihomo.sha256 末行)
    VERSION="$(awk 'NF == 3 && $1 ~ /^v/ { v = $1 } END { print v }' "$ROOT/scripts/mihomo.sha256" 2>/dev/null)"
    [ -n "$VERSION" ] || VERSION="v1.19.33"
    echo "::warning::获取最新版本失败,回退到 $VERSION"
  fi
else
  VERSION="$REQUESTED"
fi
[ -n "${DIGEST:-}" ] || DIGEST="-"

ASSET="mihomo-linux-${ARCH}-${VERSION}.gz"
URL="https://github.com/MetaCubeX/mihomo/releases/download/${VERSION}/${ASSET}"
# 国内可用 GH_PROXY(如 https://ghproxy.net)加速下载;CI 上不设置,直连
if [ -n "${GH_PROXY:-}" ]; then
  URL="${GH_PROXY%/}/$URL"
  echo "[INFO] 使用 GH_PROXY 镜像: $URL"
fi
BIN="$CACHE/mihomo-${VERSION}-${ARCH}"

echo "[INFO] 目标版本: $VERSION (架构 $ARCH)"
mkdir -p "$CACHE" "$GEO_DIR"

if [ ! -x "$BIN" ]; then
  echo "下载 $URL"
  if ! curl -fsSL --retry 3 --retry-delay 2 -o "$CACHE/$ASSET" "$URL"; then
    echo "::error::mihomo 下载失败"; exit 1
  fi
  if [ "$DIGEST" = "-" ]; then   # API 没给校验和时,查本地固化表
    DIGEST="$(awk -v v="$VERSION" -v a="$ASSET" '$1 == v && $2 == a { print $3 }' "$ROOT/scripts/mihomo.sha256" 2>/dev/null)"
  fi
  got="$(sha256sum "$CACHE/$ASSET" | awk '{print $1}')"
  if [ -n "${DIGEST:-}" ] && [ "$DIGEST" != "-" ]; then
    if [ "$got" != "$DIGEST" ]; then
      echo "::error::$ASSET SHA256 校验失败(期望 $DIGEST,实际 $got)"; exit 1
    fi
    echo "[OK] SHA256 校验通过"
  else
    gunzip -t "$CACHE/$ASSET" 2>/dev/null || { echo "::error::$ASSET 压缩包损坏"; exit 1; }
    echo "::warning::$ASSET 无可用校验和(API 未提供、本地表也没有),已校验压缩包完整性: $got"
  fi
  gunzip -c "$CACHE/$ASSET" > "$BIN" || { echo "::error::解压失败"; exit 1; }
  chmod +x "$BIN"
  rm -f "$CACHE/$ASSET"
  # 只保留当前版本,避免缓存目录随版本升级无限膨胀
  find "$CACHE" -maxdepth 1 -type f -name 'mihomo-*' ! -name "$(basename "$BIN")" -delete 2>/dev/null || true
else
  echo "[OK] 使用缓存内核 $BIN"
fi
"$BIN" -v || true

# 预热地理库(MMDB/geosite):否则每次 mihomo -t 都要联网下载,拖慢工作流
GATE=1
if [ -f "$GEO_DIR/.ready" ]; then
  echo "[OK] 地理库缓存已就绪"
else
  cat > "$GEO_DIR/warm.yaml" <<'YAML'
mixed-port: 7890
mode: rule
log-level: warning
rules:
  - GEOSITE,cn,DIRECT
  - GEOIP,CN,DIRECT
  - MATCH,DIRECT
YAML
  if timeout 240 "$BIN" -t -d "$GEO_DIR" -f "$GEO_DIR/warm.yaml" > "$GEO_DIR/warm.log" 2>&1 \
     && grep -q "test is successful" "$GEO_DIR/warm.log"; then
    : > "$GEO_DIR/.ready"
    echo "[OK] 地理库预热完成"
  else
    echo "::warning::地理库预热失败,mihomo 内核门禁将跳过(脚本自身校验仍然生效)"
    tail -3 "$GEO_DIR/warm.log" 2>/dev/null || true
    GATE=0
  fi
fi

if [ -n "${GITHUB_ENV:-}" ]; then
  {
    echo "MIHOMO_BIN=$BIN"
    echo "MIHOMO_DIR=$GEO_DIR"
    echo "MIHOMO_GATE=$GATE"
  } >> "$GITHUB_ENV"
else
  echo "MIHOMO_BIN=$BIN"
  echo "MIHOMO_DIR=$GEO_DIR"
  echo "MIHOMO_GATE=$GATE"
fi
