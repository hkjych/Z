#!/usr/bin/env bash
# 安装 sing-box 内核（默认取最新发行版，带 SHA256 校验），只用于 `sing-box check`
# 校验 scripts/clash_to_singbox.py 生成的 box.json。
#
# 用法：bash scripts/install_singbox.sh
# 环境变量：
#   SINGBOX_VERSION  指定版本标签（如 v1.14.4）；留空或 latest 表示自动取最新版
#   SINGBOX_CACHE    内核缓存目录（默认 ~/.cache/singbox）
#   GH_PROXY         可选 GitHub 镜像前缀（如 https://ghproxy.net）
# 输出（追加到 $GITHUB_ENV）：
#   SINGBOX_BIN   内核可执行文件路径
#   SINGBOX_GATE  1=可用于校验，0=没装上（后续步骤跳过校验）
set -uo pipefail

REQUESTED="${SINGBOX_VERSION:-latest}"
CACHE="${SINGBOX_CACHE:-$HOME/.cache/singbox}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

case "$(uname -m)" in
  x86_64 | amd64) ARCH=amd64 ;;
  aarch64 | arm64) ARCH=arm64 ;;
  *)
    echo "::warning::不支持的架构: $(uname -m)，跳过 sing-box 校验"
    [ -n "${GITHUB_ENV:-}" ] && echo "SINGBOX_GATE=0" >> "$GITHUB_ENV"
    exit 0
    ;;
esac

PY=""
for c in python3 python; do
  if command -v "$c" >/dev/null 2>&1; then PY="$c"; break; fi
done

# 读 release API：输出 "<tag> <asset名> <sha256或->"
read_release() {
  [ -n "$PY" ] || return 1
  "$PY" - "$ARCH" <<'PY'
import json
import os
import sys
import time
import urllib.error
import urllib.request

arch = sys.argv[1]
token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN") or ""
headers = {
    "User-Agent": "proxy-node-bot/1.0",
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
}
if token:
    headers["Authorization"] = "Bearer %s" % token
url = "https://api.github.com/repos/SagerNet/sing-box/releases/latest"

data, err = None, "未知错误"
for attempt in range(3):
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=30) as r:
            data = json.load(r)
        err = ""
        break
    except urllib.error.HTTPError as e:
        err = "HTTP %s %s" % (e.code, e.reason)
        if e.code in (403, 429):
            err += "（匿名限流 60 次/小时，需传 GH_TOKEN）" if not token else "（限流或权限不足）"
        if e.code not in (403, 429, 500, 502, 503, 504):
            break
    except Exception as e:
        err = "%s: %s" % (type(e).__name__, e)
    time.sleep(2 * (attempt + 1))

if data is None:
    sys.stderr.write("release API 失败: %s\n" % err)
    sys.exit(1)

tag = data.get("tag_name") or ""
if not tag:
    sys.stderr.write("release API 返回内容缺 tag_name\n")
    sys.exit(1)
version = tag.lstrip("v")
name = "sing-box-%s-linux-%s.tar.gz" % (version, arch)
digest = "-"
for a in data.get("assets") or []:
    if a.get("name") == name:
        digest = (a.get("digest") or "").replace("sha256:", "") or "-"
        break
print(tag, name, digest)
PY
}

VERSION=""
ASSET=""
DIGEST="-"
if [ "$REQUESTED" = "latest" ] || [ -z "$REQUESTED" ]; then
  echo "[INFO] 查询 sing-box 最新版本..."
  out="$(read_release 2>&1)"
  VERSION="$(printf '%s\n' "$out" | awk '/^v[0-9]/ { print $1; exit }')"
  ASSET="$(printf '%s\n' "$out" | awk '/^v[0-9]/ { print $2; exit }')"
  DIGEST="$(printf '%s\n' "$out" | awk '/^v[0-9]/ { print $3; exit }')"
  if [ -z "$VERSION" ]; then
    echo "[WARN] $(printf '%s\n' "$out" | tail -1)"
    # API 不可用时回退到仓库固化表(scripts/singbox.sha256)的最后一条,保住校验能力
    FALLBACK="$(awk 'NF == 3 && $1 ~ /^v/ { line = $0 } END { print line }' "$ROOT/scripts/singbox.sha256" 2>/dev/null)"
    if [ -n "$FALLBACK" ]; then
      VERSION="$(printf '%s\n' "$FALLBACK" | awk '{print $1}')"
      ASSET="$(printf '%s\n' "$FALLBACK" | awk '{print $2}')"
      DIGEST="$(printf '%s\n' "$FALLBACK" | awk '{print $3}')"
      echo "::warning::release API 不可用，改用固化版本 $VERSION（仍做 SHA256 校验）"
    fi
  fi
  if [ -z "$VERSION" ]; then
    echo "::warning::获取 sing-box 版本失败且无固化表，跳过 sing-box 校验"
    [ -n "${GITHUB_ENV:-}" ] && echo "SINGBOX_GATE=0" >> "$GITHUB_ENV"
    exit 0
  fi
else
  VERSION="$REQUESTED"
  ASSET="sing-box-${VERSION#v}-linux-${ARCH}.tar.gz"
fi

URL="https://github.com/SagerNet/sing-box/releases/download/${VERSION}/${ASSET}"
if [ -n "${GH_PROXY:-}" ]; then
  URL="${GH_PROXY%/}/$URL"
  echo "[INFO] 使用 GH_PROXY 镜像: $URL"
fi

BIN="$CACHE/sing-box-${VERSION}-${ARCH}"
mkdir -p "$CACHE"

if [ ! -x "$BIN" ]; then
  echo "[INFO] 下载 $URL"
  if ! curl -fsSL --connect-timeout 20 --max-time 600 --retry 2 --retry-delay 2 -o "$CACHE/$ASSET" "$URL"; then
    echo "::warning::sing-box 下载失败，跳过校验（box.json 仍会照常生成）"
    [ -n "${GITHUB_ENV:-}" ] && echo "SINGBOX_GATE=0" >> "$GITHUB_ENV"
    exit 0
  fi
  got="$(sha256sum "$CACHE/$ASSET" | awk '{print $1}')"
  if [ -n "$DIGEST" ] && [ "$DIGEST" != "-" ]; then
    if [ "$got" != "$DIGEST" ]; then
      echo "::warning::$ASSET SHA256 不匹配（期望 $DIGEST，实际 $got），放弃校验"
      rm -f "$CACHE/$ASSET"
      [ -n "${GITHUB_ENV:-}" ] && echo "SINGBOX_GATE=0" >> "$GITHUB_ENV"
      exit 0
    fi
    echo "[OK] SHA256 校验通过"
  else
    echo "::warning::$ASSET 无可用校验和，仅校验压缩包完整性（$got）"
  fi
  tar -xzf "$CACHE/$ASSET" -C "$CACHE" || { echo "::warning::解压失败，跳过校验"; exit 0; }
  cp -f "$CACHE/sing-box-${VERSION#v}-linux-${ARCH}/sing-box" "$BIN" \
    || { echo "::warning::解压后找不到 sing-box，跳过校验"; exit 0; }
  chmod +x "$BIN"
  rm -rf "$CACHE/$ASSET" "$CACHE/sing-box-${VERSION#v}-linux-${ARCH}"
  find "$CACHE" -maxdepth 1 -type f -name 'sing-box-*' ! -name "$(basename "$BIN")" -delete 2>/dev/null || true
else
  echo "[OK] 使用缓存内核 $BIN"
fi
"$BIN" version || {
  echo "::warning::sing-box 无法执行，跳过校验"
  [ -n "${GITHUB_ENV:-}" ] && echo "SINGBOX_GATE=0" >> "$GITHUB_ENV"
  exit 0
}

if [ -n "${GITHUB_ENV:-}" ]; then
  {
    echo "SINGBOX_BIN=$BIN"
    echo "SINGBOX_GATE=1"
  } >> "$GITHUB_ENV"
else
  echo "SINGBOX_BIN=$BIN"
  echo "SINGBOX_GATE=1"
fi
