#!/usr/bin/env bash
# 确保 20MB 测速文件已发布到 release:test,供测速阶段下载。
#
# 用法(本地或 CI):
#   GH_TOKEN=xxx bash scripts/ensure_speedtest_asset.sh
#
# 已有资产时直接返回;缺失时用 scripts/make_speedtest_file.py 重新生成并上传。
set -uo pipefail

TAG="${SPEEDTEST_TAG:-test}"
ASSET="${SPEEDTEST_ASSET:-speedtest-20mb.bin}"
REPO="${GITHUB_REPOSITORY:-hkjych/Z}"
URL="https://github.com/${REPO}/releases/download/${TAG}/${ASSET}"
# 测速本身必须直连(镜像只用于检查/上传),镜像仅作为本地可达性兜底
MIRROR_URL="${GH_PROXY:+${GH_PROXY%/}/}${URL}"

if curl -fsSIL --retry 3 --retry-delay 2 -o /dev/null "$URL" \
   || { [ "$MIRROR_URL" != "$URL" ] && curl -fsSIL --retry 3 --retry-delay 2 -o /dev/null "$MIRROR_URL"; }; then
  echo "[OK] 测速文件已就绪(测速时使用直连): $URL"
  exit 0
fi

echo "[WARN] 测速文件不可用,尝试重新生成并上传: $URL"
if ! command -v gh >/dev/null 2>&1; then
  echo "[FAIL] 未安装 gh,无法上传;请手动执行:"
  echo "       python scripts/make_speedtest_file.py -o $ASSET"
  echo "       gh release create $TAG $ASSET --repo $REPO"
  exit 1
fi

python3 "$(dirname "$0")/make_speedtest_file.py" -o "$ASSET" || exit 1

if ! gh release view "$TAG" --repo "$REPO" >/dev/null 2>&1; then
  echo "创建 release: $TAG"
  gh release create "$TAG" --repo "$REPO" --title "test" \
    --notes "测速用 20MB 测试文件(请勿删除,CI 测速阶段会下载)" || true
fi

gh release upload "$TAG" "$ASSET" --repo "$REPO" --clobber || exit 1
rm -f "$ASSET"
if curl -fsSIL --retry 3 --retry-delay 2 -o /dev/null "$URL"; then
  echo "[OK] 测速文件已发布: $URL"
else
  echo "[FAIL] 上传后仍无法访问: $URL"
  exit 1
fi

