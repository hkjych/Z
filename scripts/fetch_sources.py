#!/usr/bin/env python3
"""下载各来源的原始订阅到 output/<source>/clash.raw.yaml,交给 sanitize.py 清洗。

设计要点:
  * 原始文件写入 .raw.yaml(不入库),已发布的 clash.yaml 只在清洗+内核校验
    通过后才被替换 —— 下载失败时旧文件保持原样,不会被重新盖上"更新时间";
  * 只发分享链接(ss:// vmess:// ...)的来源先由 uri_to_clash 转成 Clash
    proxies,再交给 sanitize.py,否则这类来源永远卡在"顶层不是映射";
  * 单个来源失败不影响其它来源,只有全部失败才返回非 0。

用法:
  python scripts/fetch_sources.py            # 下载全部来源(不含 yoyapai,由 scraper.py 抓取)
  python scripts/fetch_sources.py au1rxx     # 只下载指定来源
"""
import os
import sys

import time

import requests
import yaml

import uri_to_clash
from sources import FETCH_URLS, GH_PROXY, mirror_url

HEADERS = {"User-Agent": "proxy-node-bot/1.0"}
RAW_NAME = "clash.raw.yaml"
TIMEOUT = 120


def yaml_parseable(body):
    """下载回来的内容能否被 YAML 解析(上游偶发写出半截文件,导致整轮白跑)。"""
    if not isinstance(body, (bytes, bytearray)):
        body = str(body).encode("utf-8", "replace")
    text = body.decode("utf-8", "replace")
    head = text.lstrip()[:40]
    if head.startswith("<"):
        return False         # HTML 页面(例如误用 github.com/.../blob/... 链接)
    if not head.startswith(("#", "---")) and ":" not in head:
        return True          # 不像 Clash 配置(例如分享链接列表),交给 sanitize 判断
    try:
        yaml.safe_load(text)
        return True
    except Exception:
        return False

def fetch_one(name, url):
    out_dir = os.path.join("output", name)
    os.makedirs(out_dir, exist_ok=True)
    dst = os.path.join(out_dir, RAW_NAME)
    if os.path.exists(dst):
        os.unlink(dst)  # 失败时不会残留上一轮原始文件

    urls = [mirror_url(url)]
    if urls[0] != url:
        urls.append(url)  # 镜像失败回退直连
    last_err = None
    for attempt in (0, 1):       # 上游偶尔写出半截文件:整体重试一次
        for u in urls:
            try:
                print(f"  [GET] {name}: {u}")
                resp = requests.get(u, headers=HEADERS, timeout=TIMEOUT)
                resp.raise_for_status()
                if not resp.content.strip():
                    raise ValueError("返回内容为空")
                # 少数来源只发分享链接(ss:// vmess:// ...),先转成 Clash proxies,
                # 否则 sanitize.py 必然报「顶层不是映射」。已经是 Clash 配置的原样写盘。
                body, note = uri_to_clash.maybe_convert(resp.content)
                if not yaml_parseable(body):
                    raise ValueError("下载内容不是有效 YAML(上游可能正在更新)")
                with open(dst, "wb") as f:
                    f.write(body)
                print(f"  [OK] {name} ({len(resp.content)} bytes)")
                if note:
                    print(f"  [CONVERT] {name}: {note}")
                return len(body)
            except Exception as e:
                last_err = e
                print(f"  [WARN] {name} 下载失败({u}): {e}")
        if attempt == 0:
            print(f"  [RETRY] {name} 3 秒后重试一次")
            time.sleep(3)
    raise last_err


# 由 scraper.py 抓取的来源:FETCH_URLS 里登记的是"文章分类页"(HTML),
# 默认再下载一遍会把刚抓到的订阅覆盖成网页,导致该来源每轮清洗都失败。
SCRAPED_BY_SCRAPER = {"yoyapai"}


def main():
    if GH_PROXY:
        print(f"  [INFO] 使用 GitHub 镜像 GH_PROXY={GH_PROXY}(仅抓取节点文件,测速不走镜像)")
    names = (sys.argv[1:] if len(sys.argv) > 1
             else [n for n in FETCH_URLS if n not in SCRAPED_BY_SCRAPER])
    unknown = [n for n in names if n not in FETCH_URLS]
    if unknown:
        raise SystemExit(f"[FAIL] 未知来源: {unknown} (可选: {', '.join(FETCH_URLS)})")
    ok, fail = 0, []
    for name in names:
        try:
            fetch_one(name, FETCH_URLS[name])
            ok += 1
        except Exception as e:
            print(f"  [FAIL] {name}: {e}")
            fail.append(name)
    print(f"下载完成: 成功 {ok}, 失败 {len(fail)} {fail}")
    if fail:
        print("  (失败来源本次不更新,已发布的 clash.yaml 保持不变)")
    if names and ok == 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
