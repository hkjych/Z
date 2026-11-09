#!/usr/bin/env python3
"""抓取 yoyapai.com 免费节点文章,下载最新 Clash 订阅到 output/yoyapai/clash.raw.yaml。

  * 原始文件写 .raw.yaml(不入库),清洗/内核校验通过后才会替换已发布的 clash.yaml;
  * 文章页并发抓取(限速),单篇失败不影响整体;
  * latest_urls.json 记录最新文章信息,供人工查看与调试。

用法:
  python scripts/scraper.py [--limit N]
"""
import argparse
import concurrent.futures as futures
import html
import json
import os
import re
import time

import requests
from bs4 import BeautifulSoup

from sources import SOURCES

BASE_URL = "https://yoyapai.com"
CATEGORY_URL = SOURCES["yoyapai"][1]
RAW_PATH = os.path.join("output", "yoyapai", "clash.raw.yaml")
LATEST_JSON = "latest_urls.json"
WORKERS = 4
RETRIES = 2

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
}

# 节点订阅链接(freenode.yoyapai.com)
NODE_LINK_PATTERN = re.compile(
    r'https?://freenode\.yoyapai\.com/\d{4}/\d{2}/[^"\'<>\s]+?\.(?:yaml|txt)',
    re.IGNORECASE,
)


def fetch(url, timeout=20):
    """带重试的 GET,返回 text。"""
    last = None
    for i in range(RETRIES + 1):
        try:
            resp = requests.get(url, headers=HEADERS, timeout=timeout)
            resp.raise_for_status()
            resp.encoding = "utf-8"
            return resp.text
        except Exception as e:
            last = e
            if i < RETRIES:
                time.sleep(1 + i)
    raise last


def parse_article_list(page_html):
    """解析分类页,返回 [{title, link, excerpt}]。"""
    soup = BeautifulSoup(page_html, "html.parser")
    articles = []
    for li in soup.select("ul.wp-block-post-template > li.wp-block-post"):
        title_tag = li.select_one("h2.wp-block-post-title a")
        if not title_tag:
            continue
        excerpt_tag = li.select_one(".wp-block-post-excerpt__excerpt")
        articles.append({
            "title": title_tag.get_text(strip=True),
            "link": title_tag.get("href", ""),
            "excerpt": excerpt_tag.get_text(strip=True) if excerpt_tag else "",
        })
    return articles


def extract_node_links(article_html):
    """从文章页提取 freenode.yoyapai.com 订阅链接(按出现顺序去重)。"""
    decoded = html.unescape(article_html)
    seen, unique = set(), []
    for link in NODE_LINK_PATTERN.findall(decoded):
        if link not in seen:
            seen.add(link)
            unique.append(link)
    return unique


def article_date(title):
    """从标题("10月16日")推日期;跨年时回退一年(不再硬编码年份)。"""
    m = re.search(r"(\d+)月(\d+)日", title)
    if not m:
        return ""
    month, day = int(m.group(1)), int(m.group(2))
    now = time.gmtime(time.time() + 8 * 3600)  # 北京时间
    year = now.tm_year
    if month > now.tm_mon:
        year -= 1
    return f"{year:04d}-{month:02d}-{day:02d}"


def main():
    ap = argparse.ArgumentParser(description="yoyapai.com 免费节点抓取")
    ap.add_argument("--limit", type=int, default=0, help="只处理前 N 篇文章(调试用)")
    args = ap.parse_args()

    t0 = time.monotonic()
    print("=" * 60)
    print(f"[1/3] 获取分类页: {CATEGORY_URL}")
    articles = parse_article_list(fetch(CATEGORY_URL))
    if args.limit:
        articles = articles[:args.limit]
    print(f"      -> {len(articles)} 篇文章")
    if not articles:
        raise SystemExit("[FAIL] 分类页未解析到任何文章(页面结构可能已变)")

    print(f"[2/3] 并发抓取文章页(并发 {WORKERS})")
    results = []

    def work(a):
        try:
            a = dict(a, node_links=extract_node_links(fetch(a["link"])))
        except Exception as e:
            a = dict(a, node_links=[], error=str(e))
        return a

    with futures.ThreadPoolExecutor(max_workers=WORKERS) as ex:
        for i, a in enumerate(ex.map(work, articles), 1):
            status = f"{len(a['node_links'])} 个链接" if a["node_links"] else f"无链接 {a.get('error', '')}".strip()
            print(f"      {i}. {a['title'][:44]} [{status}]")
            results.append(a)

    latest = results[0]
    yaml_link = next((nl for nl in latest["node_links"] if nl.endswith(".yaml")), "")
    txt_link = next((nl for nl in latest["node_links"] if nl.endswith(".txt")), "")

    print("[3/3] 下载最新订阅")
    if not yaml_link:
        raise SystemExit("[FAIL] 最新文章里没有 .yaml 订阅链接,本次不更新 yoyapai")

    resp = requests.get(yaml_link, headers=HEADERS, timeout=60)
    resp.raise_for_status()
    if not resp.content.strip():
        raise SystemExit("[FAIL] 订阅内容为空,本次不更新 yoyapai")
    os.makedirs(os.path.dirname(RAW_PATH), exist_ok=True)
    with open(RAW_PATH, "wb") as f:
        f.write(resp.content)
    print(f"      [OK] {yaml_link} ({len(resp.content)} bytes) -> {RAW_PATH}")

    data = {
        "title": latest["title"],
        "link": latest["link"],
        "date": article_date(latest["title"]),
        "yaml": yaml_link,
        "txt": txt_link,
    }
    with open(LATEST_JSON, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    print(f"      [OK] {LATEST_JSON} 已更新({data['date']}),耗时 {time.monotonic()-t0:.0f}s")


if __name__ == "__main__":
    main()
