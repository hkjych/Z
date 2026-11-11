#!/usr/bin/env python3
"""页面型来源解析器:订阅地址每天变化,需要先解析栏目/文章页再拿到下载地址。

与 sources.py 的 FETCH_URLS(固定订阅地址)互补:
  - nodetoolbox: 索引页 https://nodetoolbox.net/free-nodes/
                  -> 最新文章 /free-nodes/YYYY-MM-DD/
                  -> https://nodesub.nodetoolbox.net/YYYY/MM/nodetoolbox-YYYYMMDD.yaml

每个来源实现 discover() -> dict:
    {"sub_url": 订阅地址, "date": 内容日期, "detail": 说明文字}
没有可用地址时抛 SourceUnavailable(带原因)。
"""
import re
import time
from datetime import date, timedelta

import requests

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
}
TIMEOUT = 60
RETRIES = 2


class SourceUnavailable(RuntimeError):
    """页面解析不到可用订阅(站点停更/订阅域名失效/结构变化)。"""


def fetch_text(url, timeout=TIMEOUT):
    """带重试的 GET,返回解码后的文本。"""
    last = None
    for i in range(RETRIES + 1):
        try:
            resp = requests.get(url, headers=HEADERS, timeout=timeout)
            resp.raise_for_status()
            if not resp.encoding or resp.encoding.lower() == "iso-8859-1":
                resp.encoding = resp.apparent_encoding or "utf-8"
            return resp.text
        except Exception as e:  # noqa: BLE001 - 统一转成 SourceUnavailable
            last = e
            if i < RETRIES:
                time.sleep(1 + i)
    raise SourceUnavailable(f"请求失败 {url}: {last}")


# --------------------------------------------------------------------------
# NodeToolBox: 索引页 -> 每日文章页 -> 每日订阅 yaml
# --------------------------------------------------------------------------
NODETOOLBOX_INDEX = "https://nodetoolbox.net/free-nodes/"
NODETOOLBOX_SUB_RE = re.compile(r'https://nodesub\.nodetoolbox\.net/[^"\'\s<>]+\.ya?ml')
NODETOOLBOX_DAY_RE = re.compile(r'/free-nodes/(\d{4}-\d{2}-\d{2})/')


def _nodetoolbox_days(index_html):
    days = sorted(set(NODETOOLBOX_DAY_RE.findall(index_html)), reverse=True)
    return days


def _nodetoolbox_extract(daily_html):
    """每日文章页里的 Clash 订阅地址;优先 <a class=node-sub-url>,其次任意 nodesub 链接。"""
    m = re.search(
        r'<a[^>]+class="[^"]*node-sub-url[^"]*"[^>]+href="(https://nodesub\.[^"]+\.ya?ml)"',
        daily_html, re.I)
    if m:
        return m.group(1)
    m = re.search(NODETOOLBOX_SUB_RE, daily_html)
    if m:
        return m.group(0)
    return None


def _nodetoolbox_discover():
    index = fetch_text(NODETOOLBOX_INDEX)
    days = _nodetoolbox_days(index)
    # 索引页可能缓存滞后:再按今天/昨天补两个候选
    today = date.today()
    for d in (today, today - timedelta(days=1)):
        if d.isoformat() not in days:
            days.append(d.isoformat())
    errors = []
    for day in days[:4]:
        url = f"{NODETOOLBOX_INDEX}{day}/"
        try:
            daily = fetch_text(url)
        except SourceUnavailable as e:
            errors.append(str(e))
            continue
        sub_url = _nodetoolbox_extract(daily)
        if sub_url:
            return {"sub_url": sub_url, "date": day, "detail": f"每日文章 {url}"}
        errors.append(f"{url} 中没有找到 .yaml 订阅链接")
    raise SourceUnavailable("; ".join(errors[-2:]) or "索引页没有每日文章")


# 注册表:来源标识必须与 sources.SOURCES 中的键一致(sanitize 需要)
PAGE_SOURCES = {
    "nodetoolbox": {
        "name": "NodeToolBox",
        "homepage": NODETOOLBOX_INDEX,
        "discover": _nodetoolbox_discover,
    },
}
