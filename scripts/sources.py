#!/usr/bin/env python3
"""订阅来源清单(集中维护) + GitHub 下载镜像支持。

SOURCES:       来源标识 -> (显示名称, 主页 URL),供 sanitize.py 说明节点使用
FETCH_URLS:    来源标识 -> 固定订阅文件 URL(yoyapai 由 scraper.py 抓取,不在此列)
PAGE_SOURCES:  页面型来源(订阅地址每日变化)见 page_sources.py,由 scrape_page_sources.py 抓取
"""
import os

# 国内直连 GitHub 不稳:设置 GH_PROXY(例如 https://ghproxy.net)后,
# **抓取节点文件**时会自动走该镜像;节点测速不走镜像(必须直连测真实速度)。
GH_PROXY = os.environ.get("GH_PROXY", "").rstrip("/")
GITHUB_PREFIXES = (
    "https://raw.githubusercontent.com/",
    "https://github.com/",
    "https://gist.githubusercontent.com/",
    "https://objects.githubusercontent.com/",
    "https://codeload.github.com/",
)


def mirror_url(url: str) -> str:
    """把 GitHub 链接改写为镜像链接(未配置 GH_PROXY 时原样返回)。"""
    if GH_PROXY and url.startswith(GITHUB_PREFIXES):
        return f"{GH_PROXY}/{url}"
    return url


SOURCES = {
    # 页面型来源(订阅地址每日变化,由 scrape_page_sources.py 解析)
    "yoyapai": ("yoyapai.com", "https://yoyapai.com/category/mianfeijiedian"),
    "nodetoolbox": ("NodeToolBox", "https://nodetoolbox.net/free-nodes/"),
    "jichangg": ("机场e (jichangg.world)", "https://jichangg.world/mianfei/"),
    "au1rxx": ("Au1rxx/free-vpn-subscriptions", "https://github.com/Au1rxx/free-vpn-subscriptions"),
    "freesub": ("Ruk1ng001/freeSub", "https://github.com/Ruk1ng001/freeSub"),
    "xiaoji235": ("xiaoji235/airport-free", "https://github.com/xiaoji235/airport-free"),
    "passcro": ("zhangkaiitugithub/passcro", "https://github.com/zhangkaiitugithub/passcro"),
    "ripaojiedian": ("ripaojiedian/freenode", "https://github.com/ripaojiedian/freenode"),
    "chengaopan": ("chengaopan/AutoMergePublicNodes", "https://raw.githubusercontent.com/chengaopan/AutoMergePublicNodes/"),
    "peasoft": ("peasoft/NoMoreWalls", "https://raw.githubusercontent.com/peasoft/NoMoreWalls/"),
    "anaer": ("anaer.github.io/Sub", "https://anaer.github.io/Sub/"),
    "Pawdroid": ("Pawdroid/Free-servers", "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub"),
    "free18": ("free18/v2ray", "https://raw.githubusercontent.com/free18/v2ray/"),
    "go4sharing": ("go4sharing/sub", "https://raw.githubusercontent.com/go4sharing/sub/"),
    "Leon406": ("Leon406/SubCrawler", "https://raw.githubusercontent.com/Leon406/SubCrawler/main/sub/share/a11"),
    "shaoyou": ("shaoyouvip/free", "https://raw.githubusercontent.com/shaoyouvip/free/"),
    "kooker": ("kooker/FreeSubsCheck","https://raw.githubusercontent.com/kooker/FreeSubsCheck/"),
    "ovmvo": ("ovmvo/FreeSub","https://raw.githubusercontent.com/ovmvo/FreeSub/refs/heads/main/sub/permanent/"),
    "zhuhaiuk": ("zhuhaiuk/free-nodes","https://raw.githubusercontent.com/zhuhaiuk/free-nodes/"),
    "g-hunter-g": ("g-hunter-g/awesome-vpn", "https://raw.githubusercontent.com/g-hunter-g/awesome-vpn/"),
    "barabama": ("Barabama/FreeNodes", "https://github.com/Barabama/FreeNodes"),
    "wzmwayne": ("wzmwayne/proxy-node", "https://raw.githubusercontent.com/wzmwayne/proxy-node/"),
    "lanzm": ("lanzm/MetaFetch", "https://raw.githubusercontent.com/lanzm/MetaFetch/"),
    "1000ttank": ("1000ttank/free-vpn-clash-aggregator","https://raw.githubusercontent.com/1000ttank/free-vpn-clash-aggregator/"),
    "Eleven1985": ("Eleven1985/Scrape-By-Country","https://raw.githubusercontent.com/Eleven1985/Scrape-By-Country/"),
    "LinVireo": ("LinVireo/SmartSub", "https://raw.githubusercontent.com/LinVireo/SmartSub/"),
}

FETCH_URLS = {
    "au1rxx": "https://raw.githubusercontent.com/Au1rxx/free-vpn-subscriptions/main/output/clash.yaml",
    "freesub": "https://raw.githubusercontent.com/Ruk1ng001/freeSub/main/clash.yaml",
    "xiaoji235": "https://raw.githubusercontent.com/xiaoji235/airport-free/main/clash/clashnodecc.txt",
    "passcro": "https://raw.githubusercontent.com/zhangkaiitugithub/passcro/main/speednodes.yaml",
    "ripaojiedian": "https://raw.githubusercontent.com/ripaojiedian/freenode/main/clash",
    "chengaopan": "https://raw.githubusercontent.com/chengaopan/AutoMergePublicNodes/master/list.yml",
    "peasoft": "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.meta.yml",
    "anaer": "https://anaer.github.io/Sub/proxies.yaml",
    "Pawdroid": "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
    "free18": "https://raw.githubusercontent.com/free18/v2ray/refs/heads/main/c.yaml",
    "go4sharing": "https://raw.githubusercontent.com/go4sharing/sub/main/sub.yaml",
    "Leon406": "https://raw.githubusercontent.com/Leon406/SubCrawler/main/sub/share/a11",
    "shaoyou": "https://raw.githubusercontent.com/shaoyouvip/free/refs/heads/main/all.yaml",
    "kooker": "https://raw.githubusercontent.com/kooker/FreeSubsCheck/main/mihomo.yaml",
    "ovmvo": "https://raw.githubusercontent.com/ovmvo/FreeSub/refs/heads/main/sub/permanent/mihomo.yaml",
    "zhuhaiuk": "https://raw.githubusercontent.com/zhuhaiuk/free-nodes/main/clash_config.yaml",
    "g-hunter-g": "https://raw.githubusercontent.com/g-hunter-g/awesome-vpn/refs/heads/main/key.txt",
    "barabama": "https://raw.githubusercontent.com/Barabama/FreeNodes/main/nodes/clashmeta.yaml",
    "wzmwayne": "https://raw.githubusercontent.com/wzmwayne/proxy-node/refs/heads/main/output/aio-all/clash.yaml",
    "lanzm": "https://raw.githubusercontent.com/lanzm/MetaFetch/refs/heads/master/list.meta.yml",
    "1000ttank": "https://raw.githubusercontent.com/1000ttank/free-vpn-clash-aggregator/refs/heads/main/output/clash.yaml",
    "Eleven1985": "https://raw.githubusercontent.com/Eleven1985/Scrape-By-Country/refs/heads/main/configs/protocols/AllProtocols.txt",
    "LinVireo": "https://raw.githubusercontent.com/LinVireo/SmartSub/refs/heads/main/sub/sub_all_clash.txt",
}
