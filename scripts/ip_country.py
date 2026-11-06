#!/usr/bin/env python3
"""离线 IP -> 国家代码查询。

数据源: ip-location-db 的 dbip-country-ipv4.csv(start,end,country_code),
每行一段 IPv4 区间。文件缓存在 MIHOMO_DIR 下,跟着地理库缓存一起被 Actions 缓存,
所以 CI 上一般只在第一次运行时下载。

用法:
    from ip_country import IpCountry, ensure_csv
    path = ensure_csv()
    db = IpCountry(path) if path else None
    db.lookup("1.2.3.4")   # -> "US" / "" (查不到)
"""
import bisect
import ipaddress
import os
import shutil
import time
import urllib.request

CSV_URL = ("https://raw.githubusercontent.com/sapics/ip-location-db/main/"
           "dbip-country/dbip-country-ipv4.csv")
CSV_NAME = "dbip-country-ipv4.csv"
MIN_BYTES = 64


def cache_dir():
    """跟 mihomo 地理库放一起(MIHOMO_DIR 已被 actions/cache 缓存)。"""
    return os.environ.get("MIHOMO_DIR") or os.path.join(".cache", "geo")


def ensure_csv(path=None, tries=2, timeout=120):
    """确保 CSV 存在;返回路径,拿不到返回空串(调用方退回按名字识别)。"""
    path = path or os.path.join(cache_dir(), CSV_NAME)
    if os.path.isfile(path) and os.path.getsize(path) > MIN_BYTES:
        return path
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = path + ".tmp"
    for i in range(tries):
        try:
            print(f"  [INFO] 下载 IP 归属地库({i + 1}/{tries}): {CSV_URL}")
            with urllib.request.urlopen(CSV_URL, timeout=timeout) as resp, open(tmp, "wb") as f:
                shutil.copyfileobj(resp, f)
            if os.path.getsize(tmp) <= MIN_BYTES:
                raise ValueError("文件过小,疑似下载失败")
            os.replace(tmp, path)
            print(f"  [OK] IP 归属地库就绪: {path} ({os.path.getsize(path) // 1024} KB)")
            return path
        except Exception as e:  # noqa: BLE001 - 网络问题一律降级
            print(f"  [WARN] 下载失败({i + 1}/{tries}): {e}")
            time.sleep(2 + i * 3)
    return ""


class IpCountry:
    """把 dbip-country 的区间表读进内存,二分查国家代码。"""

    def __init__(self, path):
        rows = []
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                parts = line.rstrip("\n").split(",")
                if len(parts) < 3:
                    continue
                try:
                    start = int(ipaddress.IPv4Address(parts[0].strip()))
                    end = int(ipaddress.IPv4Address(parts[1].strip()))
                except ValueError:
                    continue           # 表头/注释行
                code = parts[2].strip().upper()
                if code:
                    rows.append((start, end, code))
        rows.sort(key=lambda r: r[0])
        self.starts = [r[0] for r in rows]
        self.ends = [r[1] for r in rows]
        self.codes = [r[2] for r in rows]
        print(f"  [OK] IP 归属地表载入 {len(rows)} 段")

    def __len__(self):
        return len(self.starts)

    def lookup(self, ip):
        try:
            num = int(ipaddress.IPv4Address(str(ip).strip()))
        except ValueError:
            return ""
        i = bisect.bisect_right(self.starts, num) - 1
        if i >= 0 and num <= self.ends[i]:
            return self.codes[i]
        return ""
