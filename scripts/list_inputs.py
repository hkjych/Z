#!/usr/bin/env python3
"""列出可参与合并的已发布订阅(只认清单内来源,自动跳过已下线目录)。

output/ 里可能还留着已下线来源的旧 clash.yaml(GA..GF、改名前的目录等),
它们不该再被合并进 AIO。按 sources.SOURCES 白名单挑文件,顺便保证顺序稳定。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sources import SOURCES  # noqa: E402


def main():
    files = []
    for name in SOURCES:
        p = os.path.join("output", name, "clash.yaml")
        if os.path.isfile(p):
            files.append(p)
    print(" ".join(sorted(files)))


if __name__ == "__main__":
    main()
