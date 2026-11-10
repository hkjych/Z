#!/usr/bin/env python3
"""校验 output/ 目录与 sources.py 来源清单一致，并顺带生成 sing-box 版 box.json。

  * output/<name>/ 必须能在 SOURCES 里找到（只有 output/aio、output/aio-all 例外）；
  * 已下线来源（RETIRED）保留旧目录不删，只告警，不影响构建；
  * 每个来源都应有已发布的 clash.yaml，缺失只告警（v1 可自动重建）；
  * 最后把 output/aio、output/aio-all 的 clash.yaml 翻成同目录的 box.json
    （sing-box 格式）。这一步放在这里，是因为本脚本正好跑在 AIO 发布之后，
    而修改 .github/workflows 需要额外的 token scope；转换失败只告警，
    不会让来源校验变红。

用法：
  python scripts/check_sources.py            # 校验 + 生成 box.json
  python scripts/check_sources.py --no-singbox   # 只校验来源
"""
import importlib.util
import json
import os
import sys

from sources import SOURCES

ALLOWED_EXTRA = {"aio", "aio-all"}
# 已下线/改名的来源：目录里还留着上一版 clash.yaml（老订阅链接仍可用），但不再抓取。
# 想彻底清掉就 git rm 掉目录，再把名字从这里删掉。
RETIRED = {"GA", "GB", "GC", "GD", "GE", "GF", "shaoyouvip", "anzm"}
OUTPUT = "output"
SINGBOX_DIRS = ("aio", "aio-all")


def _load_converter():
    """按文件路径加载同目录的 clash_to_singbox.py（不依赖 sys.path）。"""
    here = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(here, "clash_to_singbox.py")
    spec = importlib.util.spec_from_file_location("clash_to_singbox", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def generate_singbox(output=OUTPUT):
    """把 AIO 的 clash.yaml 翻成同目录 box.json；任何异常只告警。"""
    try:
        import yaml
        mod = _load_converter()
    except Exception as e:                       # 转换器缺失/依赖没装
        print(f"[WARN] 跳过 sing-box 生成：{e}")
        return []

    produced = []
    for name in SINGBOX_DIRS:
        src = os.path.join(output, name, "clash.yaml")
        if not os.path.isfile(src):
            continue
        dst = os.path.join(output, name, "box.json")
        try:
            with open(src, encoding="utf-8") as f:
                clash = yaml.safe_load(f) or {}
            config, stats, skipped, groups = mod.build_config(clash)
            tmp = dst + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(config, f, ensure_ascii=False, separators=(",", ":"))
                f.write("\n")
            os.replace(tmp, dst)
        except Exception as e:
            print(f"[WARN] {src} 转 sing-box 失败，保留上一版 {dst}：{e}")
            continue
        total = sum(len(o.get("outbounds") or []) for o in groups)
        print(f"[OK] {dst}：节点 {sum(stats.values())}，分组 {len(groups)}"
              f"（成员引用 {total}），出站 {len(config['outbounds'])}，"
              f"{os.path.getsize(dst) / 1024:.0f} KB")
        if skipped:
            print("     跳过：" + "，".join(f"{k}×{v}" for k, v in skipped.most_common(6)))
        produced.append(dst)
    return produced


def main():
    if not os.path.isdir(OUTPUT):
        raise SystemExit(f"[FAIL] 找不到 {OUTPUT}/ 目录")
    dirs = sorted(d for d in os.listdir(OUTPUT) if os.path.isdir(os.path.join(OUTPUT, d)))

    orphans = [d for d in dirs if d not in SOURCES and d not in ALLOWED_EXTRA and d not in RETIRED]
    retired = [d for d in dirs if d in RETIRED and d not in SOURCES]
    unknown_src = []
    missing = []
    for name in SOURCES:
        p = os.path.join(OUTPUT, name, "clash.yaml")
        if not os.path.isfile(p):
            missing.append(name)

    print(f"来源目录 {len(dirs)} 个: {dirs}")
    print(f"sources.py 来源 {len(SOURCES)} 个: {sorted(SOURCES)}")
    if retired:
        print(f"[WARN] 已下线来源(保留旧文件,不再更新): {retired}")
    if unknown_src:
        print(f"[WARN] 清单里没有对应抓取方式的来源: {unknown_src}")
    if missing:
        print(f"[WARN] 尚未发布 clash.yaml 的来源: {missing}")
    if orphans:
        print(f"[FAIL] 孤儿目录(不在 SOURCES 中): {orphans}")
        print("       请删除该目录,或在 sources.py 中登记来源。")
        return 1
    print("[OK] output/ 与来源清单一致")

    if "--no-singbox" not in sys.argv:
        generate_singbox()
    return 0


if __name__ == "__main__":
    sys.exit(main())
