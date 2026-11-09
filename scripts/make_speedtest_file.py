#!/usr/bin/env python3
"""生成固定大小的测速文件(默认 20MB,内容为不可压缩随机数据,可复现)。

测速文件发布在 release:test,由测速阶段(tests_nodes.py)下载使用;
随机数据可避免代理/CDN 压缩导致测速虚高。

用法:
  python scripts/make_speedtest_file.py                     # 生成 speedtest-20mb.bin
  python scripts/make_speedtest_file.py -o /tmp/s.bin --bytes 20000000
"""
import argparse
import hashlib
import random


def main():
    ap = argparse.ArgumentParser(description="生成测速文件")
    ap.add_argument("-o", "--output", default="speedtest-20mb.bin")
    ap.add_argument("--bytes", type=int, default=20_000_000, help="文件大小(字节)")
    ap.add_argument("--seed", type=int, default=20261017, help="随机种子(保证内容可复现)")
    ap.add_argument("--chunk", type=int, default=1 << 20, help="每次生成的随机块大小")
    args = ap.parse_args()

    rnd = random.Random(args.seed)
    digest = hashlib.sha256()
    written = 0
    with open(args.output, "wb") as f:
        while written < args.bytes:
            n = min(args.chunk, args.bytes - written)
            block = rnd.randbytes(n)  # 每块独立随机,不可压缩
            f.write(block)
            digest.update(block)
            written += n
    print(f"[OK] {args.output}: {written} bytes  sha256={digest.hexdigest()}")


if __name__ == "__main__":
    main()
