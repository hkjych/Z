#!/usr/bin/env python3
"""清洗 Clash 订阅 YAML,保证输出能被 Clash.Meta (mihomo) 正常加载。

用法:
  python sanitize.py <in.yaml> <out.yaml> --source <来源标识> [--gate --mihomo <内核路径>]

处理内容:
  1. 控制字符:按 go-yaml v3 的码点白名单检查**解码后**的每个字符串值;
  2. 垃圾顶层键:上游错误页残留的标量键(如 "error code: 520")一并剔除;
  3. 名称唯一性:重复节点名/组名、节点名与组名冲突(否则 mihomo 报
     "proxy xxx is the duplicate name",整份配置加载失败);
  4. 悬空引用:丢弃节点/分组后,修复 group->proxy、group->group、rule->目标
     的失效引用(否则 mihomo 报 "proxy group[0]: xxx: 'yyy' not found");
  5. 说明节点:注入"说明-"假节点与"说明"分组,承载来源/清洗结果/时间/仓库;
  6. 输出为纯 ASCII YAML(非 ASCII 以 \\uXXXX 转义,兼容所有 YAML 解析器);
  7. 写入前二次解析校验 + 可选 mihomo 内核 `-t` 门禁,任一不过即拒绝发布。

背景:
  go-yaml v3 的读取器只接受白名单码点(U+0009/000A/000D、0x20-0x7E、0x85、
  0xA0-0xD7FF、0xE000-0xFFFD、0x10000-0x10FFFF),遇到真实控制字符
  (C0: 0x00-0x08/0x0B/0x0C/0x0E-0x1F、DEL 0x7F、C1: 0x80-0x84/0x86-0x9F)
  直接报 "yaml: control characters are not allowed"。
  部分订阅源把损坏的 UTF-8 字节写成 "\\x9F" 之类的转义,解析后变成真实控制
  字符 —— 仅靠字节扫描发现不了,必须在解码后的值层面检查。
"""
import argparse
import os
import re
import shutil
import subprocess

import yaml

from sources import SOURCES

REPO = "https://github.com/hkjych/Z"
AUTHOR = "wzmwayne"             # 上游作者
REPO_SLUG = "hkjych/Z"          # 说明节点里只写 owner/repo,不带网址

# 节点名里不允许出现网址/域名(yoyapai.com、https://xxx 之类)。
# 只认"带点的主机名",所以 IPv4(1.2.3.4)、版本号(v1.19.9)不会被误伤。
_URLISH = re.compile(
    r"(?i)(?:https?://|www[.])[^ \t丨|｜,，、]+"
    r"|(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?[.])+[a-z]{2,24}(?:/[^ \t丨|｜,，、]*)?"
)


def _host_head(host) -> str:
    """取网址的首段(去掉协议、www、端口、路径与后缀):yoyapai.com -> yoyapai。"""
    h = str(host)
    low = h.lower()
    for prefix in ("https://", "http://", "www."):
        if low.startswith(prefix):
            h = h[len(prefix):]
            break
    for sep in ("/", "?", "#"):
        h = h.split(sep)[0]
    h = h.split(":")[0]
    return h.split(".")[0] or ""


_BRACKET_PAIRS = {"[": "]", "(": ")", "（": "）", "【": "】"}


def _strip_unbalanced(s: str) -> str:
    """删掉没有配对的括号(网址被删后常会剩半只括号)。"""
    for op, cl in _BRACKET_PAIRS.items():
        while s.count(op) > s.count(cl):
            i = s.rfind(op)
            s = s[:i] + s[i + 1:]
        while s.count(cl) > s.count(op):
            i = s.rfind(cl)
            s = s[:i] + s[i + 1:]
    return s


_NAME_SEPS = " \t-_·,，、/=|" + chr(92)


def clean_proxy_name(name) -> str:
    """删掉节点名里的网址/域名,并清掉因此悬空的分隔符。

    "🇮🇹IT意大利丨yoyapai.com"   -> "🇮🇹IT意大利"
    "🇩🇪DE德国丨yoyapai.com (11)" -> "🇩🇪DE德国丨(11)"
    """
    s = str(name)
    if not _URLISH.search(s):
        return s
    kept = []
    for part in re.split(r"[丨|｜]", s):
        t = _URLISH.sub("", part)
        t = re.sub(r"[ \t]{2,}", " ", t).strip(_NAME_SEPS)
        if t:
            kept.append(t)
    out = "丨".join(kept).strip(_NAME_SEPS)
    out = re.sub(r"丨([（(\[])", r"\1", out)   # "…丨(2)" -> "…(2)",不留悬空分隔符
    out = re.sub(r"[\[(（【]\s*[\])）】]", "", out)      # 删掉被清空后剩下的空括号
    out = _strip_unbalanced(out)
    out = re.sub(r"_{2,}", "_", out)                 # dokng.com 删掉后常留下 "__"
    out = re.sub(r"[丨|｜]{2,}", "丨", out)
    out = re.sub(r"[ \t]{2,}", " ", out).strip(_NAME_SEPS + "：:")
    if out and re.search(r"[0-9A-Za-z\u4e00-\u9fff]", out):
        return out
    # 名字里只剩表情/符号(如 "📦 yoyapai.com")时,退回网址首段,避免出现纯符号名
    head = _host_head(_URLISH.search(s).group(0))
    return head or "节点"


def clean_label(label) -> str:
    """分组/说明用的名称:删网址,但整段都是网址时保留首段(yoyapai.com -> yoyapai)。"""
    s = str(label)
    if not _URLISH.search(s):
        return s
    s = _URLISH.sub(lambda m: _host_head(m.group(0)), s)
    s = re.sub(r"[ \t]{2,}", " ", s).strip()
    return s.strip(_NAME_SEPS) or "节点"


# 浏览器指纹取值(mihomo 的 client-fingerprint);带 chrome-120 之类的版本号也算
_BROWSER_FP_RE = re.compile(
    r"(?i)^(chrome|chromium|firefox|safari|edge|360|qq|ios|android|random|randomized)(-\d+)?$"
)
# TLS 证书固定(pinning)的取值:64 位十六进制 / 冒号分隔的十六进制 / base64
_CERT_PIN_RE = re.compile(
    r"^(?:[0-9A-Fa-f]{64}|(?:[0-9A-Fa-f]{2}:){31}[0-9A-Fa-f]{2}|[A-Za-z0-9+/]{43}=?)$"
)


def normalize_proxy_fields(proxy: dict) -> list:
    """把上游常见的老字段/错字段改成 mihomo 认识的写法,返回修复说明。

    `fingerprint` 在 mihomo 里是 TLS 证书固定,浏览器指纹必须写 `client-fingerprint`;
    取值是 chrome/firefox 之类时直接改名,整个订阅才不会因为一个节点被内核拒绝。
    """
    fixes = []
    name = str(proxy.get("name", "?"))[:24]

    # REALITY 必须开 TLS,否则 mihomo 报 "REALITY requires TLS" 拒绝整份配置
    if proxy.get("reality-opts") and proxy.get("tls") is not True:
        proxy["tls"] = True
        fixes.append(f"{name}: REALITY 补 tls: true")

    # alpn 里有非法码点(上游写坏的 UTF-8):丢掉这个可选字段,别连累整份订阅
    alpn = proxy.get("alpn")
    if isinstance(alpn, list) and any(
        isinstance(x, str) and find_bad_codepoints(x) for x in alpn
    ):
        del proxy["alpn"]
        fixes.append(f"{name}: 丢弃含非法码点的 alpn")

    fp = proxy.get("fingerprint")
    if fp is None:
        return fixes
    value = fp.strip() if isinstance(fp, str) else ""
    if value and _BROWSER_FP_RE.match(value):
        if "client-fingerprint" not in proxy:
            proxy["client-fingerprint"] = value
        del proxy["fingerprint"]
        fixes.append(f"{name}: fingerprint->client-fingerprint({value})")
    elif value and _CERT_PIN_RE.match(value):
        pass                     # 真的是证书固定,原样保留
    else:
        del proxy["fingerprint"]
        fixes.append(f"{name}: 丢弃非法 fingerprint({str(fp)[:16] or '空值'})")
    return fixes


def _rewrite_rule_target(rule: str, rename: dict) -> str:
    """规则出口被改名时同步改写(否则该条规则会变成悬空引用被丢弃)。"""
    target = rule_target(rule)
    if target is None or target not in rename:
        return rule
    parts = split_rule_fields(rule)
    idx = 1 if parts and parts[0].upper() in _NO_PAYLOAD_RULES else 2
    if idx < len(parts):
        parts[idx] = rename[target]
        return ",".join(parts)
    return rule

# go-yaml v3 会把这些字符串解析为非字符串(yaml.v3 resolve.go):
#   显式映射的 bool/null/inf/nan,以及 int/float/timestamp 样式。
_YAML_V3_LITERALS = {
    "true", "True", "TRUE", "false", "False", "FALSE",
    "~", "null", "Null", "NULL",
    ".nan", ".NaN", ".NAN",
    ".inf", ".Inf", ".INF",
    "+.inf", "+.Inf", "+.INF",
    "-.inf", "-.Inf", "-.INF",
    "<<",
}
_YAML_V3_FLOAT = re.compile(r"^[-+]?(\.[0-9]+|[0-9]+(\.[0-9]*)?)([eE][-+]?[0-9]+)?$")
_YAML_V3_TIMESTAMP = re.compile(
    r"^[0-9]{4}-[0-9]{1,2}-[0-9]{1,2}([Tt ]+.*)?$"
)

# mihomo/Clash 的合法顶层键。不在表内且值为标量的键视为上游垃圾(错误页残留),
# 直接剔除;不在表内但值是映射/列表的键保留(可能是新版本配置段)。
KNOWN_TOP_LEVEL_KEYS = {
    "port", "socks-port", "mixed-port", "redir-port", "tproxy-port", "routing-mark",
    "allow-lan", "bind-address", "lan-allowed-ips", "lan-disallowed-ips",
    "authentication", "skip-auth-prefixes", "mode", "log-level", "ipv6",
    "external-controller", "external-controller-cors", "external-controller-tls",
    "external-ui", "external-ui-name", "external-ui-url", "secret",
    "interface-name", "dns", "hosts", "proxies", "proxy-groups", "proxy-providers",
    "rules", "rule-providers", "sub-rules", "listeners", "tun", "tuic-server",
    "sniffer", "sniffing", "ntp", "experimental", "profile", "tunnel", "tls",
    "http", "socks", "script", "geodata-mode", "geodata-loader", "geox-url",
    "geo-auto-update", "geo-update-interval", "geosite-matcher",
    "unified-delay", "tcp-concurrent", "find-process-mode",
    "global-ua", "keep-alive-idle", "keep-alive-interval", "disable-keep-alive",
    "cfw-latency-url", "cfw-latency-type", "cfw-latency-timeout",
    "cfw-conn-break-strategy", "clash-for-android", "url-rewrite",
}

# mihomo 内置的固定出口,不算悬空引用。
BUILTIN_TARGETS = {
    "DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE", "GLOBAL", "PROXY",
}

# 规则类型 -> 目标字段下标。无 payload 的规则目标在第 1 段,其余在第 2 段。
_NO_PAYLOAD_RULES = {"MATCH", "FINAL"}


def yaml_v3_needs_quotes(s: str) -> bool:
    """判断字符串在 go-yaml v3 中是否会被解析为数字/布尔/null 等非字符串。"""
    if s in _YAML_V3_LITERALS:
        return True
    if s == "":
        return False  # PyYAML 对空串输出 '' 引号,本身安全
    plain = s.replace("_", "")
    try:
        int(plain, 0)  # 十进制 / 0x / 0o / 0b
        return True
    except ValueError:
        pass
    try:
        int(plain, 16)
        return True
    except ValueError:
        pass
    if _YAML_V3_FLOAT.match(s):
        try:
            float(plain)
            return True
        except ValueError:
            pass
    if _YAML_V3_TIMESTAMP.match(s):
        return True
    return False


class SafeDumper(yaml.SafeDumper):
    pass


def _represent_str(dumper, data):
    if yaml_v3_needs_quotes(data):
        return dumper.represent_scalar("tag:yaml.org,2002:str", data, style='"')
    return yaml.SafeDumper.represent_str(dumper, data)


SafeDumper.add_representer(str, _represent_str)


def beijing_now():
    from datetime import datetime, timedelta, timezone

    return datetime.now(timezone(timedelta(hours=8))).strftime("%Y-%m-%d %H:%M")


def count_non_ascii(node):
    """统计结构中所有字符串值的非 ASCII 字符数(即会被转译的字符数)。"""
    if isinstance(node, str):
        return sum(1 for c in node if ord(c) > 0x7E)
    if isinstance(node, dict):
        return sum(count_non_ascii(v) for v in node.values())
    if isinstance(node, list):
        return sum(count_non_ascii(v) for v in node)
    return 0


def fake_proxy(name):
    """构造一个承载说明信息的假节点(无法实际使用,仅用于展示说明)。"""
    return {
        "name": name,
        "type": "trojan",
        "server": "127.0.0.1",
        "port": 443,
        "password": "dummy",
        "udp": True,
        "skip-cert-verify": True,
    }


def strip_injected(data):
    """移除上一轮注入的"说明-"假节点与"说明"分组(保证脚本可重复运行)。"""
    proxies = data.get("proxies")
    if isinstance(proxies, list):
        data["proxies"] = [
            p for p in proxies
            if not (isinstance(p, dict) and str(p.get("name", "")).startswith("说明-"))
        ]
    groups = data.get("proxy-groups")
    if isinstance(groups, list):
        data["proxy-groups"] = [
            g for g in groups
            if not (isinstance(g, dict) and g.get("name") == "说明")
        ]


def inject_fake_nodes(data, source_label, dropped_count, escaped_chars, time_str, fixes=0):
    """注入一组"说明-"假节点与"说明"分组,承载来源/清洗结果/时间/仓库。"""
    names = [
        f"说明-来源: {clean_label(source_label)}",
        f"说明-清洗结果: 清理 {dropped_count} 个节点、修复 {fixes} 处引用、转译 {escaped_chars} 个字符",
        f"说明-更新时间: {time_str} (CST)",
        f"说明-作者: {AUTHOR}",
        f"说明-仓库: {REPO_SLUG}",
    ]
    proxies = data.get("proxies")
    if isinstance(proxies, list):
        data["proxies"] = proxies + [fake_proxy(n) for n in names]

    groups = data.get("proxy-groups")
    if isinstance(groups, list):
        data["proxy-groups"] = [{"name": "说明", "type": "select", "proxies": names}] + groups
    else:
        data["proxy-groups"] = [{"name": "说明", "type": "select", "proxies": names}]


def is_allowed(cp: int) -> bool:
    """go-yaml v3 允许的码点白名单(yaml.v3 readerc.go 的检查逻辑)。"""
    return (
        cp in (0x09, 0x0A, 0x0D)
        or 0x20 <= cp <= 0x7E
        or cp == 0x85
        or 0xA0 <= cp <= 0xD7FF
        or 0xE000 <= cp <= 0xFFFD
        or 0x10000 <= cp <= 0x10FFFF
    )


def find_bad_codepoints(text: str):
    """返回文本中所有非法码点(去重)。"""
    return sorted({ord(c) for c in text if not is_allowed(ord(c))})


def check_values(node, path=""):
    """递归检查结构中的所有字符串值,返回违规位置列表 [(path, codepoints)]。"""
    violations = []
    if isinstance(node, dict):
        for k, v in node.items():
            child = f"{path}.{k}" if path else str(k)
            if isinstance(v, str):
                bad = find_bad_codepoints(v)
                if bad:
                    violations.append((child, bad))
            else:
                violations.extend(check_values(v, child))
    elif isinstance(node, list):
        for i, v in enumerate(node):
            child = f"{path}[{i}]"
            if isinstance(v, str):
                bad = find_bad_codepoints(v)
                if bad:
                    violations.append((child, bad))
            else:
                violations.extend(check_values(v, child))
    return violations


def deep_clean(node, removed=None):
    """递归剔除结构中的违规字符串:dict 删键、list 剔除元素,返回清理后的结构。"""
    if removed is None:
        removed = []
    if isinstance(node, dict):
        result = {}
        for k, v in node.items():
            if isinstance(v, str):
                if find_bad_codepoints(v):
                    removed.append(str(k))
                    continue
                result[k] = v
            else:
                result[k] = deep_clean(v, removed)
        return result
    if isinstance(node, list):
        result = []
        for v in node:
            if isinstance(v, str):
                if find_bad_codepoints(v):
                    removed.append(v[:40])
                    continue
                result.append(v)
            else:
                result.append(deep_clean(v, removed))
        return result
    return node


# mihomo 1.19.x 起移除的顶层配置:保留会被内核直接判为错误
REMOVED_TOP_KEYS = {"global-client-fingerprint"}


def drop_junk_keys(data):
    """剔除上游错误页残留的标量顶层键(如 "error code: 520")。"""
    dropped, kept_unknown = [], []
    for k in list(data.keys()):
        if k in REMOVED_TOP_KEYS:
            dropped.append((k, "mihomo 已移除,改在各节点上写 client-fingerprint"))
            del data[k]
            continue
        if k in KNOWN_TOP_LEVEL_KEYS:
            continue
        if isinstance(data[k], (dict, list)):
            kept_unknown.append(k)  # 未知配置段:保留,仅提示
        else:
            dropped.append((k, data[k]))
            del data[k]
    return dropped, kept_unknown


def split_rule_fields(rule: str):
    """按顶层逗号切分规则(括号内的逗号不算)。"""
    parts, buf, depth = [], [], 0
    for ch in rule:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth = max(0, depth - 1)
        if ch == "," and depth == 0:
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    parts.append("".join(buf))
    return [p.strip() for p in parts]


def rule_target(rule: str):
    """返回规则的出口目标名;无法判断时返回 None(不做检查)。"""
    if not isinstance(rule, str) or not rule.strip():
        return None
    parts = split_rule_fields(rule)
    if len(parts) < 2:
        return None
    rtype = parts[0].upper()
    if rtype in _NO_PAYLOAD_RULES:
        return parts[1] or None
    if len(parts) >= 3:
        return parts[2] or None
    return None


def unique_names(data):
    """保证节点名/组名全局唯一(mihomo 对重名直接拒绝加载整份配置)。"""
    proxies = data.get("proxies")
    groups = data.get("proxy-groups")
    proxies = proxies if isinstance(proxies, list) else []
    groups = groups if isinstance(groups, list) else []

    group_names = set()
    cleaned_groups = []
    dropped_groups = []
    for g in groups:
        if not isinstance(g, dict):
            continue
        name = str(g.get("name", "") or "")
        if not name or name in group_names:
            dropped_groups.append(name or "<空>")
            continue
        group_names.add(name)
        cleaned_groups.append(g)

    seen = set(group_names)  # 节点名不能与组名相同
    renamed_nodes = []
    dropped_nodes = []
    cleaned_proxies = []
    for p in proxies:
        if not isinstance(p, dict):
            continue
        name = str(p.get("name", "") or "")
        if not name:
            dropped_nodes.append("<空>")
            continue
        if name in seen:
            base, i = name, 2
            while f"{base} #{i}" in seen:
                i += 1
            new_name = f"{base} #{i}"
            p = dict(p, name=new_name)
            renamed_nodes.append((name, new_name))
            name = new_name
        seen.add(name)
        cleaned_proxies.append(p)

    data["proxies"] = cleaned_proxies
    data["proxy-groups"] = cleaned_groups
    return dropped_nodes, dropped_groups, renamed_nodes


def repair_references(data):
    """修复丢弃节点/分组后产生的悬空引用(group->*, rule->目标)。"""
    proxies = data.get("proxies") or []
    groups = data.get("proxy-groups") or []
    valid = {str(p.get("name")) for p in proxies if isinstance(p, dict)}
    valid |= {str(g.get("name")) for g in groups if isinstance(g, dict)}
    valid |= BUILTIN_TARGETS

    fixes = []
    for g in groups:
        refs = g.get("proxies")
        if not isinstance(refs, list):
            continue
        kept = []
        for r in refs:
            if isinstance(r, str) and r in valid:
                kept.append(r)
            else:
                fixes.append(f"{g.get('name')}->{r}")
        if not kept and not g.get("use"):
            kept = ["DIRECT"]
            fixes.append(f"{g.get('name')}->空分组补 DIRECT")
        g["proxies"] = kept

    rules = data.get("rules")
    if isinstance(rules, list):
        kept_rules = []
        for r in rules:
            target = rule_target(r) if isinstance(r, str) else None
            if target is not None and target not in valid:
                fixes.append(f"rule:{target}")
                continue
            kept_rules.append(r)
        data["rules"] = kept_rules
    return fixes


def mihomo_test(config_path, mihomo_bin, workdir, timeout=120):
    """用 mihomo 内核 `-t` 校验配置,返回 (是否通过, 关键输出)。"""
    os.makedirs(workdir, exist_ok=True)
    try:
        proc = subprocess.run(
            [mihomo_bin, "-t", "-d", workdir, "-f", config_path],
            capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return False, f"mihomo -t 超时(>{timeout}s)"
    out = (proc.stdout or "") + (proc.stderr or "")
    ok = "test is successful" in out
    lines = [ln for ln in out.splitlines() if "level=error" in ln or "test is" in ln]
    return ok, " | ".join(lines[-2:]) if lines else out.strip()[-200:]


def clean_yaml(src, dst, source, gate=False, mihomo_bin=None, mihomo_dir=None):
    if source not in SOURCES:
        raise SystemExit(f"[FAIL] 未知来源: {source} (可选: {', '.join(SOURCES)})")
    source_label, source_url = SOURCES[source]

    with open(src, "rb") as f:
        raw = f.read()
    try:
        data = yaml.safe_load(raw)
    except Exception as e:
        raise SystemExit(f"[FAIL] {src} YAML 解析失败: {e}") from e
    if data is None:
        raise SystemExit(f"[FAIL] {src} 解析结果为空")
    if not isinstance(data, dict):
        raise SystemExit(f"[FAIL] {src} 顶层不是映射")

    # 0) 移除上一轮注入的说明节点,保证可重复运行
    strip_injected(data)

    dropped_nodes, dropped_groups, renamed_nodes = [], [], []
    dropped_rules = 0
    dropped_other = []

    # 1) 垃圾顶层键(上游错误页残留)
    junk_keys, unknown_keys = drop_junk_keys(data)

    # 2) 清洗 proxies:任一字段含非法码点则丢弃整个节点
    if isinstance(data.get("proxies"), list):
        cleaned = []
        for p in data["proxies"]:
            if not isinstance(p, dict):
                continue
            bad = [k for k, v in p.items() if isinstance(v, str) and find_bad_codepoints(v)]
            if bad:
                dropped_nodes.append((p.get("name", "?"), bad))
                continue
            # hysteria2 配了 obfs 却没有 obfs-password:mihomo 报 "missing obfs password"
            # 拒绝加载整份配置,而这种节点本身也连不上,直接丢弃
            if str(p.get("type", "")).lower().startswith("hysteria") and p.get("obfs") \
                    and not p.get("obfs-password"):
                dropped_nodes.append((p.get("name", "?"), ["missing obfs password"]))
                continue
            cleaned.append(p)
        data["proxies"] = cleaned
    else:
        raise SystemExit(f"[FAIL] {src} 缺少 proxies 列表")

    if not data["proxies"]:
        raise SystemExit(f"[FAIL] {src} 清洗后没有任何节点,疑似上游返回错误内容")

    dropped_names = {name for name, _ in dropped_nodes}

    # 2.4) 字段规范化:老字段/错字段改成 mihomo 认识的写法(否则单个节点就能让门禁红)
    field_fixes = []
    for p in data["proxies"]:
        if isinstance(p, dict):
            field_fixes.extend(normalize_proxy_fields(p))

    # 2.5) 名称去网址:节点名彻底删掉域名,分组名退化成首段,并同步改写引用
    rename = {}
    for p in data["proxies"]:
        old = str(p.get("name", "") or "")
        new = clean_proxy_name(old)
        if new != old:
            rename[old] = new
            p["name"] = new
    for g in data.get("proxy-groups") or []:
        if not isinstance(g, dict):
            continue
        old = str(g.get("name", "") or "")
        new = clean_label(old)
        if new != old:
            rename.setdefault(old, new)
            g["name"] = new
    if rename:
        for g in data.get("proxy-groups") or []:
            if not isinstance(g, dict):
                continue
            refs = g.get("proxies")
            if isinstance(refs, list):
                g["proxies"] = [rename.get(r, r) if isinstance(r, str) else r for r in refs]
        if isinstance(data.get("rules"), list):
            data["rules"] = [
                _rewrite_rule_target(r, rename) if isinstance(r, str) else r
                for r in data["rules"]
            ]

    # 3) 清洗 proxy-groups:剔除引用已删节点的项;组字段含非法码点则丢组
    if isinstance(data.get("proxy-groups"), list):
        cleaned = []
        for g in data["proxy-groups"]:
            if not isinstance(g, dict):
                continue
            bad = [k for k, v in g.items() if isinstance(v, str) and find_bad_codepoints(v)]
            if bad:
                dropped_groups.append((g.get("name", "?"), bad))
                continue
            refs = g.get("proxies")
            if isinstance(refs, list):
                g["proxies"] = [r for r in refs if r not in dropped_names]
            cleaned.append(g)
        data["proxy-groups"] = cleaned

    # 4) 清洗 rules:剔除含非法码点的行
    if isinstance(data.get("rules"), list):
        cleaned = [r for r in data["rules"] if not (isinstance(r, str) and find_bad_codepoints(r))]
        dropped_rules = len(data["rules"]) - len(cleaned)
        data["rules"] = cleaned

    # 5) 清洗其余顶层字段:嵌套结构中的违规字符串一律剔除
    for k, v in list(data.items()):
        if k in ("proxies", "proxy-groups", "rules"):
            continue
        if isinstance(v, str) and find_bad_codepoints(v):
            dropped_other.append((k, find_bad_codepoints(v)))
            del data[k]
        else:
            removed = []
            data[k] = deep_clean(v, removed)
            if removed:
                dropped_other.append((k, removed[:5]))

    # 6) 名称唯一性 + 悬空引用修复(否则 mihomo 拒绝加载整份配置)
    dup_nodes, dup_groups, renamed_nodes = unique_names(data)
    fixes = repair_references(data)

    # 7) 统计清洗结果,注入"说明-"假节点与"说明"分组
    escaped_chars = count_non_ascii(data)
    inject_fake_nodes(
        data, source_label,
        dropped_count=len(dropped_nodes) + len(dup_nodes),
        escaped_chars=escaped_chars,
        time_str=beijing_now(),
        fixes=len(fixes),
    )

    # 8) 输出为纯 ASCII YAML(非 ASCII 全部转义;避免语义漂移)
    out = yaml.dump(
        data,
        Dumper=SafeDumper,
        allow_unicode=False,
        default_flow_style=False,
        sort_keys=False,
    ).encode("utf-8")

    # 9) 二次校验:重新解析输出,值层面必须零违规
    violations = check_values(yaml.safe_load(out))
    if violations:
        raise SystemExit(f"[FAIL] {dst} 清洗后仍含非法码点: {violations[:5]}")

    # 10) 先写临时文件,内核门禁通过后再原子替换,保证已发布文件永不倒退
    tmp = dst + ".tmp"
    with open(tmp, "wb") as f:
        f.write(out)
    if gate:
        ok, detail = mihomo_test(tmp, mihomo_bin, mihomo_dir or os.path.dirname(os.path.abspath(tmp)))
        if not ok:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise SystemExit(f"[FAIL] {src} 未通过 mihomo 内核校验,拒绝发布: {detail}")
    os.replace(tmp, dst)

    total = len(dropped_nodes) + len(dup_nodes) + len(dropped_groups) + len(dup_groups) \
        + dropped_rules + len(dropped_other) + len(junk_keys) + len(fixes) + len(rename) + len(field_fixes)
    print(f"[OK] {src} -> {dst} (来源: {source_label})")
    print(f"     节点: 丢弃 {len(dropped_nodes)} 个(控制字符)、{len(dup_nodes)} 个(无名/重复)")
    if dropped_names:
        print(f"     被丢弃节点示例: {[n for n, _ in dropped_nodes][:5]}")
    if renamed_nodes:
        print(f"     重命名冲突节点 {len(renamed_nodes)} 个: {renamed_nodes[:3]}")
    if rename:
        print(f"     名称去网址 {len(rename)} 个: {list(rename.items())[:3]}")
    if field_fixes:
        print(f"     字段规范化 {len(field_fixes)} 处: {field_fixes[:3]}")
    if dropped_groups:
        print(f"     分组: 丢弃 {len(dropped_groups)} 个(控制字符)")
    if dup_groups:
        print(f"     分组: 丢弃 {len(dup_groups)} 个(重复/无名)")
    if dropped_rules:
        print(f"     rules: 剔除 {dropped_rules} 条(控制字符)")
    if fixes:
        print(f"     引用修复 {len(fixes)} 处: {fixes[:5]}")
    if junk_keys:
        print(f"     垃圾顶层键: 剔除 {junk_keys}")
    if unknown_keys:
        print(f"     未知配置段(保留): {unknown_keys}")
    if dropped_other:
        print(f"     其他: 剔除 {len(dropped_other)} 项: {dropped_other[:5]}")
    print(f"     转译非 ASCII 字符: {escaped_chars} 个")
    if gate:
        print("     内核门禁: mihomo -t 通过")
    if total == 0:
        print("     无需清洗,已原样重编码")


def main():
    ap = argparse.ArgumentParser(description="清洗 Clash 订阅 YAML(控制字符/重名/悬空引用)并注入说明节点")
    ap.add_argument("src")
    ap.add_argument("dst")
    ap.add_argument("--source", required=True, choices=list(SOURCES), help="订阅来源标识")
    ap.add_argument("--gate", action="store_true", help="发布前用 mihomo -t 校验")
    ap.add_argument("--mihomo", default=os.environ.get("MIHOMO_BIN", "mihomo"), help="mihomo 内核路径")
    ap.add_argument("--mihomo-dir", default=os.environ.get("MIHOMO_DIR", ""), help="mihomo 工作目录(复用地理库缓存)")
    args = ap.parse_args()

    if args.gate and not (os.path.isfile(args.mihomo) or shutil.which(args.mihomo)):
        raise SystemExit(f"[FAIL] 找不到 mihomo 内核: {args.mihomo}(可用 --mihomo 指定)")
    clean_yaml(args.src, args.dst, args.source,
               gate=args.gate, mihomo_bin=args.mihomo, mihomo_dir=args.mihomo_dir or None)


if __name__ == "__main__":
    main()
