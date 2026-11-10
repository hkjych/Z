#!/usr/bin/env python3
"""把 AIO 的 clash.yaml 转成 sing-box 的 box.json（放在同目录）。

只做「协议/分组/规则」的等价翻译，不做测速、不改节点名：

* 节点：ss / vmess / vless / trojan / hysteria / hysteria2 / tuic / anytls /
  http / socks5 / wireguard 逐条映射；ssr、mieru 以及 sing-box 没有的
  老式 vmess（alterId≠0）会被跳过，并在结束时汇总原因。
* 分组：select → selector，url-test / fallback / load-balance → urltest，
  include-all-proxies + filter 在这里展开成真实成员列表。
* 规则：GEOIP,CN / MATCH 等常见写法翻译成 sing-box 1.14 的规则；
  sing-box 1.14 已去掉内置 geoip 规则，改用远程 geoip-cn 规则集。

用法：
  python scripts/clash_to_singbox.py output/aio/clash.yaml -o output/aio/box.json
  python scripts/clash_to_singbox.py output/aio-all/clash.yaml   # 默认同名 box.json
"""

import argparse
import ipaddress
import json
import os
import re
import sys
from collections import Counter

import yaml

# ---------------------------------------------------------------- 常量表

# shadowsocks 支持的加密方式（sing-box 1.14 的 method 枚举）
SS_METHODS = {
    "none", "aes-128-gcm", "aes-192-gcm", "aes-256-gcm",
    "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305",
    "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
    "aes-128-ctr", "aes-192-ctr", "aes-256-ctr",
    "aes-128-cfb", "aes-192-cfb", "aes-256-cfb",
    "rc4-md5", "chacha20-ietf", "xchacha20",
}

# utls 指纹白名单
UTLS_FINGERPRINTS = {
    "chrome", "firefox", "edge", "safari", "360", "qq", "ios", "android",
    "random", "randomized", "chrome_psk", "chrome_psk_shuffle",
    "chrome_padding_psk_shuffle", "chrome_pq", "chrome_pq_psk",
}

# sing-box 1.14 已没有的节点类型
UNSUPPORTED_TYPES = {"ssr", "mieru", "snell", "juicity", "naive+quic", "tor"}

GEOIP_RULESET_URL = (
    "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs"
)


class Unsupported(Exception):
    """单个节点无法翻译，跳过它但不影响整份配置。"""


def is_ip(value):
    try:
        ipaddress.ip_address(str(value))
        return True
    except ValueError:
        return False


def first(*values):
    for v in values:
        if v not in (None, "", [], {}):
            return v
    return None


def need(p, key, default=None):
    v = p.get(key, default)
    if v in (None, ""):
        raise Unsupported("缺少 %s" % key)
    return v


# ---------------------------------------------------------------- TLS / 传输层

def build_tls(p, force=False):
    """mihomo 的 tls 相关字段 → sing-box OutboundTLSOptions。"""
    enabled = force or bool(p.get("tls")) or bool(p.get("reality-opts"))
    if not enabled:
        return None

    tls = {"enabled": True}
    sni = first(p.get("servername"), p.get("sni"), p.get("peer"))
    if not sni:
        host = str(p.get("server") or "")
        if host and not is_ip(host):
            sni = host
    if sni:
        tls["server_name"] = str(sni)
    if p.get("skip-cert-verify"):
        tls["insecure"] = True
    if p.get("disable-sni"):
        tls["disable_sni"] = True
    if p.get("alpn"):
        tls["alpn"] = [str(a) for a in p["alpn"]]

    reality = p.get("reality-opts") or {}
    if reality.get("public-key"):
        block = {"enabled": True, "public_key": str(reality["public-key"])}
        if reality.get("short-id") not in (None, ""):
            block["short_id"] = str(reality["short-id"])
        tls["reality"] = block

    fp = str(p.get("client-fingerprint") or "").lower()
    if fp:
        tls["utls"] = {"enabled": True,
                       "fingerprint": fp if fp in UTLS_FINGERPRINTS else "chrome"}
    # reality 必须配 uTLS，缺指纹时补默认的 chrome
    if "reality" in tls and "utls" not in tls:
        tls["utls"] = {"enabled": True, "fingerprint": "chrome"}
    return tls


def build_transport(p):
    """mihomo 的 network + *-opts → sing-box V2RayTransport。"""
    # 订阅里常见 "tcp#备注"、"raw"（v2ray 的裸 TCP）这类写法，先归一化
    net = str(p.get("network") or "").lower().split("#")[0].split("?")[0].strip()
    if net in ("", "tcp", "none", "raw"):
        return None

    if net == "ws":
        opts = p.get("ws-opts") or {}
        out = {"type": "ws"}
        if opts.get("path"):
            out["path"] = str(opts["path"])
        headers = opts.get("headers") or {}
        if headers:
            out["headers"] = {str(k): str(v) for k, v in headers.items()}
        if opts.get("max-early-data"):
            out["max_early_data"] = int(opts["max-early-data"])
        if opts.get("early-data-header-name"):
            out["early_data_header_name"] = str(opts["early-data-header-name"])
        return out

    if net == "grpc":
        opts = p.get("grpc-opts") or {}
        out = {"type": "grpc"}
        name = first(opts.get("grpc-service-name"), opts.get("serviceName"))
        if name:
            out["service_name"] = str(name)
        return out

    if net in ("h2", "http"):
        opts = p.get("h2-opts") or p.get("http-opts") or {}
        out = {"type": "http"}
        host = opts.get("host") or opts.get("Host")
        if isinstance(host, str):
            out["host"] = [host]
        elif isinstance(host, list):
            out["host"] = [str(h) for h in host]
        path = opts.get("path")
        if isinstance(path, list) and path:
            path = path[0]
        if path:
            out["path"] = str(path)
        return out

    if net == "httpupgrade":
        opts = p.get("ws-opts") or {}
        out = {"type": "httpupgrade"}
        if opts.get("path"):
            out["path"] = str(opts["path"])
        headers = opts.get("headers") or {}
        host = headers.get("Host") or headers.get("host")
        if host:
            out["host"] = str(host)
        return out

    raise Unsupported("不支持的传输 %s" % net)


def ports_of(p):
    """mihomo 的 ports/port 写法 → sing-box 的 server_ports（"a:b" 区间）。"""
    raw = first(p.get("ports"), p.get("port"))
    if raw in (None, ""):
        return None
    if isinstance(raw, int):
        return [str(raw)]
    raw = str(raw).strip()
    if not raw:
        return None
    parts = []
    for item in re.split(r"[,\s]+", raw):
        if not item:
            continue
        parts.append(item.replace("-", ":"))
    return parts or None


def mbps(value):
    """'55 Mbps' / '55' / 55 → 整数 Mbps。"""
    if value in (None, ""):
        return None
    m = re.search(r"\d+(?:\.\d+)?", str(value))
    if not m:
        return None
    return int(float(m.group(0)))


# ---------------------------------------------------------------- 各协议转换

def conv_ss(p):
    method = str(p.get("cipher") or "").lower()
    if method not in SS_METHODS:
        raise Unsupported("ss 加密方式 %s" % (method or "空"))
    out = {
        "type": "shadowsocks",
        "server": str(need(p, "server")),
        "server_port": int(need(p, "port")),
        "method": method,
        "password": str(p.get("password") or ""),
    }
    plugin = str(p.get("plugin") or "").lower()
    opts = p.get("plugin-opts") or {}
    if plugin == "obfs":
        bits = ["obfs=%s" % str(opts.get("mode") or "http")]
        if opts.get("host"):
            bits.append("obfs-host=%s" % opts["host"])
        out["plugin"] = "obfs-local"
        out["plugin_opts"] = ";".join(bits)
    elif plugin == "v2ray-plugin":
        bits = ["mode=websocket"]
        if opts.get("tls"):
            bits.append("tls")
        if opts.get("host"):
            bits.append("host=%s" % opts["host"])
        bits.append("path=%s" % (opts.get("path") or "/"))
        if opts.get("mux"):
            bits.append("mux=1")
        out["plugin"] = "v2ray-plugin"
        out["plugin_opts"] = ";".join(bits)
    elif plugin:
        raise Unsupported("ss 插件 %s" % plugin)
    return out


def conv_vmess(p):
    alter = p.get("alterId", p.get("alter-id", 0)) or 0
    try:
        alter = int(alter)
    except (TypeError, ValueError):
        alter = 0
    if alter:
        raise Unsupported("vmess alterId=%d（非 AEAD）" % alter)
    out = {
        "type": "vmess",
        "server": str(need(p, "server")),
        "server_port": int(need(p, "port")),
        "uuid": str(need(p, "uuid")),
        "security": str(p.get("cipher") or "auto"),
        "alter_id": 0,
    }
    transport = build_transport(p)
    if transport:
        out["transport"] = transport
    tls = build_tls(p)
    if tls:
        out["tls"] = tls
    if p.get("packet-encoding") in ("xudp", "packetaddr"):
        out["packet_encoding"] = p["packet-encoding"]
    return out


def conv_vless(p):
    out = {
        "type": "vless",
        "server": str(need(p, "server")),
        "server_port": int(need(p, "port")),
        "uuid": str(need(p, "uuid")),
    }
    flow = str(p.get("flow") or "")
    if flow == "xtls-rprx-vision":
        out["flow"] = flow
    transport = build_transport(p)
    if transport:
        out["transport"] = transport
    tls = build_tls(p)
    if tls:
        out["tls"] = tls
    if p.get("packet-encoding") in ("xudp", "packetaddr"):
        out["packet_encoding"] = p["packet-encoding"]
    return out


def conv_trojan(p):
    out = {
        "type": "trojan",
        "server": str(need(p, "server")),
        "server_port": int(need(p, "port")),
        "password": str(need(p, "password")),
        "tls": build_tls(p, force=True),
    }
    transport = build_transport(p)
    if transport:
        out["transport"] = transport
    return out


def conv_hysteria2(p):
    out = {
        "type": "hysteria2",
        "server": str(need(p, "server")),
        "server_port": int(need(p, "port")),
        "password": str(p.get("password") or p.get("auth") or ""),
        "tls": build_tls(p, force=True),
    }
    up, down = mbps(p.get("up")), mbps(p.get("down"))
    if up:
        out["up_mbps"] = up
    if down:
        out["down_mbps"] = down
    obfs = str(p.get("obfs") or "")
    if obfs:
        out["obfs"] = {"type": obfs}
        if p.get("obfs-password"):
            out["obfs"]["password"] = str(p["obfs-password"])
    extra_ports = ports_of(p)
    if extra_ports and len(extra_ports) > 1:
        out["server_ports"] = extra_ports
    return out


def conv_hysteria(p):
    out = {
        "type": "hysteria",
        "server": str(need(p, "server")),
        "server_port": int(need(p, "port")),
        "tls": build_tls(p, force=True),
    }
    auth = first(p.get("auth-str"), p.get("auth"), p.get("auth_str"))
    if auth:
        out["auth_str"] = str(auth)
    obfs = str(p.get("obfs") or "")
    if obfs:
        out["obfs"] = obfs
    up, down = mbps(p.get("up")), mbps(p.get("down"))
    if up:
        out["up_mbps"] = up
    if down:
        out["down_mbps"] = down
    extra_ports = ports_of(p)
    if extra_ports and len(extra_ports) > 1:
        out["server_ports"] = extra_ports
    return out


def conv_tuic(p):
    out = {
        "type": "tuic",
        "server": str(need(p, "server")),
        "server_port": int(need(p, "port")),
        "uuid": str(need(p, "uuid")),
        "password": str(p.get("password") or ""),
        "tls": build_tls(p, force=True),
    }
    cc = str(p.get("congestion-controller") or "").lower()
    if cc in ("cubic", "new_reno", "bbr"):
        out["congestion_control"] = cc
    mode = str(p.get("udp-relay-mode") or "").lower()
    if mode in ("native", "quic"):
        out["udp_relay_mode"] = mode
    hb = p.get("heartbeat-interval")
    if hb not in (None, ""):
        try:
            out["heartbeat"] = "%dms" % int(float(hb))
        except (TypeError, ValueError):
            pass
    return out


def conv_anytls(p):
    return {
        "type": "anytls",
        "server": str(need(p, "server")),
        "server_port": int(need(p, "port")),
        "password": str(need(p, "password")),
        "tls": build_tls(p, force=True),
    }


def conv_http(p):
    out = {
        "type": "http",
        "server": str(need(p, "server")),
        "server_port": int(need(p, "port")),
    }
    if p.get("username"):
        out["username"] = str(p["username"])
    if p.get("password"):
        out["password"] = str(p["password"])
    tls = build_tls(p)
    if tls:
        out["tls"] = tls
    return out


def conv_socks(p):
    out = {
        "type": "socks",
        "server": str(need(p, "server")),
        "server_port": int(need(p, "port")),
        "version": "5",
    }
    if p.get("username"):
        out["username"] = str(p["username"])
    if p.get("password"):
        out["password"] = str(p["password"])
    tls = build_tls(p)
    if tls:
        out["tls"] = tls
    return out


def conv_wireguard(p):
    """mihomo 的单 peer wireguard → sing-box endpoint。"""
    private_key = str(need(p, "private-key"))
    public_key = first(p.get("public-key"), (p.get("peers") or [{}])[0].get("public-key"))
    if not public_key:
        raise Unsupported("wireguard 缺少 public-key")

    address = []
    for key in ("ip", "ipv6"):
        value = p.get(key)
        if not value:
            continue
        for item in (value if isinstance(value, list) else [value]):
            item = str(item).strip()
            if item and "/" not in item:
                item += "/128" if ":" in item else "/32"
            if item:
                address.append(item)
    if not address:
        raise Unsupported("wireguard 缺少本地地址 ip/ipv6")

    peer = {
        "address": str(need(p, "server")),
        "port": int(need(p, "port")),
        "public_key": str(public_key),
        "allowed_ips": ["0.0.0.0/0", "::/0"],
    }
    if p.get("reserved"):
        peer["reserved"] = [int(x) for x in p["reserved"]]
    if p.get("pre-shared-key"):
        peer["pre_shared_key"] = str(p["pre-shared-key"])
    keepalive = first(p.get("persistent-keepalive"), p.get("keepalive"))
    if keepalive not in (None, "", 0, "0"):
        try:
            peer["persistent_keepalive_interval"] = int(float(keepalive))
        except (TypeError, ValueError):
            pass

    out = {
        "type": "wireguard",
        "address": address,
        "private_key": private_key,
        "peers": [peer],
    }
    if p.get("mtu"):
        out["mtu"] = int(p["mtu"])
    return out


CONVERTERS = {
    "ss": conv_ss,
    "vmess": conv_vmess,
    "vless": conv_vless,
    "trojan": conv_trojan,
    "hysteria2": conv_hysteria2,
    "hysteria": conv_hysteria,
    "tuic": conv_tuic,
    "anytls": conv_anytls,
    "http": conv_http,
    "socks5": conv_socks,
    "wireguard": conv_wireguard,
}


# ---------------------------------------------------------------- 分组 / 规则

SPECIAL_TAGS = {"DIRECT": "direct", "REJECT": "block", "REJECT-DROP": "block"}


def expand_members(group, tag, proxy_tags, name_map):
    """展开分组成员：显式列表 + include-all-proxies/filter（mihomo 的两种写法）。"""
    members = []
    for name in group.get("proxies") or []:
        key = str(name).strip()
        target = name_map.get(key) or SPECIAL_TAGS.get(key.upper())
        if target and target != tag and target not in members:
            members.append(target)

    if group.get("include-all") or group.get("include-all-proxies"):
        pattern = group.get("filter")
        exclude = group.get("exclude-filter")
        try:
            include_re = re.compile(pattern) if pattern else None
            exclude_re = re.compile(exclude) if exclude else None
        except re.error:
            include_re = exclude_re = None
        for name in proxy_tags:
            if include_re and not include_re.search(name):
                continue
            if exclude_re and exclude_re.search(name):
                continue
            if name not in members:
                members.append(name)

    # 去重后仍为空时给 direct 兜底，避免 sing-box 报空分组
    return members or ["direct"]


def build_groups(clash, proxy_tags, name_map):
    """mihomo proxy-groups → sing-box selector / urltest。

    分两遍：先给所有分组定好 tag（分组之间会互相引用），再解析成员。
    """
    plan, used = [], set(name_map.values())
    for group in clash.get("proxy-groups") or []:
        name = str(group.get("name") or "").strip()
        if not name:
            continue
        tag = name
        while tag in used:                      # 与节点名撞车时加后缀
            tag += " ·"
        used.add(tag)
        name_map[name] = tag
        plan.append((group, tag))

    groups = []
    for group, tag in plan:
        members = expand_members(group, tag, proxy_tags, name_map)
        gtype = str(group.get("type") or "select").lower()

        if gtype in ("url-test", "fallback", "load-balance"):
            out = {"type": "urltest", "tag": tag, "outbounds": members}
            url = group.get("url")
            if url:
                out["url"] = str(url)
            interval = group.get("interval")
            if interval:
                try:
                    out["interval"] = "%ds" % int(interval)
                except (TypeError, ValueError):
                    pass
            tolerance = group.get("tolerance")
            if tolerance is not None:
                try:
                    out["tolerance"] = int(tolerance)
                except (TypeError, ValueError):
                    pass
        else:
            out = {"type": "selector", "tag": tag, "outbounds": members}
            out["default"] = members[0]

        groups.append(out)

    return groups


def translate_rules(clash, mapping, master, geoip="off"):
    """mihomo 的 rules → sing-box route 规则（只翻译常见几种）。

    geoip="off" 时整条 GEOIP,CN 规则会被丢掉：sing-box 1.14 只能靠远程
    geoip-cn 规则集做这件事，而规则集下载失败会直接让进程起不来，
    所以默认不写，改成让所有流量走总模式；需要分流时用 --geoip remote。
    """
    rules, geoip_used = [], False

    for raw in clash.get("rules") or []:
        if not isinstance(raw, str) or not raw.strip():
            continue
        parts = [x.strip() for x in raw.split(",")]
        kind = parts[0].upper()

        if kind in ("MATCH", "FINAL"):
            target = parts[1] if len(parts) > 1 else ""
            master = mapping.get(target, master)
            continue

        if len(parts) < 3:
            continue
        value, target = parts[1], parts[2]
        outbound = mapping.get(target)
        if outbound is None:
            if target.upper() == "DIRECT":
                outbound = "direct"
            elif target.upper() in ("REJECT", "REJECT-DROP"):
                outbound = "block"
            else:
                continue

        if kind == "GEOIP":
            if value.upper() != "CN" or geoip == "off":
                continue
            geoip_used = True
            rules.append({"rule_set": ["geoip-cn"], "action": "route",
                          "outbound": outbound})
        elif kind == "DOMAIN-SUFFIX":
            rules.append({"domain_suffix": [value], "action": "route",
                          "outbound": outbound})
        elif kind == "DOMAIN":
            rules.append({"domain": [value], "action": "route",
                          "outbound": outbound})
        elif kind in ("DOMAIN-KEYWORD", "DOMAIN-REGEX"):
            key = "domain_keyword" if kind == "DOMAIN-KEYWORD" else "domain_regex"
            rules.append({key: [value], "action": "route", "outbound": outbound})
        elif kind in ("IP-CIDR", "IP-CIDR6"):
            rules.append({"ip_cidr": [value], "action": "route",
                          "outbound": outbound})

    return rules, geoip_used, master


# ---------------------------------------------------------------- 组装配置

def build_config(clash, mixed_port=None, api_port=9090, tun=True, geoip="off"):
    proxies = clash.get("proxies") or []
    stats = Counter()
    skipped = Counter()

    outbounds, endpoints = [], []
    name_map = {}          # mihomo 名字 → sing-box tag
    proxy_tags = []        # 转换成功的节点 tag（顺序同原文件）
    used = set()

    for p in proxies:
        name = str(p.get("name") or "").strip()
        if not name:
            skipped["无名节点"] += 1
            continue
        ptype = str(p.get("type") or "").lower()
        tag = name
        while tag in used:
            tag = tag + " ·"
        used.add(tag)

        if ptype in UNSUPPORTED_TYPES:
            skipped[ptype] += 1
            continue
        conv = CONVERTERS.get(ptype)
        if conv is None:
            skipped[ptype or "未知"] += 1
            continue
        try:
            body = conv(p)
        except Unsupported as e:
            skipped["%s: %s" % (ptype, e)] += 1
            continue
        except Exception as e:                    # 单条脏数据不该炸整份配置
            skipped["%s: %r" % (ptype, e)] += 1
            continue

        body["tag"] = tag
        name_map[name] = tag
        if ptype == "wireguard":
            endpoints.append(body)
        else:
            outbounds.append(body)
        proxy_tags.append(tag)
        stats[ptype] += 1

    groups = build_groups(clash, proxy_tags, name_map)
    group_map = name_map

    master = None
    for group in clash.get("proxy-groups") or []:
        if str(group.get("type") or "").lower() == "select" and master is None:
            master = group_map.get(str(group.get("name")))
    master = master or (groups[0]["tag"] if groups else "direct")

    # direct / block 永远存在，供分组与规则引用
    outbounds.append({"type": "direct", "tag": "direct"})
    outbounds.append({"type": "block", "tag": "block"})
    outbounds.extend(groups)

    rules, geoip_used, final = translate_rules(clash, group_map, master, geoip)

    port = mixed_port or int(clash.get("mixed-port") or 7890)
    inbounds = []
    if tun:
        inbounds.append({
            "type": "tun",
            "tag": "tun-in",
            "address": ["172.19.0.1/30", "fdfe:dcba:9876::1/126"],
            "mtu": 9000,
            "auto_route": True,
            "strict_route": True,
            "stack": "mixed",
        })
    inbounds.append({
        "type": "mixed",
        "tag": "mixed-in",
        "listen": "127.0.0.1",
        "listen_port": port,
    })

    dns = {
        "servers": [
            {"type": "local", "tag": "dns-local"},
            {"type": "https", "tag": "dns-remote", "server": "1.1.1.1",
             "path": "/dns-query", "detour": final},
        ],
        # 只有 .cn 域名走系统 DNS，其余走代理的加密 DNS；
        # 不用 1.14 已弃用的地址匹配字段（ip_is_private / ip_cidr）
        "rules": [
            {"domain_suffix": [".cn"], "server": "dns-local"},
        ],
        "final": "dns-remote",
        "strategy": "prefer_ipv4",
    }

    route = {
        "rules": [
            {"action": "sniff"},
            {"protocol": "dns", "action": "hijack-dns"},
        ] + rules,
        "final": final,
        "auto_detect_interface": True,
        # sing-box 1.14 起必须显式给出解析出站域名的 DNS
        "default_domain_resolver": {"server": "dns-local"},
    }
    if geoip_used:
        route["rule_set"] = [{
            "tag": "geoip-cn",
            "type": "remote",
            "format": "binary",
            "url": GEOIP_RULESET_URL,
            "download_detour": final,
        }]

    config = {
        "log": {"level": "warn", "timestamp": True},
        "dns": dns,
        "inbounds": inbounds,
        "outbounds": outbounds,
    }
    if endpoints:
        config["endpoints"] = endpoints
    config["route"] = route
    config["experimental"] = {
        "cache_file": {"enabled": True},
        "clash_api": {
            "external_controller": "127.0.0.1:%d" % int(api_port),
            "default_mode": "rule",
        },
    }
    return config, stats, skipped, groups


def main():
    ap = argparse.ArgumentParser(description="clash.yaml → sing-box box.json")
    ap.add_argument("input", help="输入 clash.yaml")
    ap.add_argument("-o", "--output", help="输出 box.json（默认与输入同目录的 box.json）")
    ap.add_argument("--mixed-port", type=int, default=0, help="混合入站端口（默认沿用 mixed-port）")
    ap.add_argument("--api-port", type=int, default=9090, help="clash_api 端口")
    ap.add_argument("--no-tun", action="store_true", help="只留 mixed 入站，不加 tun")
    ap.add_argument("--geoip", choices=["off", "remote"], default="off",
                    help="CN 分流：off=不写 geoip 规则（默认，启动不需联网）；"
                         "remote=用远程 geoip-cn 规则集（启动时要能下载）")
    args = ap.parse_args()

    with open(args.input, encoding="utf-8") as f:
        clash = yaml.safe_load(f) or {}

    config, stats, skipped, groups = build_config(
        clash, mixed_port=args.mixed_port or None,
        api_port=args.api_port, tun=not args.no_tun, geoip=args.geoip)

    output = args.output or os.path.join(os.path.dirname(args.input) or ".", "box.json")
    os.makedirs(os.path.dirname(output) or ".", exist_ok=True)
    tmp = output + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(config, f, ensure_ascii=False, separators=(",", ":"))
        f.write("\n")
    os.replace(tmp, output)

    total = sum(len(o.get("outbounds") or []) for o in groups)
    size = os.path.getsize(output) / 1024
    print("[OK] %s → %s" % (args.input, output))
    print("     节点: %d（%s）" % (
        sum(stats.values()),
        ", ".join("%s×%d" % (k, v) for k, v in stats.most_common()) or "无"))
    print("     分组: %d（成员引用 %d），出站 %d，endpoint %d，%.1f KB" % (
        len(groups), total, len(config["outbounds"]), len(config.get("endpoints") or []), size))
    if skipped:
        print("     跳过: " + ", ".join("%s×%d" % (k, v) for k, v in skipped.most_common(8)))
    if not stats:
        raise SystemExit("[FAIL] 一个节点都没转换成功")


if __name__ == "__main__":
    main()
