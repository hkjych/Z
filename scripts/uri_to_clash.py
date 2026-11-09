#!/usr/bin/env python3
"""把分享链接(URI 列表)转换成 Clash/mihomo 的 proxies。

有的来源根本不发 Clash 配置,只发一行一个的分享链接(ss:// vmess:// vless://
trojan:// hysteria2:// tuic://),或者把整份列表 base64 后再发一份。sanitize.py
只吃 Clash YAML,所以这些来源以前必然在清洗阶段失败。抓取时先转换一次,
后面照旧走清洗 + 内核门禁。

用法:
  python scripts/uri_to_clash.py <in.txt> <out.yaml>       # 手动转换
  from uri_to_clash import maybe_convert                   # fetch_sources 调用

上限:
  转换结果默认最多留 MAX_NODES 个节点(按 server/port 去重后的先到先得),
  避免把几千上万个节点塞进测速环节把 35 分钟的 job 撑爆。用环境变量
  URI_MAX_NODES 覆盖,设为 0 表示不限制。

支持的协议: ss(SIP002,含 obfs / v2ray-plugin)、vmess(v2rayN JSON)、vless、
trojan、hysteria2/hy2、hysteria(v1)、tuic。其余(ssr:// 等)跳过并计数。

mihomo 不认识的传输层(xhttp 等)也直接丢弃 —— 否则一个坏节点会让整份配置
过不了内核校验,来源反而发不出去。
"""
import base64
import html
import json
import os
import re
import sys
import urllib.parse

import yaml

DEFAULT_MAX_NODES = 1200

# mihomo 认识的 network(传输层)
NETWORKS = {"tcp", "udp", "ws", "grpc", "h2", "http", "httpupgrade", "quic"}

# mihomo 支持的 ss 加密方式;不在表里的说明链接解析错了(常见于不是 base64 的
# userinfo 被当成 method:password),直接丢弃,不然一个坏节点会让整份配置过不了
# 内核校验。
SS_CIPHERS = {
    "aes-128-gcm", "aes-192-gcm", "aes-256-gcm",
    "aes-128-cfb", "aes-192-cfb", "aes-256-cfb",
    "aes-128-ctr", "aes-192-ctr", "aes-256-ctr",
    "rc4-md5", "chacha20", "chacha20-ietf", "xchacha20",
    "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305",
    "aes-128-gcm-siv", "aes-256-gcm-siv",
    "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
    "none", "plain",
}

_B64_RE = re.compile(r"^[A-Za-z0-9+/=_\-\s]+$")


def _b64d(text: str) -> str:
    """容错 base64 解码(补 padding、兼容 URL-safe)。不是 base64 就返回空串。"""
    s = (text or "").strip()
    if not s or not _B64_RE.match(s):
        return ""
    s = s.replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    try:
        return base64.b64decode(s).decode("utf-8", "ignore")
    except Exception:
        return ""


def _split_fragment(uri: str):
    """拆出 #备注,并做百分号解码。"""
    frag = ""
    if "#" in uri:
        uri, frag = uri.split("#", 1)
        frag = urllib.parse.unquote(frag.strip())
    return uri, frag


def _split_query(uri: str):
    if "?" not in uri:
        return uri, {}
    base, query = uri.split("?", 1)
    return base, {k: v[0] for k, v in urllib.parse.parse_qs(query, keep_blank_values=True).items()}


def _hostport(text: str):
    """'1.2.3.4:443' / '[2001:db8::1]:443' -> (host, port)。"""
    s = (text or "").strip().rstrip("/")
    if s.startswith("["):
        host, _, rest = s[1:].partition("]")
        port = rest.lstrip(":") or "0"
        return host, int(port) if port.isdigit() else 0
    if ":" not in s:
        return s, 0
    host, _, port = s.rpartition(":")
    return host, int(port) if port.isdigit() else 0


def _flag(value) -> bool:
    return str(value).lower() in ("1", "true", "yes", "on")


def _ws_opts(q: dict, default_path="/"):
    opts = {"path": q.get("path") or q.get("serviceName") or default_path}
    host = q.get("host") or q.get("sni") or ""
    if host:
        opts["headers"] = {"Host": host}
    return opts


def _apply_transport(proxy: dict, network: str, q: dict):
    """按传输层补 ws-opts / grpc-opts / h2-opts。"""
    network = (network or "tcp").lower()
    if network not in NETWORKS:
        return None                      # mihomo 不认,丢弃
    if network != "tcp":
        proxy["network"] = network
    if network == "ws":
        proxy["ws-opts"] = _ws_opts(q)
    elif network == "grpc":
        proxy["grpc-opts"] = {"grpc-service-name": q.get("serviceName") or q.get("path") or ""}
    elif network in ("h2", "http"):
        opts = {}
        if q.get("path"):
            opts["path"] = q["path"]
        if q.get("host"):
            opts["host"] = [h for h in q["host"].split(",") if h]
        if opts:
            proxy["h2-opts" if network == "h2" else "http-opts"] = opts
    return proxy


def _apply_tls(proxy: dict, security: str, q: dict):
    sec = (security or "").lower()
    if sec in ("tls", "xtls", "reality"):
        proxy["tls"] = True
        sni = q.get("sni") or q.get("peer") or q.get("host")
        if sni:
            proxy["servername"] = sni
        if q.get("alpn"):
            proxy["alpn"] = [a for a in q["alpn"].split(",") if a]
        if _flag(q.get("allowInsecure") or q.get("insecure") or q.get("skip-cert-verify")):
            proxy["skip-cert-verify"] = True
        fp = q.get("fp") or q.get("client-fingerprint")
        if fp:
            proxy["client-fingerprint"] = fp
        if sec == "reality":
            pub = q.get("pbk") or q.get("public-key")
            if not pub:
                return None              # reality 缺公钥必然连不上
            proxy["reality-opts"] = {"public-key": pub, "short-id": q.get("sid", "")}
    return proxy


def parse_ss(uri: str):
    body = uri[len("ss://"):]
    main, q = _split_query(body)
    if "@" in main:
        userinfo, hostport = main.rsplit("@", 1)
        userinfo = urllib.parse.unquote(userinfo)
        if ":" not in userinfo:
            userinfo = _b64d(userinfo)
    else:
        decoded = _b64d(main)
        if "@" not in decoded:
            return None
        userinfo, hostport = decoded.rsplit("@", 1)
        q = {}
    method, _, password = userinfo.partition(":")
    host, port = _hostport(hostport)
    if not (method and password and host and port):
        return None
    if method.lower() not in SS_CIPHERS:      # 解析歪了,别让它拖垮整份配置
        return None
    proxy = {
        "name": f"ss-{host}-{port}",
        "type": "ss",
        "server": host,
        "port": port,
        "cipher": method,
        "password": password,
        "udp": True,
    }
    plugin = q.get("plugin")
    if plugin:
        parts = plugin.split(";")
        kind, params = parts[0].strip().lower(), {}
        for item in parts[1:]:
            k, _, v = item.partition("=")
            params[k.strip().lower()] = v.strip()
        if kind.startswith("obfs"):
            proxy["plugin"] = "obfs"
            proxy["plugin-opts"] = {
                "mode": params.get("obfs", "http"),
                "host": params.get("obfs-host", ""),
            }
        elif kind.startswith("v2ray"):
            proxy["plugin"] = "v2ray-plugin"
            opts = {"mode": params.get("mode", "websocket")}
            if params.get("host"):
                opts["host"] = params["host"]
            if params.get("path"):
                opts["path"] = params["path"]
            if "tls" in parts or _flag(params.get("tls")):
                opts["tls"] = True
            proxy["plugin-opts"] = opts
        else:
            return None                  # 未知插件,连不上,丢弃
    return proxy


def parse_vmess(uri: str):
    body = uri[len("vmess://"):]
    raw = body if body.lstrip().startswith("{") else _b64d(body)
    if not raw.lstrip().startswith("{"):
        # 少数订阅用 URI 写法:vmess://uuid@host:port?security=tls&type=ws&path=/x#备注
        main, q = _split_query(body)
        if "@" not in main:
            return None
        userinfo, hostport = main.rsplit("@", 1)
        uuid = urllib.parse.unquote(userinfo)
        host, port = _hostport(hostport)
        if not (uuid and host and port):
            return None
        proxy = {
            "name": f"vmess-{host}-{port}",
            "type": "vmess",
            "server": host,
            "port": port,
            "uuid": uuid,
            "alterId": 0,
            "cipher": "auto",
            "udp": True,
        }
        proxy = _apply_tls(proxy, q.get("security", ""), q)
        if proxy is None:
            return None
        return _apply_transport(proxy, q.get("type", "tcp"), q)
    try:
        j = json.loads(raw)
    except Exception:
        return None
    host, port = _hostport(f"{j.get('add', '')}:{j.get('port', '')}")
    if not (host and port and j.get("id")):
        return None
    proxy = {
        "name": str(j.get("ps") or f"vmess-{host}-{port}"),
        "type": "vmess",
        "server": host,
        "port": port,
        "uuid": str(j["id"]),
        "alterId": int(j.get("aid") or 0),
        "cipher": str(j.get("scy") or "auto"),
        "udp": True,
    }
    if str(j.get("tls", "")).lower() in ("tls", "reality") or _flag(j.get("tls")):
        proxy["tls"] = True
        sni = j.get("sni") or j.get("host")
        if sni:
            proxy["servername"] = str(sni)
    q = {
        "path": j.get("path") or "/",
        "host": j.get("host") or "",
        "serviceName": j.get("path") or "",
    }
    return _apply_transport(proxy, str(j.get("net") or "tcp"), q)


def parse_vless(uri: str):
    body = uri[len("vless://"):]
    main, q = _split_query(body)
    if "@" not in main:
        return None
    userinfo, hostport = main.rsplit("@", 1)
    host, port = _hostport(hostport)
    uuid = urllib.parse.unquote(userinfo)
    if not (host and port and uuid):
        return None
    proxy = {
        "name": f"vless-{host}-{port}",
        "type": "vless",
        "server": host,
        "port": port,
        "uuid": uuid,
        "udp": True,
    }
    flow = q.get("flow")
    if flow and flow.lower() not in ("none", "xtls-rprx-vision-udp443"):
        proxy["flow"] = flow
    proxy = _apply_tls(proxy, q.get("security", ""), q)
    if proxy is None:
        return None
    return _apply_transport(proxy, q.get("type", "tcp"), q)


def parse_trojan(uri: str):
    body = uri[len("trojan://"):]
    main, q = _split_query(body)
    if "@" not in main:
        return None
    password, hostport = main.rsplit("@", 1)
    host, port = _hostport(hostport)
    password = urllib.parse.unquote(password)
    if not (host and port and password):
        return None
    proxy = {
        "name": f"trojan-{host}-{port}",
        "type": "trojan",
        "server": host,
        "port": port,
        "password": password,
        "udp": True,
    }
    if q.get("sni") or q.get("peer"):
        proxy["sni"] = q.get("sni") or q.get("peer")
    if _flag(q.get("allowInsecure") or q.get("insecure")):
        proxy["skip-cert-verify"] = True
    return _apply_transport(proxy, q.get("type", "tcp"), q)


def parse_hysteria2(uri: str):
    scheme = uri.split("://", 1)[0].lower()
    body = uri[len(scheme) + 3:]
    main, q = _split_query(body)
    if "@" in main:
        password, hostport = main.rsplit("@", 1)
    else:                                   # 少数写法把密码放查询里
        password, hostport = q.get("auth") or q.get("password") or "", main
    host, port = _hostport(hostport)
    if not (host and port):
        return None
    proxy = {
        "name": f"hy2-{host}-{port}",
        "type": "hysteria2",
        "server": host,
        "port": port,
    }
    if password:
        proxy["password"] = urllib.parse.unquote(password)
    sni = q.get("sni") or q.get("peer")
    if sni:
        proxy["sni"] = sni
    if _flag(q.get("insecure") or q.get("allowInsecure")):
        proxy["skip-cert-verify"] = True
    if q.get("obfs"):
        proxy["obfs"] = q["obfs"]
        if q.get("obfs-password"):
            proxy["obfs-password"] = q["obfs-password"]
    return proxy


def parse_hysteria(uri: str):
    """hysteria v1: hysteria://host:port?auth=xx&peer=xx&upmbps=..&downmbps=.."""
    body = uri[len("hysteria://"):]
    main, q = _split_query(body)
    host, port = _hostport(main)
    if not (host and port):
        return None
    proxy = {"name": f"hy-{host}-{port}", "type": "hysteria", "server": host, "port": port}
    if q.get("auth"):
        proxy["auth-str"] = q["auth"]
    if q.get("peer") or q.get("sni"):
        proxy["sni"] = q.get("peer") or q.get("sni")
    for key, field in (("upmbps", "up"), ("downmbps", "down")):
        if q.get(key):
            try:
                proxy[field] = int(q[key])
            except ValueError:
                pass
    if q.get("alpn"):
        proxy["alpn"] = [a for a in q["alpn"].split(",") if a]
    if _flag(q.get("insecure")):
        proxy["skip-cert-verify"] = True
    return proxy


def parse_tuic(uri: str):
    body = uri[len("tuic://"):]
    main, q = _split_query(body)
    if "@" not in main:
        return None
    userinfo, hostport = main.rsplit("@", 1)
    host, port = _hostport(hostport)
    userinfo = urllib.parse.unquote(userinfo)
    uuid, _, password = userinfo.partition(":")
    if not (host and port and uuid):
        return None
    proxy = {
        "name": f"tuic-{host}-{port}",
        "type": "tuic",
        "server": host,
        "port": port,
        "uuid": uuid,
    }
    if password:
        proxy["password"] = password
    sni = q.get("sni")
    if sni:
        proxy["sni"] = sni
    if q.get("alpn"):
        proxy["alpn"] = [a for a in q["alpn"].split(",") if a]
    if q.get("congestion_control") or q.get("congestion-controller"):
        proxy["congestion-controller"] = q.get("congestion_control") or q.get("congestion-controller")
    if _flag(q.get("allow_insecure") or q.get("insecure")):
        proxy["skip-cert-verify"] = True
    return proxy


PARSERS = {
    "ss": parse_ss,
    "vmess": parse_vmess,
    "vless": parse_vless,
    "trojan": parse_trojan,
    "hysteria2": parse_hysteria2,
    "hy2": parse_hysteria2,
    "hysteria": parse_hysteria,
    "tuic": parse_tuic,
}


def _node_key(p: dict):
    return (
        p.get("type"), p.get("server"), p.get("port"),
        p.get("uuid") or "", p.get("password") or "", p.get("cipher") or "",
    )


def convert(text: str, max_nodes: int = DEFAULT_MAX_NODES):
    """URI 列表文本 -> (proxies, 统计)。解析不出任何节点时 proxies 为空。"""
    stat = {"lines": 0, "ok": 0, "dup": 0, "skip": 0, "truncated": 0}
    text = html.unescape(text or "")
    if "://" not in text:                     # 整份是 base64
        text = _b64d("".join(text.split()))
        if "://" not in text:
            return [], stat
    proxies, seen = [], set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("//"):
            continue
        if "://" not in line:
            continue
        stat["lines"] += 1
        line, name = _split_fragment(line)
        scheme = line.split("://", 1)[0].lower()
        parser = PARSERS.get(scheme)
        if not parser:
            stat["skip"] += 1
            continue
        try:
            proxy = parser(line)
        except Exception:
            proxy = None
        if not proxy:
            stat["skip"] += 1
            continue
        if name:
            proxy["name"] = name
        key = _node_key(proxy)
        if key in seen:
            stat["dup"] += 1
            continue
        seen.add(key)
        proxies.append(proxy)
    if max_nodes and len(proxies) > max_nodes:
        stat["truncated"] = len(proxies) - max_nodes
        proxies = proxies[:max_nodes]
    stat["ok"] = len(proxies)
    return proxies, stat


def _looks_like_clash(text: str) -> bool:
    try:
        data = yaml.safe_load(text)
    except Exception:
        return False
    return isinstance(data, dict) and ("proxies" in data or "proxy-groups" in data)


def maybe_convert(raw: bytes):
    """抓到的内容不是 Clash 配置时,尝试当 URI 列表转换。

    返回 (要写盘的字节, 说明或 None)。
    """
    text = raw.decode("utf-8", "ignore")
    if _looks_like_clash(text):
        return raw, None
    proxies, stat = convert(text)
    if not proxies:
        return raw, None
    body = yaml.safe_dump({"proxies": proxies}, allow_unicode=True, sort_keys=False).encode("utf-8")
    note = "URI 列表 -> %d 个节点(扫描 %d 行,去重 %d,跳过 %d" % (
        stat["ok"], stat["lines"], stat["dup"], stat["skip"],
    )
    if stat["truncated"]:
        note += ",截断 %d" % stat["truncated"]
    note += ")"
    return body, note


def main():
    if len(sys.argv) < 3:
        raise SystemExit("用法: python scripts/uri_to_clash.py <in.txt> <out.yaml>")
    src, dst = sys.argv[1], sys.argv[2]
    with open(src, "rb") as f:
        raw = f.read()
    body, note = maybe_convert(raw)
    if note is None:
        print("[SKIP] 不是 URI 列表,或一个节点都没解析出来")
        return 1
    with open(dst, "wb") as f:
        f.write(body)
    print("[OK] %s -> %s: %s" % (src, dst, note))
    return 0


if __name__ == "__main__":
    sys.exit(main())
