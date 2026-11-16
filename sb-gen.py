#!/usr/bin/env python3
# usage: sb-gen [--mode tun|proxy] 'https://SUBSCRIPTION/plain/config/' > config.json
#   tun   (default) - TUN captures all traffic, plus local proxy on 127.0.0.1:2080; needs sudo
#   proxy           - no TUN: local proxy on 127.0.0.1:2080, set as macOS system proxy
#                     while sing-box runs (--no-system-proxy to skip that)
# filtering (regex, case-insensitive, matched against "<tag> <server>",
# e.g. "vless | PL / VLESS (WS+TLS) #2 pl-globalcdn1.example.org"):
#   --include 'cdn|PL /'   keep only matching servers
#   --exclude 'hysteria2'  drop matching servers (applied after --include)
# direct routing (domains + GeoIP of one country bypass the proxy):
#   --country ru   (default) needs /etc/sing-box/geoip-ru.srs
#   --country none send everything through the proxy
import argparse
import base64
import json
import os
import re
import sys
import urllib.request
from urllib.parse import parse_qs, unquote, urlparse

# TLDs a country uses besides ".<code>" (IDN ones in punycode)
EXTRA_TLDS = {
    "ru": ["xn--p1ai"],  # .рф
    "by": ["xn--90ais"],  # .бел
    "ua": ["xn--j1amh"],  # .укр
    "kz": ["xn--80ao21a"],  # .қаз
    "rs": ["xn--90a3ac"],  # .срб
    "gb": ["uk"],
}


def b64(s):
    s = s.strip().replace("-", "+").replace("_", "/")
    return base64.b64decode(s + "=" * (-len(s) % 4)).decode()


def q1(q, k, d=None):
    return unquote(q[k][0]) if k in q and q[k][0] != "" else d


def tls(q, host, default_on):
    sec = q1(q, "security", "tls" if default_on else "none")
    if sec == "none":
        return None
    t = {
        "enabled": True,
        "server_name": q1(q, "sni", q1(q, "host", host)),
        "utls": {"enabled": True, "fingerprint": q1(q, "fp", "chrome")},
    }
    if q1(q, "alpn"):
        t["alpn"] = q1(q, "alpn").split(",")
    if q1(q, "allowInsecure") in ("1", "true"):
        t["insecure"] = True
    if sec == "reality":
        t["reality"] = {
            "enabled": True,
            "public_key": q1(q, "pbk"),
            "short_id": q1(q, "sid", ""),
        }
    return t


def transport(q, host):
    typ = q1(q, "type", "tcp")
    if typ == "ws":
        return {
            "type": "ws",
            "path": q1(q, "path", "/"),
            "headers": {"Host": q1(q, "host", host)},
        }
    if typ == "grpc":
        return {"type": "grpc", "service_name": q1(q, "serviceName", "")}
    if typ == "httpupgrade":
        return {
            "type": "httpupgrade",
            "path": q1(q, "path", "/"),
            "host": q1(q, "host", host),
        }
    if typ in ("http", "h2"):
        return {
            "type": "http",
            "path": q1(q, "path", "/"),
            "host": [q1(q, "host", host)],
        }
    if typ in ("tcp", "raw", None):
        return None
    raise ValueError(f"unsupported transport {typ}")


def parse(line):
    scheme = line.split("://", 1)[0].lower()
    if scheme == "vmess":
        j = json.loads(b64(line[8:]))
        host = j["add"]
        q = {
            "type": [j.get("net") or "tcp"],
            "path": [j.get("path") or "/"],
            "host": [j.get("host") or host],
        }
        if j.get("tls") == "tls":
            q["security"] = ["tls"]
            q["sni"] = [j.get("sni") or j.get("host") or host]
        o = {
            "type": "vmess",
            "server": host,
            "server_port": int(j["port"]),
            "uuid": j["id"],
            "alter_id": int(j.get("aid") or 0),
            "security": j.get("scy") or "auto",
        }
        name = j.get("ps") or host
    else:
        u = urlparse(line)
        q = parse_qs(u.query)
        host = u.hostname
        name = unquote(u.fragment)
        if scheme in ("hysteria2", "hy2"):
            o = {
                "type": "hysteria2",
                "server": host,
                "server_port": u.port or 443,
                "password": unquote(u.netloc.rsplit("@", 1)[0]),
                "tls": {"enabled": True, "server_name": q1(q, "sni", host)},
            }
            if q1(q, "insecure") == "1":
                o["tls"]["insecure"] = True
            if q1(q, "obfs"):
                o["obfs"] = {
                    "type": q1(q, "obfs"),
                    "password": q1(q, "obfs-password", ""),
                }
            return o, name or f"{host}:{o['server_port']}"
        elif scheme == "vless":
            o = {
                "type": "vless",
                "server": host,
                "server_port": u.port,
                "uuid": unquote(u.username),
            }
            if q1(q, "flow"):
                o["flow"] = q1(q, "flow")
        elif scheme == "trojan":
            o = {
                "type": "trojan",
                "server": host,
                "server_port": u.port,
                "password": unquote(u.netloc.rsplit("@", 1)[0]),
            }
            if "security" not in q:
                q["security"] = ["tls"]
        elif scheme == "ss":
            if "plugin" in q:
                raise ValueError("ss plugin unsupported")
            if "@" not in u.netloc:
                creds, hp = b64(u.netloc).rsplit("@", 1)
                host, port = hp.rsplit(":", 1)
            else:
                ui, hp = u.netloc.rsplit("@", 1)
                ui = unquote(ui)
                try:
                    creds = b64(ui)
                    if ":" not in creds:
                        raise ValueError
                except Exception:
                    creds = ui
                port = u.port
            method, pw = creds.split(":", 1)
            return (
                {
                    "type": "shadowsocks",
                    "server": host,
                    "server_port": int(port),
                    "method": method,
                    "password": pw,
                },
                name or host,
            )
        else:
            raise ValueError(f"unknown scheme {scheme}")
    t = tls(q, host, False)
    if t:
        o["tls"] = t
    tr = transport(q, host)
    if tr:
        o["transport"] = tr
    return o, name or f"{host}:{o['server_port']}"


ap = argparse.ArgumentParser(description="subscription -> sing-box config")
ap.add_argument("src", help="subscription URL or local file")
ap.add_argument("--mode", choices=("tun", "proxy"), default="tun")
ap.add_argument(
    "--no-system-proxy",
    action="store_true",
    help="proxy mode: don't set the macOS system proxy",
)
ap.add_argument(
    "--cache",
    help="cache file path (default: /etc/sing-box/cache.db for tun, "
    "~/.cache/sing-box/cache.db for proxy so it runs without sudo)",
)
ap.add_argument(
    "--include",
    metavar="REGEX",
    help='keep only servers whose "<tag> <server>" matches',
)
ap.add_argument(
    "--exclude",
    metavar="REGEX",
    help='drop servers whose "<tag> <server>" matches',
)
ap.add_argument(
    "--country",
    metavar="CODE",
    default="ru",
    help="two-letter country code whose domains and IPs go direct "
    "(default: ru; needs /etc/sing-box/geoip-<code>.srs), "
    "or 'none' to send everything through the proxy",
)
args = ap.parse_args()
cc = args.country.lower()
if cc != "none" and not re.fullmatch(r"[a-z]{2}", cc):
    ap.error("--country must be a two-letter code or 'none'")
try:
    inc = re.compile(args.include, re.I) if args.include else None
    exc = re.compile(args.exclude, re.I) if args.exclude else None
except re.error as e:
    ap.error(f"bad regex: {e}")
tun = args.mode == "tun"
cache = args.cache or (
    "/etc/sing-box/cache.db"
    if tun
    else os.path.expanduser("~/.cache/sing-box/cache.db")
)
if not tun:
    os.makedirs(os.path.dirname(cache), exist_ok=True)

src = args.src
if src.startswith("http"):
    raw = urllib.request.urlopen(src, timeout=30).read().decode()
else:
    raw = open(src).read()
raw = raw.replace("\\r", "").strip()
if "://" not in raw:
    raw = b64(raw)

outs, seen = [], set()
for line in raw.splitlines():
    line = line.strip()
    if "://" not in line:
        continue
    try:
        o, name = parse(line)
    except Exception as e:
        print(f"skip: {line[:40]}... ({e})", file=sys.stderr)
        continue
    tag = f"{o['type']} | {name}"
    i = 2
    while tag in seen:
        tag = f"{o['type']} | {name} #{i}"
        i += 1
    seen.add(tag)
    o["tag"] = tag
    outs.append(o)

# filter after tagging so tags (incl. "#2") match what `sbx ls` shows
total = len(outs)
outs = [
    o
    for o in outs
    if (not inc or inc.search(f"{o['tag']} {o['server']}"))
    and not (exc and exc.search(f"{o['tag']} {o['server']}"))
]
if not outs:
    sys.exit(f"error: no servers left after filtering ({total} parsed)")

tags = [o["tag"] for o in outs]
kept = f"{len(tags)}/{total}" if len(tags) != total else f"{total}"
print(f"{kept} outbounds, mode: {args.mode}, direct: {cc}", file=sys.stderr)

if cc == "none":
    direct_suffixes, geoip = [], None
else:
    direct_suffixes = [f".{t}" for t in [cc, *EXTRA_TLDS.get(cc, [])]]
    geoip = f"/etc/sing-box/geoip-{cc}.srs"
    if not os.path.exists(geoip):
        print(
            f"warning: {geoip} not found, sing-box won't start without it:\n"
            f"  sudo curl -L -o {geoip} https://raw.githubusercontent.com/"
            f"SagerNet/sing-geoip/rule-set/geoip-{cc}.srs",
            file=sys.stderr,
        )

mixed = {
    "type": "mixed",
    "tag": "mixed-in",
    "listen": "127.0.0.1",
    "listen_port": 2080,
}
if not tun and not args.no_system_proxy:
    mixed["set_system_proxy"] = True
inbounds = [mixed]
if tun:
    inbounds.insert(
        0,
        {
            "type": "tun",
            "tag": "tun-in",
            "address": ["172.19.0.1/30"],
            "auto_route": True,
            "strict_route": True,
            "stack": "mixed",
        },
    )

cfg = {
    "log": {"level": "warn"},
    "experimental": {
        "clash_api": {"external_controller": "127.0.0.1:9090"},
        "cache_file": {"enabled": True, "path": cache},
    },
    "dns": {
        "servers": [
            {"type": "https", "tag": "remote", "server": "1.1.1.1", "detour": "proxy"},
            {"type": "local", "tag": "local"},
        ],
        "rules": (
            [{"domain_suffix": direct_suffixes, "server": "local"}]
            if direct_suffixes
            else []
        ),
        "final": "remote",
        "strategy": "ipv4_only",
    },
    "inbounds": inbounds,
    "outbounds": [
        {
            "type": "selector",
            "tag": "proxy",
            "outbounds": ["auto"] + tags,
            "default": "auto",
        },
        {
            "type": "urltest",
            "tag": "auto",
            "outbounds": tags,
            "url": "https://www.gstatic.com/generate_204",
            "interval": "3m",
            "tolerance": 100,
        },
        *outs,
        {"type": "direct", "tag": "direct"},
    ],
    "route": {
        "rules": [
            {"action": "sniff"},
            *([{"protocol": "dns", "action": "hijack-dns"}] if tun else []),
            {"ip_is_private": True, "outbound": "direct"},
            *(
                [
                    {"domain_suffix": direct_suffixes, "outbound": "direct"},
                    {"rule_set": f"geoip-{cc}", "outbound": "direct"},
                ]
                if geoip
                else []
            ),
        ],
        "rule_set": (
            [
                {
                    "type": "local",
                    "tag": f"geoip-{cc}",
                    "format": "binary",
                    "path": geoip,
                }
            ]
            if geoip
            else []
        ),
        "final": "proxy",
        "auto_detect_interface": True,
        "default_domain_resolver": "local",
    },
}
print(json.dumps(cfg, indent=2, ensure_ascii=False))
