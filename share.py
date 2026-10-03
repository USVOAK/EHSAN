"""Share-link and subscription building, ported from Lunel Core/Console.

Used by RVG's main.py. Covers VLESS / Trojan over WebSocket and xHTTP.
Shadowsocks and MTProto links are still built in main.py (they are
identical in RVG and Lunel / not part of Lunel).

What changed vs. the old RVG generator (all taken from Lunel's links.py):
  * ALPN is chosen per transport, not read from the stored link:
      WebSocket -> "http/1.1"   (h2 breaks the WS upgrade through CDN edges)
      xHTTP     -> "h2,http/1.1"
  * path / alpn query values are fully percent-encoded (path=%2Fws%2F<uuid>)
    the way xray clients emit them.
  * ":443" is only appended when the host does not already carry a port.
  * the remark (#name) is used exactly as given — no prefix is added.
"""
from __future__ import annotations

import base64
import json
import os
from urllib.parse import parse_qs, quote, unquote, urlparse

# ══════════════════════════════════════════════════════════════════════════════
# Built-in settings — nothing needs to be configured.
# These values work as-is. To change one, edit it here; an environment variable
# with the same name (if you ever set one) takes priority over this table.
# ══════════════════════════════════════════════════════════════════════════════
DEFAULTS = {
    # Secret-ish prefix of the transport paths. Unique to this copy of the code.
    # NOTE: changing it invalidates links that were already handed out.
    "PATH_PREFIX": "/static/38a217",
    # Force one TLS fingerprint on all links (chrome, firefox, safari, ios,
    # android, edge, random, randomized). "" = use each link's own setting.
    "FP_OVERRIDE": "",
    # Comma separated CDN "clean" IPs/domains. Only for domains behind a CDN
    # such as Cloudflare. "" = off.
    "CLEAN_ADDRESSES": "",
    # Decoy home page + generic 404 + minimal /health. "1" = on, "0" = off.
    "DECOY": "1",
    # Secret login path, e.g. "/k7x2m9". "" = normal /login (recommended until
    # you have bookmarked the secret URL).
    "PANEL_PATH": "",
}


def _setting(name: str) -> str:
    return os.environ.get(name, DEFAULTS[name])


# ── Neutral transport paths ───────────────────────────────────────────────────
# The share links no longer carry RVG's telltale paths (/ws/<uuid>, /trojan-ws,
# /xhttp-siz10/..., /ss-ws). They use ordinary-looking API paths instead, under
# a configurable prefix:
#
#     PATH_PREFIX (see DEFAULTS)
#       {P}/stream/<uuid>            VLESS  WebSocket
#       {P}/events                   Trojan WebSocket
#       {P}/socket                   Shadowsocks WebSocket
#       {P}/data/<mode>/<uuid>/...   VLESS  xHTTP
#       {P}/media/<mode>/<uuid>/...  Trojan xHTTP
#
# PathAliasMiddleware maps these back to RVG's internal routes before routing,
# so the relay code is untouched. The old internal paths keep working, so links
# created earlier still connect.

def _norm_prefix(raw: str) -> str:
    raw = (raw or "").strip().strip("/")
    return f"/{raw}" if raw else ""


PATH_PREFIX = _norm_prefix(_setting("PATH_PREFIX"))

# exact public path -> exact internal path
_EXACT = {
    f"{PATH_PREFIX}/events": "/trojan-ws",
    f"{PATH_PREFIX}/socket": "/ss-ws",
}
# public prefix -> internal prefix (the rest of the path is kept as is)
_PREFIXES = (
    (f"{PATH_PREFIX}/stream/", "/ws/"),
    (f"{PATH_PREFIX}/data/", "/xhttp-siz10/"),
    (f"{PATH_PREFIX}/media/", "/txhttp-siz10/"),
)


def internal_path(path: str) -> str:
    """Public (neutral) path -> RVG's internal route; unknown paths unchanged."""
    hit = _EXACT.get(path)
    if hit:
        return hit
    for pub, inner in _PREFIXES:
        if path.startswith(pub):
            return inner + path[len(pub):]
    return path


class PathAliasMiddleware:
    """Pure-ASGI rewrite of neutral paths (HTTP and WebSocket) to internal ones."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] in ("http", "websocket"):
            old = scope.get("path", "")
            new = internal_path(old)
            if new != old:
                scope = dict(scope)
                scope["path"] = new
                scope["raw_path"] = new.encode()
        await self.app(scope, receive, send)


def build_ss_link(host: str, port: int, cipher: str, password: str, remark: str) -> str:
    """Shadowsocks + v2ray-plugin (ws, tls) link using the neutral socket path."""
    userinfo = base64.urlsafe_b64encode(f"{cipher}:{password}".encode()).decode().rstrip("=")
    plugin = quote(f"v2ray-plugin;tls;mux=0;path={PATH_PREFIX}/socket;host={host}")
    return f"ss://{userinfo}@{host}:{port}/?plugin={plugin}#{quote(remark)}"


# ── Anti-filter knobs (see DEFAULTS at the top of this file) ──────────────────
# FP_OVERRIDE      force one TLS client fingerprint on every generated link
#                  (chrome, firefox, safari, ios, android, edge, random, randomized)
# CLEAN_ADDRESSES  comma separated IPs/domains. When set, each VLESS/Trojan
#                  config is emitted once per address: the TCP connection goes to
#                  that address while SNI and Host stay your real domain. Only
#                  useful when the domain sits behind a CDN (e.g. Cloudflare);
#                  leave unset otherwise or the configs will not connect.
# DECOY            "0" turns the decoy home page / generic 404 off (default on)
# PANEL_PATH       optional secret path for the panel login, e.g. /k7x2m9
ALLOWED_FP = ("chrome", "firefox", "safari", "ios", "android", "edge", "random", "randomized")


def clean_fp(value: str | None) -> str:
    value = (value or "").strip().lower()
    return value if value in ALLOWED_FP else "chrome"


FP_OVERRIDE = clean_fp(_setting("FP_OVERRIDE")) if _setting("FP_OVERRIDE").strip() else ""
CLEAN_ADDRESSES = [a.strip() for a in _setting("CLEAN_ADDRESSES").split(",") if a.strip()]
DECOY = _setting("DECOY").strip().lower() not in ("0", "false", "no", "off")
PANEL_PATH = _norm_prefix(_setting("PANEL_PATH"))

DECOY_HTML = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Welcome</title>
<style>body{font-family:system-ui,sans-serif;background:#fafafa;color:#333;display:flex;align-items:center;
justify-content:center;min-height:100vh;margin:0}main{text-align:center;padding:24px}h1{font-weight:500;margin:0 0 8px}
p{color:#777;margin:0}</style></head>
<body><main><h1>Coming soon</h1><p>This site is under construction.</p></main></body></html>"""

NOT_FOUND_HTML = ("<!DOCTYPE html><html><head><title>404 Not Found</title></head>"
                  "<body><center><h1>404 Not Found</h1></center></body></html>")


def transport_alpn(protocol: str) -> str:
    return "h2,http/1.1" if "xhttp" in protocol else "http/1.1"


def build_link(uuid: str, host: str, remark: str, protocol: str, fingerprint: str = "chrome",
               address: str | None = None) -> str:
    """vless:// or trojan:// import URL for the given RVG protocol name.

    ``address`` (optional) is where the client actually connects; SNI and Host
    always stay ``host``."""
    fp = FP_OVERRIDE or clean_fp(fingerprint)
    alpn = quote(transport_alpn(protocol), safe="")
    authority = address or host
    port_part = "" if ":" in authority else ":443"
    frag = quote(remark)

    if protocol == "trojan-ws":
        params = {
            "security": "tls", "type": "ws", "host": host,
            "path": quote(f"{PATH_PREFIX}/events", safe=""), "sni": host, "fp": fp, "alpn": alpn,
        }
        return f"trojan://{uuid}@{authority}{port_part}?{_qs(params)}#{frag}"

    if protocol.startswith("trojan-xhttp-"):
        mode = protocol.replace("trojan-xhttp-", "")
        params = {
            "security": "tls", "type": "xhttp", "mode": mode, "host": host,
            "path": quote(f"{PATH_PREFIX}/media/{mode}/{uuid}", safe=""),
            "sni": host, "fp": fp, "alpn": alpn,
        }
        return f"trojan://{uuid}@{authority}{port_part}?{_qs(params)}#{frag}"

    if protocol == "vless-ws":
        params = {
            "encryption": "none", "security": "tls", "type": "ws", "host": host,
            "path": quote(f"{PATH_PREFIX}/stream/{uuid}", safe=""), "sni": host, "fp": fp, "alpn": alpn,
        }
    else:
        mode = protocol.replace("xhttp-", "") if protocol.startswith("xhttp-") else "packet-up"
        params = {
            "encryption": "none", "security": "tls", "type": "xhttp", "mode": mode,
            "host": host, "path": quote(f"{PATH_PREFIX}/data/{mode}/{uuid}", safe=""),
            "sni": host, "fp": fp, "alpn": alpn,
        }
    return f"vless://{uuid}@{authority}{port_part}?{_qs(params)}#{frag}"


def build_links(uuid: str, host: str, remark: str, protocol: str, fingerprint: str = "chrome") -> list[str]:
    """One link normally; one per CLEAN_ADDRESSES entry when that is configured."""
    if not CLEAN_ADDRESSES:
        return [build_link(uuid, host, remark, protocol, fingerprint)]
    if len(CLEAN_ADDRESSES) == 1:
        return [build_link(uuid, host, remark, protocol, fingerprint, CLEAN_ADDRESSES[0])]
    return [build_link(uuid, host, f"{remark} · {i}", protocol, fingerprint, addr)
            for i, addr in enumerate(CLEAN_ADDRESSES, 1)]


def _qs(params: dict) -> str:
    return "&".join(f"{k}={v}" for k, v in params.items())


# ── Subscription output formats (from Lunel gateway.py) ──────────────────────

def _query(u) -> dict:
    return {k: v[0] for k, v in parse_qs(u.query).items()}


def singbox_outbound(url: str) -> dict | None:
    """vless/trojan/ss URL -> sing-box outbound. None = not representable
    (xHTTP, MTProto, unknown schemes) and is skipped by the caller."""
    u = urlparse(url)
    q = _query(u)
    if q.get("type") == "xhttp":
        return None
    tag = unquote(u.fragment) or "config"
    if u.scheme in ("vless", "trojan"):
        out = {
            "type": u.scheme, "tag": tag,
            "server": u.hostname or "", "server_port": u.port or 443,
            "tls": {
                "enabled": q.get("security") == "tls",
                "server_name": q.get("sni") or u.hostname or "",
            },
        }
        if q.get("alpn"):
            out["tls"]["alpn"] = unquote(q["alpn"]).split(",")
        if q.get("fp"):
            out["tls"]["utls"] = {"enabled": True, "fingerprint": q["fp"]}
        if u.scheme == "vless":
            out["uuid"] = u.username or ""
        else:
            out["password"] = u.username or ""
        if q.get("type") == "ws":
            out["transport"] = {
                "type": "ws", "path": unquote(q.get("path", "/")),
                "headers": {"Host": q.get("host") or u.hostname or ""},
            }
        return out
    if u.scheme == "ss":
        parsed = _ss_userinfo(u)
        if not parsed:
            return None
        method, password = parsed
        return {"type": "shadowsocks", "tag": tag, "server": u.hostname or "",
                "server_port": u.port or 443, "method": method, "password": password}
    return None


def clash_proxy(url: str) -> dict | None:
    """vless/trojan/ss URL -> Clash Meta proxy map. None = skipped."""
    u = urlparse(url)
    q = _query(u)
    if q.get("type") == "xhttp":
        return None
    name = unquote(u.fragment) or "config"
    ws_opts = {"path": unquote(q.get("path", "/")),
               "headers": {"Host": q.get("host") or u.hostname or ""}}
    if u.scheme == "vless":
        return {"name": name, "type": "vless", "server": u.hostname or "",
                "port": u.port or 443, "uuid": u.username or "", "udp": True,
                "tls": q.get("security") == "tls",
                "servername": q.get("sni") or u.hostname or "",
                "client-fingerprint": q.get("fp", "chrome"),
                "network": "ws", "ws-opts": ws_opts}
    if u.scheme == "trojan":
        return {"name": name, "type": "trojan", "server": u.hostname or "",
                "port": u.port or 443, "password": u.username or "", "udp": True,
                "sni": q.get("sni") or u.hostname or "",
                "client-fingerprint": q.get("fp", "chrome"),
                "network": "ws", "ws-opts": ws_opts}
    if u.scheme == "ss":
        parsed = _ss_userinfo(u)
        if not parsed:
            return None
        method, password = parsed
        return {"name": name, "type": "ss", "server": u.hostname or "",
                "port": u.port or 443, "cipher": method, "password": password}
    return None


def _ss_userinfo(u) -> tuple[str, str] | None:
    raw = u.username or ""
    try:
        method, password = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)).decode().split(":", 1)
        return method, password
    except Exception:
        return None


def render(lines: list[str], headers: dict, fmt: str = "", group: str = "Proxy") -> tuple[str, str, dict]:
    """(body, media_type, headers) for a subscription.

    fmt: ""/anything else -> base64 v2ray list (default, unchanged behaviour)
         "singbox" | "sing-box" | "sb" -> sing-box JSON
         "clash" | "clash-meta" | "yaml" -> Clash Meta YAML
    Configs a format cannot express (xHTTP, MTProto) are left out of that
    format; the default list always contains everything.
    """
    fmt = (fmt or "").strip().lower()
    if fmt in ("singbox", "sing-box", "sb"):
        outs = [o for o in (singbox_outbound(l) for l in lines) if o]
        return json.dumps({"outbounds": outs}, ensure_ascii=False, indent=2), "application/json", headers
    if fmt in ("clash", "clash-meta", "yaml"):
        proxies = [p for p in (clash_proxy(l) for l in lines) if p]
        body = (
            "port: 7890\nsocks-port: 7891\nallow-lan: false\nmode: rule\nlog-level: warning\n"
            "proxies:\n"
            + "".join("  - " + json.dumps(p, ensure_ascii=False) + "\n" for p in proxies)
            + f"proxy-groups:\n  - name: {json.dumps(group, ensure_ascii=False)}\n    type: select\n    proxies:\n"
            + "".join(f"      - {json.dumps(p['name'], ensure_ascii=False)}\n" for p in proxies)
            + f"rules:\n  - MATCH,{group}\n"
        )
        return body, "text/yaml", headers
    body = base64.b64encode("\n".join(lines).encode()).decode()
    return body, "text/plain", headers
