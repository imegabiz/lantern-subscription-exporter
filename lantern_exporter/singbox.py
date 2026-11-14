import copy
import json

from . import constants as C
from .errors import ValidationError

SELECTOR_TAG = "Lantern"
URLTEST_TAG = "Lantern Auto"
DIRECT_TAG = "direct"
TUN_TAG = "tun-in"
DNS_REMOTE_TAG = "dns-remote"
RESERVED_TAGS = (SELECTOR_TAG, URLTEST_TAG, DIRECT_TAG)


def build_profile(proxies, names):
    if len(proxies) != len(names) or not proxies:
        raise ValidationError("proxy and name lists are inconsistent")
    if len(set(names)) != len(names) or set(names) & set(RESERVED_TAGS):
        raise ValidationError("proxy names are not unique")
    proxy_outbounds = []
    for proxy, name in zip(proxies, names):
        outbound = {"type": proxy.outbound["type"], "tag": name}
        outbound.update(copy.deepcopy({k: v for k, v in proxy.outbound.items() if k != "type"}))
        if proxy.kind == "hysteria2":
            outbound["tls"]["certificate"] = outbound["tls"]["certificate"].strip().split("\n")
        proxy_outbounds.append(outbound)
    profile = {
        "log": {"level": "warn", "timestamp": True},
        "dns": {
            "servers": [
                {"type": "https", "tag": DNS_REMOTE_TAG, "server": "1.1.1.1", "detour": SELECTOR_TAG}
            ],
            "final": DNS_REMOTE_TAG,
            "strategy": "ipv4_only",
        },
        "inbounds": [
            {
                "type": "tun",
                "tag": TUN_TAG,
                "address": ["172.19.0.1/30"],
                "auto_route": True,
                "strict_route": True,
                "stack": "mixed",
            }
        ],
        "outbounds": [
            {
                "type": "selector",
                "tag": SELECTOR_TAG,
                "outbounds": [URLTEST_TAG] + list(names),
                "default": URLTEST_TAG,
            },
            {
                "type": "urltest",
                "tag": URLTEST_TAG,
                "outbounds": list(names),
                "url": C.URLTEST_URL,
                "interval": "3m",
                "tolerance": 50,
            },
        ]
        + proxy_outbounds
        + [{"type": "direct", "tag": DIRECT_TAG}],
        "route": {
            "rules": [
                {"action": "sniff"},
                {"protocol": "dns", "action": "hijack-dns"},
                {"ip_is_private": True, "outbound": DIRECT_TAG},
            ],
            "final": SELECTOR_TAG,
            "auto_detect_interface": True,
        },
    }
    validate_profile(profile, len(proxies))
    return profile


def validate_profile(profile, expected_proxies):
    outbounds = profile.get("outbounds")
    if not isinstance(outbounds, list):
        raise ValidationError("profile has no outbounds")
    tags = [item.get("tag") for item in outbounds]
    if len(set(tags)) != len(tags) or any(not isinstance(tag, str) or not tag for tag in tags):
        raise ValidationError("profile tags are invalid or duplicated")
    proxy_items = [item for item in outbounds if item.get("type") in ("shadowsocks", "vless", "hysteria2")]
    if len(proxy_items) != expected_proxies:
        raise ValidationError("profile proxy count mismatch")
    known = set(tags)
    for item in outbounds:
        if item.get("type") in ("selector", "urltest"):
            members = item.get("outbounds")
            if not members or not set(members) <= known:
                raise ValidationError("selector or urltest references unknown outbounds")
    route = profile.get("route", {})
    if route.get("final") not in known:
        raise ValidationError("route final points to an unknown outbound")
    for rule in route.get("rules", []):
        if "outbound" in rule and rule["outbound"] not in known:
            raise ValidationError("a route rule points to an unknown outbound")
    if not any(item.get("type") == "tun" for item in profile.get("inbounds", [])):
        raise ValidationError("profile has no tun inbound")
    dns = profile.get("dns", {})
    dns_tags = {server.get("tag") for server in dns.get("servers", [])}
    if dns.get("final") not in dns_tags:
        raise ValidationError("dns final points to an unknown server")
    for server in dns.get("servers", []):
        if server.get("detour") is not None and server["detour"] not in known:
            raise ValidationError("a dns server detour points to an unknown outbound")


def render_profile(profile):
    return (json.dumps(profile, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
