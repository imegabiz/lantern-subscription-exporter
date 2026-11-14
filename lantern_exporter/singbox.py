import copy
import json

from . import constants as C
from .errors import ValidationError

SELECTOR_TAG = "Lantern"
URLTEST_TAG = "Lantern Auto"
DIRECT_TAG = "direct"
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
        proxy_outbounds.append(outbound)
    profile = {
        "log": {"level": "warn", "timestamp": True},
        "inbounds": [
            {"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 2080}
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
        "route": {"final": SELECTOR_TAG},
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
    proxy_items = [item for item in outbounds if item.get("type") in ("shadowsocks", "vless")]
    if len(proxy_items) != expected_proxies:
        raise ValidationError("profile proxy count mismatch")
    known = set(tags)
    for item in outbounds:
        if item.get("type") in ("selector", "urltest"):
            members = item.get("outbounds")
            if not members or not set(members) <= known:
                raise ValidationError("selector or urltest references unknown outbounds")
    if profile.get("route", {}).get("final") not in known:
        raise ValidationError("route final points to an unknown outbound")


def render_profile(profile):
    return (json.dumps(profile, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
