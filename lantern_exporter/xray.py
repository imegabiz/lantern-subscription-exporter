import copy
import json

from . import constants as C
from .errors import ValidationError
from .links import certificate_pin

TAG_PREFIX = "lantern-"
BALANCER_TAG = "lantern-balancer"
DIRECT_TAG = "direct"
BLOCK_TAG = "block"
KIND_LABELS = {"shadowsocks": "ss", "vless": "vless", "hysteria2": "hy2"}
PRIVATE_RANGES = (
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "::1/128",
    "fc00::/7",
    "fe80::/10",
)
IRAN_DOMAINS = ("domain:ir", "geosite:category-ir")
IRAN_IPS = ("geoip:ir",)
SNIFFING = {"enabled": True, "destOverride": ["http", "tls"], "routeOnly": True}


def _shadowsocks(outbound):
    return {
        "protocol": "shadowsocks",
        "settings": {
            "address": outbound["server"],
            "port": outbound["server_port"],
            "method": outbound["method"],
            "password": outbound["password"],
        },
    }


def _vless(outbound):
    settings = {
        "address": outbound["server"],
        "port": outbound["server_port"],
        "id": outbound["uuid"],
        "encryption": "none",
    }
    if outbound.get("flow"):
        settings["flow"] = outbound["flow"]
    tls = outbound.get("tls")
    if not tls:
        return {"protocol": "vless", "settings": settings, "streamSettings": {"network": "raw"}}
    reality = tls.get("reality")
    if not reality:
        stream = {"network": "raw", "security": "tls", "tlsSettings": {"serverName": tls["server_name"]}}
        if tls.get("utls"):
            stream["tlsSettings"]["fingerprint"] = tls["utls"]["fingerprint"]
        return {"protocol": "vless", "settings": settings, "streamSettings": stream}
    reality_settings = {
        "serverName": tls["server_name"],
        "fingerprint": tls["utls"]["fingerprint"],
        "password": reality["public_key"],
    }
    if reality.get("short_id"):
        reality_settings["shortId"] = reality["short_id"]
    stream = {"network": "raw", "security": "reality", "realitySettings": reality_settings}
    return {"protocol": "vless", "settings": settings, "streamSettings": stream}


def _junk_mask():
    return {
        "udp": [
            {
                "type": "noise",
                "settings": {
                    "reset": "30-60",
                    "noise": [{"rand": "8-64", "delay": "10-20"}],
                },
            }
        ]
    }


def _hysteria2(outbound):
    tls = outbound["tls"]
    stream = {
        "network": "hysteria",
        "security": "tls",
        "tlsSettings": {
            "serverName": tls["server_name"],
            "alpn": ["h3"],
            "pinnedPeerCertSha256": certificate_pin(tls["certificate"]),
        },
        "hysteriaSettings": {"version": 2, "auth": outbound["password"]},
    }
    if outbound.get("pre_initial_junk") is True:
        stream["finalmask"] = _junk_mask()
    return {
        "protocol": "hysteria",
        "settings": {
            "version": 2,
            "address": outbound["server"],
            "port": outbound["server_port"],
        },
        "streamSettings": stream,
    }


BUILDERS = {"shadowsocks": _shadowsocks, "vless": _vless, "hysteria2": _hysteria2}


def build_config(proxies):
    if not proxies:
        raise ValidationError("no proxies for the xray config")
    outbounds = []
    for index, proxy in enumerate(proxies, start=1):
        builder = BUILDERS.get(proxy.kind)
        if builder is None:
            raise ValidationError("cannot build an xray outbound for type %s" % proxy.kind)
        outbound = builder(copy.deepcopy(proxy.outbound))
        outbound["tag"] = "%s%02d-%s" % (TAG_PREFIX, index, KIND_LABELS[proxy.kind])
        outbounds.append(outbound)
    first_tag = outbounds[0]["tag"]
    config = {
        "remarks": C.PROFILE_NAME,
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "tag": "socks-in",
                "listen": "127.0.0.1",
                "port": 10808,
                "protocol": "socks",
                "settings": {"udp": True},
                "sniffing": copy.deepcopy(SNIFFING),
            },
            {
                "tag": "http-in",
                "listen": "127.0.0.1",
                "port": 10809,
                "protocol": "http",
                "sniffing": copy.deepcopy(SNIFFING),
            },
        ],
        "outbounds": outbounds
        + [
            {"tag": DIRECT_TAG, "protocol": "freedom"},
            {"tag": BLOCK_TAG, "protocol": "blackhole"},
        ],
        "routing": {
            "domainStrategy": "AsIs",
            "balancers": [
                {
                    "tag": BALANCER_TAG,
                    "selector": [TAG_PREFIX],
                    "fallbackTag": first_tag,
                    "strategy": {"type": "leastPing"},
                }
            ],
            "rules": [
                {"type": "field", "ip": list(PRIVATE_RANGES), "outboundTag": DIRECT_TAG},
                {"type": "field", "domain": list(IRAN_DOMAINS), "outboundTag": DIRECT_TAG},
                {"type": "field", "ip": list(IRAN_IPS), "outboundTag": DIRECT_TAG},
                {"type": "field", "network": "tcp,udp", "balancerTag": BALANCER_TAG},
            ],
        },
        "observatory": {
            "subjectSelector": [TAG_PREFIX],
            "probeUrl": C.URLTEST_URL,
            "probeInterval": "3m",
            "enableConcurrency": True,
        },
    }
    validate_config(config, len(proxies))
    return config


def validate_config(config, expected_proxies):
    outbounds = config.get("outbounds")
    if not isinstance(outbounds, list):
        raise ValidationError("xray config has no outbounds")
    tags = [item.get("tag") for item in outbounds]
    if len(set(tags)) != len(tags) or any(not isinstance(tag, str) or not tag for tag in tags):
        raise ValidationError("xray outbound tags are invalid or duplicated")
    proxies = [item for item in outbounds if str(item.get("tag", "")).startswith(TAG_PREFIX)]
    if len(proxies) != expected_proxies:
        raise ValidationError("xray proxy count mismatch")
    for item in proxies:
        if item.get("protocol") not in ("shadowsocks", "vless", "hysteria"):
            raise ValidationError("unexpected xray outbound protocol")
    routing = config.get("routing", {})
    balancers = routing.get("balancers", [])
    balancer_tags = {item.get("tag") for item in balancers}
    for balancer in balancers:
        if balancer.get("fallbackTag") not in tags:
            raise ValidationError("balancer fallback points to an unknown outbound")
    for rule in routing.get("rules", []):
        if "outboundTag" in rule and rule["outboundTag"] not in tags:
            raise ValidationError("a routing rule points to an unknown outbound")
        if "balancerTag" in rule and rule["balancerTag"] not in balancer_tags:
            raise ValidationError("a routing rule points to an unknown balancer")
    if not config.get("inbounds"):
        raise ValidationError("xray config has no inbounds")
    if not isinstance(config.get("remarks"), str) or not config["remarks"].strip():
        raise ValidationError("xray config has no remarks")


def render_config(config):
    return (json.dumps(config, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
