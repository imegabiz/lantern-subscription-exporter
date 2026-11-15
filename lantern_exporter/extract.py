import copy
import hashlib
import ipaddress
import json
import re
import ssl
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

from cryptography import x509

from . import constants as C
from .errors import ExtractionError

UTILITY_TYPES = frozenset({"selector", "urltest", "direct", "block", "dns"})
SHADOWSOCKS_KEYS = frozenset({"type", "tag", "server", "server_port", "method", "password"})
VLESS_KEYS = frozenset({"type", "tag", "server", "server_port", "uuid", "flow", "tls", "network", "packet_encoding"})
HYSTERIA2X_KEYS = frozenset({"type", "tag", "server", "server_port", "password", "tls", "pre_initial_junk"})
HYSTERIA2X_TLS_KEYS = frozenset({"enabled", "server_name", "certificate"})
MAX_CERTIFICATE_CHARS = 8192
TLS_KEYS = frozenset({"enabled", "server_name", "utls", "reality"})
UTLS_KEYS = frozenset({"enabled", "fingerprint"})
REALITY_KEYS = frozenset({"enabled", "public_key", "short_id"})
REALITY_PUBLIC_KEY = re.compile(r"^[A-Za-z0-9_-]{43}$")
SHORT_ID = re.compile(r"^(?:[0-9a-fA-F]{2}){0,8}$")
HOST = re.compile(r"^[A-Za-z0-9.:_\-]+$")
PEM_BLOCK = re.compile(r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", re.S)
FINGERPRINTS = frozenset(
    {"chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "randomized"}
)
PACKET_ENCODINGS = ("", "xudp")


@dataclass(frozen=True)
class Proxy:
    kind: str
    outbound: dict
    country_code: str
    country: str
    city: str


@dataclass
class Extraction:
    proxies: list
    skipped: dict = field(default_factory=dict)
    counts: dict = field(default_factory=dict)
    country: str = ""


class _Reject(Exception):
    pass


def _check_keys(raw, allowed):
    extra = sorted(set(raw) - allowed)
    if extra:
        names = ",".join(re.sub(r"[^A-Za-z0-9_-]", "?", str(key))[:24] for key in extra[:6])
        raise _Reject("unsupported_options", "keys=" + names)


def _host(value):
    if not isinstance(value, str) or not value or not HOST.match(value):
        raise _Reject("invalid_server")
    return value


def _port(value):
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
        raise _Reject("invalid_port")
    return value


def _text(value, reason):
    if not isinstance(value, str) or not value.strip():
        raise _Reject(reason)
    return value


def _normalize_shadowsocks(raw, now):
    _check_keys(raw, SHADOWSOCKS_KEYS)
    method = _text(raw.get("method"), "invalid_method")
    if method not in C.SHADOWSOCKS_METHODS:
        raise _Reject("unsupported_method")
    return {
        "type": "shadowsocks",
        "server": _host(raw.get("server")),
        "server_port": _port(raw.get("server_port")),
        "method": method,
        "password": _text(raw.get("password"), "invalid_password"),
    }


def _normalize_tls(raw):
    if not isinstance(raw, dict):
        raise _Reject("unsupported_options", "tls")
    _check_keys(raw, TLS_KEYS)
    if raw.get("enabled") is not True:
        raise _Reject("tls_disabled")
    tls = {"enabled": True}
    server_name = raw.get("server_name")
    if server_name is not None:
        tls["server_name"] = _host(server_name)
    utls = raw.get("utls")
    if utls is not None:
        if not isinstance(utls, dict):
            raise _Reject("unsupported_options", "utls")
        _check_keys(utls, UTLS_KEYS)
        if utls.get("enabled") is True:
            fingerprint = utls.get("fingerprint")
            if fingerprint not in FINGERPRINTS:
                raise _Reject("invalid_fingerprint")
            tls["utls"] = {"enabled": True, "fingerprint": fingerprint}
    reality = raw.get("reality")
    if reality is not None:
        if not isinstance(reality, dict):
            raise _Reject("unsupported_options", "reality")
        _check_keys(reality, REALITY_KEYS)
        if reality.get("enabled") is True:
            public_key = reality.get("public_key")
            if not isinstance(public_key, str) or not REALITY_PUBLIC_KEY.match(public_key):
                raise _Reject("invalid_reality_key")
            short_id = reality.get("short_id", "")
            if not isinstance(short_id, str) or not SHORT_ID.match(short_id):
                raise _Reject("invalid_short_id")
            if "server_name" not in tls:
                raise _Reject("reality_without_sni")
            if "utls" not in tls:
                raise _Reject("reality_without_utls")
            entry = {"enabled": True, "public_key": public_key}
            if short_id:
                entry["short_id"] = short_id
            tls["reality"] = entry
    return tls


def _normalize_vless(raw, now):
    _check_keys(raw, VLESS_KEYS)
    if raw.get("network") not in (None, "tcp"):
        raise _Reject("unsupported_transport")
    packet_encoding = raw.get("packet_encoding")
    if packet_encoding is None:
        packet_encoding = ""
    if packet_encoding not in PACKET_ENCODINGS:
        raise _Reject("unsupported_packet_encoding")
    flow = raw.get("flow", "")
    if flow not in ("", "xtls-rprx-vision"):
        raise _Reject("unsupported_flow")
    try:
        user = str(uuid.UUID(_text(raw.get("uuid"), "invalid_uuid")))
    except ValueError:
        raise _Reject("invalid_uuid")
    outbound = {
        "type": "vless",
        "server": _host(raw.get("server")),
        "server_port": _port(raw.get("server_port")),
        "uuid": user,
    }
    if flow:
        outbound["flow"] = flow
    if raw.get("network") == "tcp":
        outbound["network"] = "tcp"
    if packet_encoding:
        outbound["packet_encoding"] = packet_encoding
    if "tls" in raw:
        outbound["tls"] = _normalize_tls(raw["tls"])
    elif flow:
        raise _Reject("flow_without_tls")
    return outbound


def _normalize_certificate(value, now):
    if isinstance(value, list) and value and all(isinstance(line, str) for line in value):
        value = "\n".join(value)
    if not isinstance(value, str) or not value.strip() or len(value) > MAX_CERTIFICATE_CHARS:
        raise _Reject("invalid_certificate")
    if "PRIVATE KEY" in value.upper():
        raise _Reject("certificate_contains_private_key")
    blocks = PEM_BLOCK.findall(value)
    if len(blocks) > 1:
        raise _Reject("unsupported_certificate_chain")
    if len(blocks) != 1:
        raise _Reject("invalid_certificate")
    try:
        der = ssl.PEM_cert_to_DER_cert("-----BEGIN CERTIFICATE-----" + blocks[0] + "-----END CERTIFICATE-----")
        parsed = x509.load_der_x509_certificate(der)
    except Exception:
        raise _Reject("invalid_certificate")
    if parsed.not_valid_after_utc < now:
        raise _Reject("certificate_expired")
    if parsed.not_valid_before_utc > now:
        raise _Reject("certificate_not_yet_valid")
    return ssl.DER_cert_to_PEM_cert(der)


def _normalize_hysteria2x(raw, now):
    _check_keys(raw, HYSTERIA2X_KEYS)
    junk = raw.get("pre_initial_junk")
    if junk not in (None, True, False) or (junk is not None and not isinstance(junk, bool)):
        raise _Reject("invalid_junk_flag")
    tls = raw.get("tls")
    if not isinstance(tls, dict):
        raise _Reject("unsupported_options", "tls")
    _check_keys(tls, HYSTERIA2X_TLS_KEYS)
    if tls.get("enabled") is not True:
        raise _Reject("tls_disabled")
    if "certificate" not in tls:
        raise _Reject("missing_certificate")
    return {
        "type": "hysteria2",
        "server": _host(raw.get("server")),
        "server_port": _port(raw.get("server_port")),
        "password": _text(raw.get("password"), "invalid_password"),
        "tls": {
            "enabled": True,
            "server_name": _host(tls.get("server_name")),
            "certificate": _normalize_certificate(tls["certificate"], now),
        },
        "pre_initial_junk": bool(junk),
    }


NORMALIZERS = {
    "shadowsocks": _normalize_shadowsocks,
    "vless": _normalize_vless,
    "hysteria2x": _normalize_hysteria2x,
}


def _canonical_host(value):
    text = value.strip().lower().rstrip(".")
    try:
        return ipaddress.ip_address(text).compressed
    except ValueError:
        return text


def canonical_identity(outbound):
    data = copy.deepcopy(outbound)
    data.pop("tag", None)
    data["server"] = _canonical_host(data["server"])
    kind = data["type"]
    tls = data.get("tls")
    if isinstance(tls, dict) and "server_name" in tls:
        tls["server_name"] = tls["server_name"].lower()
    if kind == "vless":
        data["uuid"] = data["uuid"].lower()
        data.setdefault("flow", "")
        data.setdefault("network", "tcp")
        data.setdefault("packet_encoding", "")
        if isinstance(tls, dict):
            reality = tls.get("reality")
            if isinstance(reality, dict):
                reality["short_id"] = reality.get("short_id", "").lower()
    if kind == "hysteria2":
        der = ssl.PEM_cert_to_DER_cert(tls["certificate"])
        tls["certificate"] = hashlib.sha256(der).hexdigest()
        data["pre_initial_junk"] = bool(data.get("pre_initial_junk"))
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def _location(locations, tag):
    entry = locations.get(tag) if isinstance(locations, dict) else None
    if not isinstance(entry, dict):
        return "", "", ""
    code = entry.get("country_code")
    country = entry.get("country")
    city = entry.get("city")
    code = code.upper() if isinstance(code, str) and re.match(r"^[A-Za-z]{2}$", code) else ""
    return (
        code,
        country.strip() if isinstance(country, str) else "",
        city.strip() if isinstance(city, str) else "",
    )


def extract(response, now=None):
    if not isinstance(response, dict):
        raise ExtractionError("config response is not an object")
    options = response.get("options")
    if not isinstance(options, dict):
        raise ExtractionError("config response has no options object")
    outbounds = options.get("outbounds")
    if not isinstance(outbounds, list):
        raise ExtractionError("config response has no outbounds list")
    moment = now if now is not None else datetime.now(timezone.utc)
    locations = response.get("outbound_locations")
    skipped = {}
    counts = {"total": len(outbounds), "usable": 0, "utility": 0, "unsupported": 0, "invalid": 0, "duplicate": 0}
    proxies = []
    seen = set()

    def skip(reason, bucket):
        skipped[reason] = skipped.get(reason, 0) + 1
        counts[bucket] += 1

    for raw in outbounds:
        if not isinstance(raw, dict):
            skip("not_an_object", "invalid")
            continue
        kind = raw.get("type")
        tag = raw.get("tag")
        if not isinstance(kind, str) or not kind:
            skip("missing_type", "invalid")
            continue
        if kind in UTILITY_TYPES:
            counts["utility"] += 1
            continue
        normalizer = NORMALIZERS.get(kind)
        if normalizer is None:
            skip("unsupported_type:%s" % kind, "unsupported")
            continue
        try:
            outbound = normalizer(raw, moment)
        except _Reject as exc:
            detail = "(%s)" % exc.args[1] if len(exc.args) > 1 else ""
            bucket = "unsupported" if exc.args[0].startswith("unsupported") else "invalid"
            skip("%s:%s%s" % (exc.args[0], kind, detail), bucket)
            continue
        identity = canonical_identity(outbound)
        if identity in seen:
            skip("duplicate:%s" % kind, "duplicate")
            continue
        seen.add(identity)
        code, country, city = _location(locations, tag)
        proxies.append(Proxy(kind=outbound["type"], outbound=outbound, country_code=code, country=country, city=city))
        counts["usable"] += 1
    country = response.get("country")
    return Extraction(
        proxies=proxies,
        skipped=skipped,
        counts=counts,
        country=country if isinstance(country, str) else "",
    )
