import re
import ssl
import uuid
from dataclasses import dataclass, field

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
FINGERPRINTS = frozenset(
    {"chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "randomized"}
)


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


def _normalize_shadowsocks(raw):
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


def _normalize_vless(raw):
    _check_keys(raw, VLESS_KEYS)
    if raw.get("network") not in (None, "tcp"):
        raise _Reject("unsupported_transport")
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
    if "tls" in raw:
        outbound["tls"] = _normalize_tls(raw["tls"])
    elif flow:
        raise _Reject("flow_without_tls")
    return outbound


def _normalize_certificate(value):
    if isinstance(value, list) and value and all(isinstance(line, str) for line in value):
        value = "\n".join(value)
    if not isinstance(value, str) or not value.strip() or len(value) > MAX_CERTIFICATE_CHARS:
        raise _Reject("invalid_certificate")
    pem = value.strip() + "\n"
    try:
        ssl.PEM_cert_to_DER_cert(pem)
    except ValueError:
        raise _Reject("invalid_certificate")
    return pem


def _normalize_hysteria2x(raw):
    _check_keys(raw, HYSTERIA2X_KEYS)
    if raw.get("pre_initial_junk") not in (None, True, False):
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
            "certificate": _normalize_certificate(tls["certificate"]),
        },
    }


NORMALIZERS = {
    "shadowsocks": _normalize_shadowsocks,
    "vless": _normalize_vless,
    "hysteria2x": _normalize_hysteria2x,
}


def _identity(outbound):
    credential = outbound.get("password") or outbound.get("uuid")
    reality = outbound.get("tls", {}).get("reality", {})
    return (
        outbound["type"],
        outbound["server"],
        outbound["server_port"],
        credential,
        reality.get("public_key", ""),
    )


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


def extract(response):
    if not isinstance(response, dict):
        raise ExtractionError("config response is not an object")
    options = response.get("options")
    if not isinstance(options, dict):
        raise ExtractionError("config response has no options object")
    outbounds = options.get("outbounds")
    if not isinstance(outbounds, list):
        raise ExtractionError("config response has no outbounds list")
    locations = response.get("outbound_locations")
    skipped = {}
    proxies = []
    seen = set()

    def skip(reason):
        skipped[reason] = skipped.get(reason, 0) + 1

    for raw in outbounds:
        if not isinstance(raw, dict):
            skip("not_an_object")
            continue
        kind = raw.get("type")
        tag = raw.get("tag")
        if not isinstance(kind, str) or not kind:
            skip("missing_type")
            continue
        if kind in UTILITY_TYPES:
            continue
        normalizer = NORMALIZERS.get(kind)
        if normalizer is None:
            skip("unsupported_type:%s" % kind)
            continue
        try:
            outbound = normalizer(raw)
        except _Reject as exc:
            detail = "(%s)" % exc.args[1] if len(exc.args) > 1 else ""
            skip("%s:%s%s" % (exc.args[0], kind, detail))
            continue
        identity = _identity(outbound)
        if identity in seen:
            skip("duplicate:%s" % kind)
            continue
        seen.add(identity)
        code, country, city = _location(locations, tag)
        proxies.append(Proxy(kind=outbound["type"], outbound=outbound, country_code=code, country=country, city=city))
        if len(proxies) >= C.MAX_CONFIGS:
            break
    country = response.get("country")
    return Extraction(
        proxies=proxies,
        skipped=skipped,
        country=country if isinstance(country, str) else "",
    )
