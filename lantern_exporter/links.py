import base64
import hashlib
import ssl
from urllib.parse import quote, urlsplit, parse_qs, unquote

from .errors import ValidationError

PROTOCOL_LABELS = {"shadowsocks": "SS", "vless": "VLESS", "hysteria2": "HY2"}


def flag(country_code):
    if len(country_code) != 2 or not country_code.isalpha():
        return ""
    return "".join(chr(0x1F1E6 + ord(ch) - ord("A")) for ch in country_code.upper())


def display_name(proxy):
    parts = []
    head = " ".join(part for part in (flag(proxy.country_code), proxy.country) if part)
    if head:
        parts.append(head)
    if proxy.city:
        parts.append(proxy.city)
    parts.append(PROTOCOL_LABELS.get(proxy.kind, proxy.kind.upper()))
    return " · ".join(parts)


def unique_names(proxies, reserved=()):
    taken = set(reserved)
    names = []
    for proxy in proxies:
        base = display_name(proxy)
        candidate = base
        counter = 2
        while candidate in taken:
            candidate = "%s #%d" % (base, counter)
            counter += 1
        taken.add(candidate)
        names.append(candidate)
    return names


def _authority(host, port):
    if ":" in host:
        host = "[%s]" % host
    return "%s:%d" % (host, port)


def _shadowsocks_link(outbound, name):
    userinfo = "%s:%s" % (outbound["method"], outbound["password"])
    encoded = base64.urlsafe_b64encode(userinfo.encode("utf-8")).decode("ascii").rstrip("=")
    return "ss://%s@%s#%s" % (encoded, _authority(outbound["server"], outbound["server_port"]), quote(name, safe=""))


def _vless_link(outbound, name):
    params = [("encryption", "none")]
    if outbound.get("flow"):
        params.append(("flow", outbound["flow"]))
    if outbound.get("packet_encoding"):
        params.append(("packetEncoding", outbound["packet_encoding"]))
    tls = outbound.get("tls")
    if not tls:
        params.append(("security", "none"))
    else:
        reality = tls.get("reality")
        params.append(("security", "reality" if reality else "tls"))
        if tls.get("server_name"):
            params.append(("sni", tls["server_name"]))
        if tls.get("utls"):
            params.append(("fp", tls["utls"]["fingerprint"]))
        if reality:
            params.append(("pbk", reality["public_key"]))
            params.append(("sid", reality.get("short_id", "")))
    params.append(("type", "tcp"))
    query = "&".join("%s=%s" % (key, quote(value, safe="")) for key, value in params)
    return "vless://%s@%s?%s#%s" % (
        outbound["uuid"],
        _authority(outbound["server"], outbound["server_port"]),
        query,
        quote(name, safe=""),
    )


def certificate_pin(pem):
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem)).hexdigest()


def _hysteria2_link(outbound, name):
    tls = outbound["tls"]
    params = [
        ("sni", tls["server_name"]),
        ("insecure", "1"),
        ("pinSHA256", certificate_pin(tls["certificate"])),
    ]
    query = "&".join("%s=%s" % (key, quote(value, safe="")) for key, value in params)
    return "hysteria2://%s@%s?%s#%s" % (
        quote(outbound["password"], safe=""),
        _authority(outbound["server"], outbound["server_port"]),
        query,
        quote(name, safe=""),
    )


def build_link(proxy, name):
    if proxy.kind == "shadowsocks":
        link = _shadowsocks_link(proxy.outbound, name)
    elif proxy.kind == "vless":
        link = _vless_link(proxy.outbound, name)
    elif proxy.kind == "hysteria2":
        link = _hysteria2_link(proxy.outbound, name)
    else:
        raise ValidationError("cannot build a link for type %s" % proxy.kind)
    check_link(link, proxy)
    return link


def _decode_userinfo(value):
    padded = value + "=" * (-len(value) % 4)
    try:
        return base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8")
    except (ValueError, UnicodeError) as exc:
        raise ValidationError("shadowsocks userinfo is not valid base64") from exc


def check_link(link, proxy):
    parts = urlsplit(link)
    outbound = proxy.outbound
    if parts.hostname is None or parts.port != outbound["server_port"]:
        raise ValidationError("link has a wrong host or port")
    if parts.hostname.lower() != outbound["server"].lower():
        raise ValidationError("link host does not match the outbound")
    if not unquote(parts.fragment):
        raise ValidationError("link has no name")
    if proxy.kind == "shadowsocks":
        if parts.scheme != "ss":
            raise ValidationError("wrong scheme for shadowsocks")
        method, _, password = _decode_userinfo(parts.username or "").partition(":")
        if method != outbound["method"] or password != outbound["password"]:
            raise ValidationError("shadowsocks credentials do not round-trip")
        return
    if proxy.kind == "hysteria2":
        if parts.scheme != "hysteria2" or unquote(parts.username or "") != outbound["password"]:
            raise ValidationError("wrong hysteria2 identity")
        flat = {key: values[0] for key, values in parse_qs(parts.query, keep_blank_values=True).items()}
        if flat.get("sni") != outbound["tls"]["server_name"] or flat.get("insecure") != "1":
            raise ValidationError("hysteria2 tls parameters are wrong")
        if flat.get("pinSHA256") != certificate_pin(outbound["tls"]["certificate"]):
            raise ValidationError("hysteria2 certificate pin does not match")
        return
    if parts.scheme != "vless" or parts.username != outbound["uuid"]:
        raise ValidationError("wrong vless identity")
    query = parse_qs(parts.query, keep_blank_values=True)
    flat = {key: values[0] for key, values in query.items()}
    tls = outbound.get("tls")
    expected_security = "none" if not tls else ("reality" if tls.get("reality") else "tls")
    if flat.get("security") != expected_security:
        raise ValidationError("vless security parameter is wrong")
    if expected_security == "reality":
        if flat.get("pbk") != tls["reality"]["public_key"] or not flat.get("sni") or not flat.get("fp"):
            raise ValidationError("vless reality parameters are incomplete")
    if outbound.get("flow") and flat.get("flow") != outbound["flow"]:
        raise ValidationError("vless flow parameter is wrong")
    if outbound.get("packet_encoding") and flat.get("packetEncoding") != outbound["packet_encoding"]:
        raise ValidationError("vless packet encoding parameter is wrong")
