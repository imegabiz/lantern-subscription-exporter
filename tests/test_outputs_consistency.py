import hashlib
import json
import ssl
from urllib.parse import parse_qsl, unquote, urlsplit

import pytest
from certs import make_pem

from lantern_exporter.extract import extract
from lantern_exporter.pipeline import render
from lantern_exporter import constants as C

UUID = "11111111-2222-4333-8444-555555555555"
KEY = "A" * 43
SS_PASSWORD = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
PEM = make_pem()
PIN = hashlib.sha256(ssl.PEM_cert_to_DER_cert(PEM)).hexdigest()


def shadowsocks():
    return {
        "type": "shadowsocks",
        "tag": "ss",
        "server": "192.0.2.1",
        "server_port": 8388,
        "method": "2022-blake3-chacha20-poly1305",
        "password": SS_PASSWORD,
    }


def vless(**changes):
    base = {
        "type": "vless",
        "tag": "vl",
        "server": "192.0.2.2",
        "server_port": 443,
        "uuid": UUID,
        "flow": "xtls-rprx-vision",
        "packet_encoding": "xudp",
        "tls": {
            "enabled": True,
            "server_name": "www.example.com",
            "utls": {"enabled": True, "fingerprint": "chrome"},
            "reality": {"enabled": True, "public_key": KEY, "short_id": "0011aabb"},
        },
    }
    base.update(changes)
    return base


def hysteria2x(junk):
    return {
        "type": "hysteria2x",
        "tag": "hy",
        "server": "192.0.2.3",
        "server_port": 8443,
        "password": "hy2-password",
        "tls": {"enabled": True, "server_name": "api.push.apple.com", "certificate": PEM},
        "pre_initial_junk": junk,
    }


def build(outbounds, hysteria2_links="include"):
    extraction = extract({"options": {"outbounds": outbounds}})
    files, _ = render(extraction, 1, hysteria2_links)
    links = files[C.SUBSCRIPTION_LINKS_FILE].decode("utf-8").splitlines()
    profile = json.loads(files[C.SUBSCRIPTION_SINGBOX_FILE])
    xray = json.loads(files[C.SUBSCRIPTION_XRAY_FILE])
    return extraction, links, profile, xray


def singbox_proxy(profile, kind):
    return next(o for o in profile["outbounds"] if o["type"] == kind)


def xray_proxy(xray, protocol):
    return next(o for o in xray["outbounds"] if o["protocol"] == protocol)


def query(link):
    return dict(parse_qsl(urlsplit(link).query, keep_blank_values=True))


def test_shadowsocks_keeps_every_parameter_in_all_three_outputs():
    _, links, profile, xray = build([shadowsocks()])
    link = urlsplit(links[0])
    import base64

    method, _, password = base64.urlsafe_b64decode(link.username + "=" * (-len(link.username) % 4)).decode().partition(":")
    assert (link.hostname, link.port, method, password) == ("192.0.2.1", 8388, "2022-blake3-chacha20-poly1305", SS_PASSWORD)
    sb = singbox_proxy(profile, "shadowsocks")
    assert (sb["server"], sb["server_port"], sb["method"], sb["password"]) == ("192.0.2.1", 8388, "2022-blake3-chacha20-poly1305", SS_PASSWORD)
    settings = xray_proxy(xray, "shadowsocks")["settings"]
    assert settings == {"address": "192.0.2.1", "port": 8388, "method": "2022-blake3-chacha20-poly1305", "password": SS_PASSWORD}


def test_vless_reality_keeps_every_parameter_in_link_and_singbox():
    _, links, profile, xray = build([vless()])
    link = urlsplit(links[0])
    assert (link.username, link.hostname, link.port) == (UUID, "192.0.2.2", 443)
    assert query(links[0]) == {
        "encryption": "none",
        "type": "tcp",
        "flow": "xtls-rprx-vision",
        "packetEncoding": "xudp",
        "security": "reality",
        "sni": "www.example.com",
        "fp": "chrome",
        "pbk": KEY,
        "sid": "0011aabb",
    }
    sb = singbox_proxy(profile, "vless")
    assert sb["uuid"] == UUID and sb["flow"] == "xtls-rprx-vision" and sb["packet_encoding"] == "xudp"
    assert sb["tls"] == {
        "enabled": True,
        "server_name": "www.example.com",
        "utls": {"enabled": True, "fingerprint": "chrome"},
        "reality": {"enabled": True, "public_key": KEY, "short_id": "0011aabb"},
    }


def test_vless_reality_in_xray_keeps_everything_xray_can_express_and_nothing_else():
    _, _, _, xray = build([vless()])
    item = xray_proxy(xray, "vless")
    assert item["settings"] == {"address": "192.0.2.2", "port": 443, "id": UUID, "encryption": "none", "flow": "xtls-rprx-vision"}
    assert item["streamSettings"]["realitySettings"] == {
        "serverName": "www.example.com",
        "fingerprint": "chrome",
        "password": KEY,
        "shortId": "0011aabb",
    }
    assert "packet_encoding" not in json.dumps(item) and "packetEncoding" not in json.dumps(item)


@pytest.mark.parametrize("encoding", ["", "xudp"])
def test_the_vless_packet_encoding_is_in_link_and_singbox_only_when_it_is_set(encoding):
    _, links, profile, _ = build([vless(packet_encoding=encoding)])
    assert ("packetEncoding" in query(links[0])) is bool(encoding)
    assert ("packet_encoding" in singbox_proxy(profile, "vless")) is bool(encoding)


@pytest.mark.parametrize("junk", [True, False])
def test_hysteria2_keeps_every_parameter_and_the_junk_flag_only_where_it_can_live(junk):
    extraction, links, profile, xray = build([hysteria2x(junk)])
    link = urlsplit(links[0])
    assert (unquote(link.username), link.hostname, link.port) == ("hy2-password", "192.0.2.3", 8443)
    assert query(links[0]) == {"sni": "api.push.apple.com", "insecure": "1", "pinSHA256": PIN}
    sb = singbox_proxy(profile, "hysteria2")
    assert (sb["server"], sb["server_port"], sb["password"]) == ("192.0.2.3", 8443, "hy2-password")
    assert sb["tls"]["server_name"] == "api.push.apple.com"
    assert "\n".join(sb["tls"]["certificate"]) + "\n" == extraction.proxies[0].outbound["tls"]["certificate"]
    assert "pre_initial_junk" not in sb and "insecure" not in sb["tls"]
    item = xray_proxy(xray, "hysteria")
    stream = item["streamSettings"]
    assert item["settings"] == {"version": 2, "address": "192.0.2.3", "port": 8443}
    assert stream["tlsSettings"] == {"serverName": "api.push.apple.com", "alpn": ["h3"], "pinnedPeerCertSha256": PIN}
    assert stream["hysteriaSettings"] == {"version": 2, "auth": "hy2-password"}
    assert ("finalmask" in stream) is junk
    if junk:
        assert stream["finalmask"]["udp"][0]["settings"]["noise"] == [{"rand": "8-64", "delay": "10-20"}]


def test_the_certificate_pin_is_the_same_in_the_link_and_in_xray_and_matches_the_embedded_certificate():
    extraction, links, profile, xray = build([hysteria2x(True)])
    pem_lines = singbox_proxy(profile, "hysteria2")["tls"]["certificate"]
    der = ssl.PEM_cert_to_DER_cert("\n".join(pem_lines) + "\n")
    expected = hashlib.sha256(der).hexdigest()
    assert query(links[0])["pinSHA256"] == expected
    assert xray_proxy(xray, "hysteria")["streamSettings"]["tlsSettings"]["pinnedPeerCertSha256"] == expected


def test_a_mixed_set_keeps_the_same_entries_in_the_same_order_in_every_output():
    _, links, profile, xray = build([shadowsocks(), vless(), hysteria2x(True)])
    assert [urlsplit(l).scheme for l in links] == ["ss", "vless", "hysteria2"]
    assert [o["type"] for o in profile["outbounds"] if o["type"] in ("shadowsocks", "vless", "hysteria2")] == [
        "shadowsocks",
        "vless",
        "hysteria2",
    ]
    assert [o["protocol"] for o in xray["outbounds"] if o["tag"].startswith("lantern-")] == ["shadowsocks", "vless", "hysteria"]
    names = [unquote(urlsplit(l).fragment) for l in links]
    assert names == [o["tag"] for o in profile["outbounds"] if o["type"] in ("shadowsocks", "vless", "hysteria2")]


def test_every_extracted_proxy_appears_exactly_once_per_output():
    extraction, links, profile, xray = build([shadowsocks(), vless(), hysteria2x(False)])
    assert len(extraction.proxies) == len(links) == 3
    assert len([o for o in profile["outbounds"] if o["type"] in ("shadowsocks", "vless", "hysteria2")]) == 3
    assert len([o for o in xray["outbounds"] if o["tag"].startswith("lantern-")]) == 3


def test_vless_without_optional_parameters_gains_nothing_in_any_output():
    raw = vless(flow="", packet_encoding="", tls={"enabled": True, "server_name": "a.example.com"})
    _, links, profile, xray = build([raw])
    assert query(links[0]) == {"encryption": "none", "type": "tcp", "security": "tls", "sni": "a.example.com"}
    sb = singbox_proxy(profile, "vless")
    assert set(sb) == {"type", "tag", "server", "server_port", "uuid", "tls"}
    item = xray_proxy(xray, "vless")
    assert item["settings"] == {"address": "192.0.2.2", "port": 443, "id": UUID, "encryption": "none"}
    assert item["streamSettings"] == {"network": "raw", "security": "tls", "tlsSettings": {"serverName": "a.example.com"}}


def test_the_documented_gaps_are_exactly_these_and_nothing_else_is_dropped():
    _, links, profile, xray = build([vless(), hysteria2x(True)])
    vless_link, hy_link = links
    assert "packetEncoding" in query(vless_link) and "packetEncoding" not in json.dumps(xray)
    assert "junk" not in hy_link.lower() and "pre_initial_junk" not in json.dumps(profile)
    assert "finalmask" in json.dumps(xray)
