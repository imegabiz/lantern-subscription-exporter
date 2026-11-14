import base64
import json
from urllib.parse import parse_qs, unquote, urlsplit

import pytest

from lantern_exporter.errors import ValidationError
from lantern_exporter.extract import extract
from lantern_exporter.links import build_link, check_link, display_name, flag, unique_names
from lantern_exporter.singbox import build_profile, render_profile, validate_profile


@pytest.fixture
def proxies(config_response):
    return extract(config_response).proxies


def test_flag_and_names(proxies):
    assert flag("DE") == "🇩🇪"
    assert flag("") == "" and flag("D1") == ""
    assert display_name(proxies[0]) == "🇩🇪 Germany · Frankfurt · SS"
    assert display_name(proxies[1]) == "🇩🇪 Germany · Frankfurt · VLESS"


def test_unique_names_suffix_and_reserved(proxies):
    names = unique_names([proxies[0], proxies[0]], reserved=("x",))
    assert names == ["🇩🇪 Germany · Frankfurt · SS", "🇩🇪 Germany · Frankfurt · SS #2"]


def test_shadowsocks_link_roundtrip(proxies):
    link = build_link(proxies[0], "name")
    parts = urlsplit(link)
    assert parts.scheme == "ss" and parts.port == 443
    decoded = base64.urlsafe_b64decode(parts.username + "=" * (-len(parts.username) % 4)).decode()
    assert decoded == "2022-blake3-chacha20-poly1305:" + proxies[0].outbound["password"]


def test_vless_reality_link_has_all_parameters(proxies):
    link = build_link(proxies[1], "🇩🇪 Germany · Frankfurt · VLESS")
    parts = urlsplit(link)
    query = {k: v[0] for k, v in parse_qs(parts.query, keep_blank_values=True).items()}
    assert query["security"] == "reality"
    assert query["flow"] == "xtls-rprx-vision"
    assert query["sni"] == "www.amazon.com"
    assert query["fp"] == "chrome"
    assert query["pbk"] == proxies[1].outbound["tls"]["reality"]["public_key"]
    assert query["sid"] == ""
    assert query["encryption"] == "none" and query["type"] == "tcp"
    assert unquote(parts.fragment) == "🇩🇪 Germany · Frankfurt · VLESS"


def test_check_link_detects_tampering(proxies):
    link = build_link(proxies[1], "n")
    with pytest.raises(ValidationError):
        check_link(link.replace("security=reality", "security=none"), proxies[1])
    with pytest.raises(ValidationError):
        check_link(link.replace(":443?", ":444?"), proxies[1])


def test_ipv6_host_is_bracketed(proxies):
    proxy = proxies[0]
    outbound = dict(proxy.outbound, server="2001:db8::1")
    from lantern_exporter.extract import Proxy

    v6 = Proxy(proxy.kind, outbound, proxy.country_code, proxy.country, proxy.city)
    link = build_link(v6, "n")
    assert "@[2001:db8::1]:443" in link


def test_profile_structure(proxies):
    names = unique_names(proxies, reserved=("Lantern", "Lantern Auto", "direct"))
    profile = build_profile(proxies, names)
    outbounds = {o["tag"]: o for o in profile["outbounds"]}
    assert outbounds["Lantern"]["default"] == "Lantern Auto"
    assert outbounds["Lantern Auto"]["outbounds"] == names
    assert outbounds[names[0]]["type"] == "shadowsocks"
    assert outbounds[names[1]]["tls"]["reality"]["enabled"] is True
    assert profile["route"]["final"] == "Lantern"
    assert json.loads(render_profile(profile)) == profile


def test_profile_rejects_inconsistent_input(proxies):
    with pytest.raises(ValidationError):
        build_profile(proxies, ["only-one"])
    with pytest.raises(ValidationError):
        build_profile(proxies, ["a", "a"])
    with pytest.raises(ValidationError):
        build_profile(proxies, ["Lantern", "b"])
    with pytest.raises(ValidationError):
        build_profile([], [])


def test_validate_profile_catches_dangling_references(proxies):
    names = unique_names(proxies)
    profile = build_profile(proxies, names)
    profile["route"]["final"] = "missing"
    with pytest.raises(ValidationError):
        validate_profile(profile, 2)
