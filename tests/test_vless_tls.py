import copy
import itertools
import json

import pytest

from lantern_exporter.errors import ValidationError
from lantern_exporter.extract import Proxy, extract
from lantern_exporter.links import build_link, check_link, unique_names
from lantern_exporter.singbox import RESERVED_TAGS, build_profile
from lantern_exporter.xray import build_config, render_config

UUID = "11111111-2222-4333-8444-555555555555"
KEY = "A" * 43


def raw_vless(**changes):
    base = {"type": "vless", "tag": "v", "server": "10.0.0.2", "server_port": 443, "uuid": UUID}
    base.update(changes)
    return base


def tls(**changes):
    base = {"enabled": True}
    base.update(changes)
    return base


UTLS = {"enabled": True, "fingerprint": "chrome"}
REALITY = {"enabled": True, "public_key": KEY, "short_id": "0011"}


def extracted(raw):
    return extract({"options": {"outbounds": [raw]}})


def xray_outbound(raw):
    result = extracted(raw)
    assert len(result.proxies) == 1, result.skipped
    return build_config(result.proxies)["outbounds"][0]


def all_outputs(raw):
    proxy = extracted(raw).proxies[0]
    names = unique_names([proxy], reserved=RESERVED_TAGS)
    link = build_link(proxy, names[0])
    check_link(link, proxy)
    profile = build_profile([proxy], names)
    xray = build_config([proxy])
    return link, profile, xray


def test_vless_without_tls_has_no_security_block():
    item = xray_outbound(raw_vless())
    assert item["streamSettings"] == {"network": "raw"}
    assert item["settings"] == {"address": "10.0.0.2", "port": 443, "id": UUID, "encryption": "none"}


def test_vless_with_tls_and_sni_sets_server_name():
    item = xray_outbound(raw_vless(tls=tls(server_name="a.example.com")))
    assert item["streamSettings"] == {
        "network": "raw",
        "security": "tls",
        "tlsSettings": {"serverName": "a.example.com"},
    }


def test_vless_with_tls_without_sni_omits_server_name_instead_of_failing():
    item = xray_outbound(raw_vless(tls=tls()))
    assert item["streamSettings"] == {"network": "raw", "security": "tls", "tlsSettings": {}}


def test_vless_with_tls_fingerprint_but_without_sni():
    item = xray_outbound(raw_vless(tls=tls(utls=UTLS)))
    assert item["streamSettings"]["tlsSettings"] == {"fingerprint": "chrome"}


def test_vless_with_tls_sni_and_fingerprint():
    item = xray_outbound(raw_vless(tls=tls(server_name="a.example.com", utls=UTLS)))
    assert item["streamSettings"]["tlsSettings"] == {"serverName": "a.example.com", "fingerprint": "chrome"}


def test_vless_with_reality_and_valid_sni_is_complete():
    item = xray_outbound(raw_vless(flow="xtls-rprx-vision", tls=tls(server_name="a.example.com", utls=UTLS, reality=REALITY)))
    assert item["streamSettings"] == {
        "network": "raw",
        "security": "reality",
        "realitySettings": {
            "serverName": "a.example.com",
            "fingerprint": "chrome",
            "password": KEY,
            "shortId": "0011",
        },
    }
    assert item["settings"]["flow"] == "xtls-rprx-vision"


def test_vless_with_reality_without_sni_is_rejected_with_a_reason_and_the_pipeline_goes_on():
    good = raw_vless(tag="good", server_port=444)
    bad = raw_vless(tag="bad", tls=tls(utls=UTLS, reality=REALITY))
    result = extract({"options": {"outbounds": [bad, good]}})
    assert result.skipped == {"reality_without_sni:vless": 1}
    assert len(result.proxies) == 1 and result.counts["invalid"] == 1
    assert [o["tag"] for o in build_config(result.proxies)["outbounds"]][0] == "lantern-01-vless"


def test_reality_without_a_fingerprint_is_rejected_with_a_reason():
    result = extracted(raw_vless(tls=tls(server_name="a.example.com", reality=REALITY)))
    assert result.skipped == {"reality_without_utls:vless": 1} and result.proxies == []


def test_the_xray_builder_refuses_a_reality_proxy_without_sni_with_a_clean_error():
    proxy = extracted(raw_vless(tls=tls(server_name="a.example.com", utls=UTLS, reality=REALITY))).proxies[0]
    broken = copy.deepcopy(proxy.outbound)
    del broken["tls"]["server_name"]
    with pytest.raises(ValidationError):
        build_config([Proxy(proxy.kind, broken, "", "", "")])
    broken = copy.deepcopy(proxy.outbound)
    del broken["tls"]["utls"]
    with pytest.raises(ValidationError):
        build_config([Proxy(proxy.kind, broken, "", "", "")])


@pytest.mark.parametrize(
    "raw",
    [
        raw_vless(),
        raw_vless(tls=tls()),
        raw_vless(tls=tls(server_name="a.example.com")),
        raw_vless(tls=tls(utls=UTLS)),
        raw_vless(tls=tls(server_name="a.example.com", utls=UTLS)),
        raw_vless(tls=tls(server_name="a.example.com", utls=UTLS, reality=REALITY)),
    ],
    ids=["no-tls", "tls", "tls-sni", "tls-fp", "tls-sni-fp", "reality"],
)
def test_every_valid_vless_shape_produces_all_three_outputs_without_errors(raw):
    link, profile, xray = all_outputs(raw)
    assert link.startswith("vless://")
    assert len([o for o in profile["outbounds"] if o["type"] == "vless"]) == 1
    assert len([o for o in xray["outbounds"] if o["protocol"] == "vless"]) == 1
    json.loads(render_config(xray))


def test_no_combination_of_tls_fields_can_raise_an_unexpected_error():
    sni_options = [None, "a.example.com"]
    utls_options = [None, UTLS]
    reality_options = [None, REALITY]
    flow_options = ["", "xtls-rprx-vision"]
    for sni, utls, reality, flow in itertools.product(sni_options, utls_options, reality_options, flow_options):
        body = {"enabled": True}
        if sni:
            body["server_name"] = sni
        if utls:
            body["utls"] = utls
        if reality:
            body["reality"] = reality
        raw = raw_vless(flow=flow, tls=body) if flow else raw_vless(tls=body)
        result = extracted(raw)
        if result.proxies:
            build_config(result.proxies)
            proxy = result.proxies[0]
            check_link(build_link(proxy, "n"), proxy)
        else:
            assert list(result.skipped)[0].split(":")[0] in {"reality_without_sni", "reality_without_utls"}


def test_the_sni_less_tls_config_is_valid_in_every_other_output():
    link, profile, xray = all_outputs(raw_vless(tls=tls()))
    assert "sni=" not in link and "security=tls" in link
    vless_out = next(o for o in profile["outbounds"] if o["type"] == "vless")
    assert vless_out["tls"] == {"enabled": True}


@pytest.mark.parametrize("server", ["10.1.2.3", "172.16.0.9", "172.31.255.1", "192.168.1.1", "127.0.0.1", "169.254.1.1", "::1", "fe80::1", "fd00::1"])
def test_vless_without_security_is_kept_only_for_local_addresses(server):
    result = extracted(raw_vless(server=server))
    assert len(result.proxies) == 1 and result.skipped == {}


@pytest.mark.parametrize(
    "server",
    ["192.0.2.2", "203.0.113.5", "198.51.100.1", "8.8.8.8", "172.32.0.1", "172.15.255.1", "100.64.0.1", "2001:db8::1", "example.com", "localhost.example.org"],
)
def test_vless_without_security_to_a_public_address_is_rejected_with_a_reason(server):
    result = extracted(raw_vless(server=server))
    assert result.proxies == []
    assert result.skipped == {"vless_without_security:vless": 1}
    assert result.counts["invalid"] == 1


def test_a_rejected_plaintext_vless_never_stops_the_other_entries():
    plain = raw_vless(tag="plain", server="8.8.8.8")
    secure = raw_vless(tag="secure", server="8.8.4.4", tls=tls(server_name="a.example.com"))
    result = extract({"options": {"outbounds": [plain, secure]}})
    assert len(result.proxies) == 1 and result.skipped == {"vless_without_security:vless": 1}
    build_config(result.proxies)


def test_security_makes_a_public_address_acceptable():
    assert len(extracted(raw_vless(server="8.8.8.8", tls=tls())).proxies) == 1
    assert len(extracted(raw_vless(server="example.com", tls=tls(server_name="example.com"))).proxies) == 1


def test_flow_without_tls_keeps_its_own_specific_reason():
    result = extracted(raw_vless(server="8.8.8.8", flow="xtls-rprx-vision"))
    assert result.skipped == {"flow_without_tls:vless": 1}
