import copy

import pytest

from lantern_exporter.errors import ExtractionError
from lantern_exporter.extract import extract


def test_real_shape_keeps_standard_and_skips_custom(config_response):
    result = extract(config_response)
    assert [p.kind for p in result.proxies] == ["shadowsocks", "vless"]
    assert result.skipped == {"unsupported_type:samizdat": 2, "unsupported_type:hysteria2x": 1}
    assert result.country == "IR"
    ss, vless = result.proxies
    assert ss.outbound["method"] == "2022-blake3-chacha20-poly1305"
    assert vless.outbound["flow"] == "xtls-rprx-vision"
    assert vless.outbound["tls"]["reality"]["public_key"]
    assert ss.country_code == "DE" and ss.city == "Frankfurt"


def test_utility_outbounds_are_ignored_silently(config_response):
    config_response["options"]["outbounds"] += [
        {"type": "selector", "tag": "s", "outbounds": []},
        {"type": "direct", "tag": "d"},
    ]
    assert extract(config_response).skipped.get("unsupported_type:selector") is None


@pytest.mark.parametrize(
    "mutate,reason",
    [
        (lambda o: o.update(password=""), "invalid_password:shadowsocks"),
        (lambda o: o.pop("password"), "invalid_password:shadowsocks"),
        (lambda o: o.update(server_port=0), "invalid_port:shadowsocks"),
        (lambda o: o.update(server_port="443"), "invalid_port:shadowsocks"),
        (lambda o: o.update(server=""), "invalid_server:shadowsocks"),
        (lambda o: o.update(server="a b"), "invalid_server:shadowsocks"),
        (lambda o: o.update(method="rc4"), "unsupported_method:shadowsocks"),
        (lambda o: o.update(plugin="obfs"), "unsupported_options:shadowsocks(keys=plugin)"),
        (lambda o: o.update(multiplex={"enabled": True}), "unsupported_options:shadowsocks(keys=multiplex)"),
    ],
)
def test_shadowsocks_rejections(config_response, mutate, reason):
    mutate(config_response["options"]["outbounds"][0])
    result = extract(config_response)
    assert [p.kind for p in result.proxies] == ["vless"]
    assert result.skipped[reason] == 1


@pytest.mark.parametrize(
    "mutate,reason",
    [
        (lambda o: o.update(uuid="not-a-uuid"), "invalid_uuid:vless"),
        (lambda o: o.update(flow="other"), "unsupported_flow:vless"),
        (lambda o: o.update(network="ws"), "unsupported_transport:vless"),
        (lambda o: o["tls"]["reality"].update(public_key="short"), "invalid_reality_key:vless"),
        (lambda o: o["tls"]["reality"].update(short_id="zz"), "invalid_short_id:vless"),
        (lambda o: o["tls"].pop("server_name"), "reality_without_sni:vless"),
        (lambda o: o["tls"].pop("utls"), "reality_without_utls:vless"),
        (lambda o: o["tls"].update(enabled=False), "tls_disabled:vless"),
        (lambda o: o["tls"].update(insecure=True), "unsupported_options:vless(keys=insecure)"),
        (lambda o: o["tls"]["utls"].update(fingerprint="weird"), "invalid_fingerprint:vless"),
        (lambda o: o.pop("tls"), "flow_without_tls:vless"),
    ],
)
def test_vless_rejections(config_response, mutate, reason):
    mutate(config_response["options"]["outbounds"][1])
    result = extract(config_response)
    assert [p.kind for p in result.proxies] == ["shadowsocks"]
    assert result.skipped[reason] == 1


def test_valid_short_id_is_kept(config_response):
    config_response["options"]["outbounds"][1]["tls"]["reality"]["short_id"] = "a1b2c3d4"
    vless = extract(config_response).proxies[1]
    assert vless.outbound["tls"]["reality"]["short_id"] == "a1b2c3d4"


def test_duplicates_are_removed(config_response):
    outbounds = config_response["options"]["outbounds"]
    outbounds.append(copy.deepcopy(outbounds[0]))
    outbounds[-1]["tag"] = "other-tag"
    result = extract(config_response)
    assert len(result.proxies) == 2
    assert result.skipped["duplicate:shadowsocks"] == 1


def test_missing_locations_are_tolerated(config_response):
    del config_response["outbound_locations"]
    result = extract(config_response)
    assert result.proxies[0].country_code == ""


@pytest.mark.parametrize("payload", [[], {}, {"options": []}, {"options": {}}, {"options": {"outbounds": "x"}}])
def test_structural_failures(payload):
    with pytest.raises(ExtractionError):
        extract(payload)


def test_garbage_entries_do_not_crash(config_response):
    config_response["options"]["outbounds"] += ["x", 5, None, {"tag": "t"}, {"type": 5}]
    result = extract(config_response)
    assert len(result.proxies) == 2
    assert result.skipped["not_an_object"] == 3
    assert result.skipped["missing_type"] == 2


def test_unknown_keys_are_named_in_the_reason_without_values(config_response):
    outbound = config_response["options"]["outbounds"][0]
    outbound["domain_resolver"] = "secret-value"
    outbound["bad key!"] = 1
    result = extract(config_response)
    reasons = [r for r in result.skipped if r.startswith("unsupported_options:shadowsocks")]
    assert reasons == ["unsupported_options:shadowsocks(keys=bad?key?,domain_resolver)"]
    assert "secret-value" not in str(result.skipped)
