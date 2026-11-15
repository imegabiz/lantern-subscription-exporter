import copy
import datetime

import pytest
from certs import make_pem

from lantern_exporter.errors import ExtractionError
from lantern_exporter.extract import extract


def test_real_shape_keeps_standard_and_skips_custom(config_response):
    result = extract(config_response)
    assert [p.kind for p in result.proxies] == ["shadowsocks", "vless", "hysteria2"]
    assert result.skipped == {"unsupported_type:samizdat": 2}
    assert result.country == "IR"
    ss, vless, hy2 = result.proxies
    assert hy2.outbound["type"] == "hysteria2"
    assert hy2.outbound["tls"]["server_name"] == "api.push.apple.com"
    assert hy2.outbound["tls"]["certificate"].startswith("-----BEGIN CERTIFICATE-----")
    assert hy2.outbound["pre_initial_junk"] is True
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
    assert [p.kind for p in result.proxies] == ["vless", "hysteria2"]
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
    assert [p.kind for p in result.proxies] == ["shadowsocks", "hysteria2"]
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
    assert len(result.proxies) == 3
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
    assert len(result.proxies) == 3
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


def _hysteria2x(config_response):
    return next(o for o in config_response["options"]["outbounds"] if o["type"] == "hysteria2x")


@pytest.mark.parametrize(
    "mutate,reason",
    [
        (lambda o: o["tls"].pop("certificate"), "missing_certificate:hysteria2x"),
        (lambda o: o["tls"].update(certificate="not a pem"), "invalid_certificate:hysteria2x"),
        (lambda o: o["tls"].update(certificate=""), "invalid_certificate:hysteria2x"),
        (lambda o: o["tls"].update(certificate=["x"]), "invalid_certificate:hysteria2x"),
        (lambda o: o["tls"].update(enabled=False), "tls_disabled:hysteria2x"),
        (lambda o: o["tls"].pop("server_name"), "invalid_server:hysteria2x"),
        (lambda o: o["tls"].update(insecure=True), "unsupported_options:hysteria2x(keys=insecure)"),
        (lambda o: o.update(obfs={"type": "salamander"}), "unsupported_options:hysteria2x(keys=obfs)"),
        (lambda o: o.update(password=""), "invalid_password:hysteria2x"),
        (lambda o: o.update(server_port=70000), "invalid_port:hysteria2x"),
        (lambda o: o.update(pre_initial_junk="yes"), "invalid_junk_flag:hysteria2x"),
    ],
)
def test_hysteria2x_rejections(config_response, mutate, reason):
    mutate(_hysteria2x(config_response))
    result = extract(config_response)
    assert [p.kind for p in result.proxies] == ["shadowsocks", "vless"]
    assert result.skipped[reason] == 1


def test_hysteria2x_certificate_given_as_lines_is_accepted(config_response):
    outbound = _hysteria2x(config_response)
    outbound["tls"]["certificate"] = outbound["tls"]["certificate"].strip().split("\n")
    hy2 = extract(config_response).proxies[2]
    assert hy2.outbound["tls"]["certificate"].endswith("-----END CERTIFICATE-----\n")


@pytest.mark.parametrize("value,expected", [(True, True), (False, False), (None, False)])
def test_hysteria2x_junk_flag_is_kept_with_the_documented_default(config_response, value, expected):
    _hysteria2x(config_response)["pre_initial_junk"] = value
    assert extract(config_response).proxies[2].outbound["pre_initial_junk"] is expected


def test_hysteria2x_missing_junk_flag_defaults_to_false(config_response):
    del _hysteria2x(config_response)["pre_initial_junk"]
    assert extract(config_response).proxies[2].outbound["pre_initial_junk"] is False


@pytest.mark.parametrize("bad", [1, 0, "true", [], {}])
def test_hysteria2x_non_boolean_junk_flag_is_rejected(config_response, bad):
    _hysteria2x(config_response)["pre_initial_junk"] = bad
    result = extract(config_response)
    assert result.skipped["invalid_junk_flag:hysteria2x"] == 1
    assert len(result.proxies) == 2


def test_counters_add_up_exactly(config_response):
    outbounds = config_response["options"]["outbounds"]
    outbounds.append({"type": "selector", "tag": "s", "outbounds": []})
    outbounds.append(dict(outbounds[0], tag="copy"))
    outbounds.append(dict(outbounds[0], tag="bad", password=""))
    outbounds.append("junk")
    outbounds.append({"type": "tuic", "tag": "t"})
    counts = extract(config_response).counts
    assert counts == {"total": 10, "usable": 3, "utility": 1, "unsupported": 3, "invalid": 2, "duplicate": 1}
    assert counts["total"] == sum(v for k, v in counts.items() if k != "total")


def test_no_truncation_even_with_many_configs(config_response):
    outbounds = config_response["options"]["outbounds"]
    base = outbounds[0]
    for index in range(250):
        outbounds.append(dict(base, tag="x%d" % index, server_port=2000 + index))
    result = extract(config_response)
    assert result.counts["usable"] == 253 and len(result.proxies) == 253
    assert [p.outbound.get("server_port") for p in result.proxies[3:6]] == [2000, 2001, 2002]


def test_processing_order_follows_the_response_order(config_response):
    outbounds = config_response["options"]["outbounds"]
    outbounds.reverse()
    assert [p.kind for p in extract(config_response).proxies] == ["hysteria2", "vless", "shadowsocks"]



def test_certificate_with_a_private_key_is_rejected(config_response):
    _hysteria2x(config_response)["tls"]["certificate"] = make_pem(include_private_key=True)
    result = extract(config_response)
    assert result.skipped["certificate_contains_private_key:hysteria2x"] == 1
    assert [p.kind for p in result.proxies] == ["shadowsocks", "vless"]


def test_certificate_chain_is_rejected_explicitly(config_response):
    _hysteria2x(config_response)["tls"]["certificate"] = make_pem() + make_pem()
    assert extract(config_response).skipped["unsupported_certificate_chain:hysteria2x"] == 1


def test_expired_and_not_yet_valid_certificates_are_rejected(config_response):
    now = datetime.datetime.now(datetime.timezone.utc)
    expired = make_pem(now - datetime.timedelta(days=30), now - datetime.timedelta(days=1))
    future = make_pem(now + datetime.timedelta(days=1), now + datetime.timedelta(days=30))
    _hysteria2x(config_response)["tls"]["certificate"] = expired
    assert extract(config_response).skipped["certificate_expired:hysteria2x"] == 1
    _hysteria2x(config_response)["tls"]["certificate"] = future
    assert extract(config_response).skipped["certificate_not_yet_valid:hysteria2x"] == 1


def test_valid_base64_that_is_not_a_certificate_is_rejected(config_response):
    body = "\n".join(["-----BEGIN CERTIFICATE-----", "QUJDREVGR0hJSktMTU5PUA==", "-----END CERTIFICATE-----"])
    _hysteria2x(config_response)["tls"]["certificate"] = body
    assert extract(config_response).skipped["invalid_certificate:hysteria2x"] == 1


def test_certificate_is_canonicalised(config_response):
    pem = make_pem()
    messy = pem.replace("\n", "\r\n") + "\n\n"
    _hysteria2x(config_response)["tls"]["certificate"] = messy
    stored = extract(config_response).proxies[2].outbound["tls"]["certificate"]
    assert stored == pem
    assert "\r" not in stored


def test_fixture_certificate_is_a_real_parsed_certificate(config_response):
    hy2 = extract(config_response).proxies[2]
    assert hy2.outbound["tls"]["certificate"].count("BEGIN CERTIFICATE") == 1
