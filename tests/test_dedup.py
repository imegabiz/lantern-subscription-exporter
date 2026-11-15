import copy

import pytest
from certs import make_pem

from lantern_exporter.extract import canonical_identity, extract

UUID_A = "11111111-2222-4333-8444-555555555555"
UUID_B = "99999999-2222-4333-8444-555555555555"
KEY_A = "A" * 43
KEY_B = "B" * 43


def shadowsocks(**changes):
    base = {
        "type": "shadowsocks",
        "tag": "ss",
        "server": "192.0.2.1",
        "server_port": 443,
        "method": "2022-blake3-chacha20-poly1305",
        "password": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
    }
    base.update(changes)
    return base


def vless(**changes):
    base = {
        "type": "vless",
        "tag": "vl",
        "server": "192.0.2.2",
        "server_port": 443,
        "uuid": UUID_A,
        "flow": "xtls-rprx-vision",
        "tls": {
            "enabled": True,
            "server_name": "www.example.com",
            "utls": {"enabled": True, "fingerprint": "chrome"},
            "reality": {"enabled": True, "public_key": KEY_A, "short_id": "0011223344556677"},
        },
    }
    tls_changes = changes.pop("tls", None)
    base.update(changes)
    if tls_changes:
        base["tls"] = copy.deepcopy(base["tls"])
        for key, value in tls_changes.items():
            if isinstance(value, dict) and isinstance(base["tls"].get(key), dict):
                base["tls"][key] = dict(base["tls"][key], **value)
            else:
                base["tls"][key] = value
    return base


PEM_ONE = make_pem()
PEM_TWO = make_pem()


def hysteria2x(**changes):
    base = {
        "type": "hysteria2x",
        "tag": "hy",
        "server": "192.0.2.3",
        "server_port": 8443,
        "password": "pw",
        "tls": {"enabled": True, "server_name": "api.push.apple.com", "certificate": PEM_ONE},
        "pre_initial_junk": True,
    }
    tls_changes = changes.pop("tls", None)
    base.update(changes)
    if tls_changes:
        base["tls"] = dict(base["tls"], **tls_changes)
    return base


def usable(*outbounds):
    result = extract({"options": {"outbounds": list(outbounds)}})
    return result


def kept(*outbounds):
    return len(usable(*outbounds).proxies)


def test_two_identical_configs_are_duplicates():
    result = usable(shadowsocks(), shadowsocks())
    assert len(result.proxies) == 1 and result.counts["duplicate"] == 1


@pytest.mark.parametrize("make", [shadowsocks, vless, hysteria2x])
def test_only_the_tag_differing_is_still_a_duplicate(make):
    assert kept(make(tag="one"), make(tag="two")) == 1


def test_shadowsocks_same_ip_port_password_but_different_method_are_both_kept():
    first = shadowsocks(method="2022-blake3-chacha20-poly1305")
    second = shadowsocks(method="2022-blake3-aes-256-gcm")
    assert kept(first, second) == 2


@pytest.mark.parametrize(
    "changes",
    [{"server": "192.0.2.99"}, {"server_port": 444}, {"password": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8x"}],
)
def test_shadowsocks_any_connection_field_keeps_both(changes):
    assert kept(shadowsocks(), shadowsocks(**changes)) == 2


def test_vless_same_uuid_but_different_flow_are_both_kept():
    assert kept(vless(flow="xtls-rprx-vision"), vless(flow="")) == 2


def test_vless_different_sni_are_both_kept():
    assert kept(vless(), vless(tls={"server_name": "www.other.com"})) == 2


def test_vless_different_reality_short_id_are_both_kept():
    assert kept(vless(), vless(tls={"reality": {"short_id": "aabbccdd"}})) == 2


def test_vless_empty_versus_set_short_id_are_both_kept():
    plain = vless()
    plain["tls"]["reality"].pop("short_id")
    assert kept(plain, vless()) == 2


def test_vless_different_public_key_are_both_kept():
    assert kept(vless(), vless(tls={"reality": {"public_key": KEY_B}})) == 2


@pytest.mark.parametrize(
    "changes",
    [
        {"uuid": UUID_B},
        {"server": "192.0.2.77"},
        {"server_port": 8443},
        {"tls": {"utls": {"fingerprint": "firefox"}}},
        {"packet_encoding": "xudp"},
    ],
)
def test_vless_every_connection_field_keeps_both(changes):
    assert kept(vless(), vless(**changes)) == 2


def test_vless_explicit_defaults_equal_omitted_values():
    assert kept(vless(), vless(network="tcp", packet_encoding="")) == 1


def test_hysteria2_same_password_but_different_certificate_are_both_kept():
    assert kept(hysteria2x(), hysteria2x(tls={"certificate": PEM_TWO})) == 2


def test_hysteria2_different_sni_are_both_kept():
    assert kept(hysteria2x(), hysteria2x(tls={"server_name": "other.example.com"})) == 2


def test_hysteria2_different_pre_initial_junk_are_both_kept():
    assert kept(hysteria2x(pre_initial_junk=True), hysteria2x(pre_initial_junk=False)) == 2


@pytest.mark.parametrize(
    "changes",
    [{"password": "other"}, {"server": "192.0.2.50"}, {"server_port": 9443}],
)
def test_hysteria2_every_connection_field_keeps_both(changes):
    assert kept(hysteria2x(), hysteria2x(**changes)) == 2


def test_hysteria2_missing_null_and_false_junk_are_the_same_config():
    absent = hysteria2x()
    del absent["pre_initial_junk"]
    assert kept(absent, hysteria2x(pre_initial_junk=None), hysteria2x(pre_initial_junk=False)) == 1


def test_hysteria2_certificate_formatting_differences_are_the_same_config():
    messy = PEM_ONE.replace("\n", "\r\n") + "\n"
    assert kept(hysteria2x(), hysteria2x(tls={"certificate": messy})) == 1


def test_same_endpoint_in_different_protocols_is_never_a_duplicate():
    ss = shadowsocks(server="192.0.2.9", server_port=443)
    vl = vless(server="192.0.2.9", server_port=443)
    hy = hysteria2x(server="192.0.2.9", server_port=443)
    assert kept(ss, vl, hy) == 3


def test_case_and_notation_differences_of_the_same_endpoint_are_duplicates():
    assert kept(vless(uuid=UUID_A.upper()), vless()) == 1
    assert kept(vless(server="EXAMPLE.com"), vless(server="example.com")) == 1
    assert kept(vless(server="example.com."), vless(server="example.com")) == 1
    assert kept(vless(tls={"server_name": "WWW.Example.COM"}), vless()) == 1
    assert kept(vless(tls={"reality": {"short_id": "AABBCCDD"}}), vless(tls={"reality": {"short_id": "aabbccdd"}})) == 1
    assert kept(shadowsocks(server="2001:db8:0:0:0:0:0:1"), shadowsocks(server="2001:db8::1")) == 1


def test_password_is_case_sensitive():
    assert kept(shadowsocks(password="AbCd"), shadowsocks(password="abcd")) == 2
    assert kept(hysteria2x(password="AbCd"), hysteria2x(password="abcd")) == 2


def test_reality_public_key_is_case_sensitive():
    assert kept(vless(tls={"reality": {"public_key": "A" * 43}}), vless(tls={"reality": {"public_key": "a" * 43}})) == 2


def test_the_first_occurrence_is_kept_and_order_is_stable():
    first = shadowsocks(tag="first")
    second = shadowsocks(tag="second")
    result = usable(first, second, vless())
    assert [p.kind for p in result.proxies] == ["shadowsocks", "vless"]


def test_identity_does_not_mutate_its_input_and_ignores_the_tag():
    outbound = {
        "type": "hysteria2",
        "tag": "a",
        "server": "Example.com",
        "server_port": 1,
        "password": "p",
        "tls": {"enabled": True, "server_name": "Api.Push.Apple.com", "certificate": PEM_ONE},
        "pre_initial_junk": False,
    }
    snapshot = copy.deepcopy(outbound)
    first = canonical_identity(outbound)
    assert outbound == snapshot
    assert first == canonical_identity(dict(outbound, tag="b"))


def test_every_single_field_change_produces_a_different_identity():
    base = extract({"options": {"outbounds": [vless(), hysteria2x(), shadowsocks()]}}).proxies
    mutations = {
        "vless": [
            lambda o: o.update(uuid=UUID_B),
            lambda o: o.update(server="192.0.2.200"),
            lambda o: o.update(server_port=1234),
            lambda o: o.update(flow=""),
            lambda o: o["tls"].update(server_name="x.example.org"),
            lambda o: o["tls"]["utls"].update(fingerprint="safari"),
            lambda o: o["tls"]["reality"].update(public_key=KEY_B),
            lambda o: o["tls"]["reality"].update(short_id="ff"),
            lambda o: o.update(packet_encoding="xudp"),
        ],
        "hysteria2": [
            lambda o: o.update(password="zzz"),
            lambda o: o.update(server="192.0.2.201"),
            lambda o: o.update(server_port=4443),
            lambda o: o["tls"].update(server_name="y.example.org"),
            lambda o: o["tls"].update(certificate=PEM_TWO),
            lambda o: o.update(pre_initial_junk=not o["pre_initial_junk"]),
        ],
        "shadowsocks": [
            lambda o: o.update(password="zzz"),
            lambda o: o.update(server="192.0.2.202"),
            lambda o: o.update(server_port=4443),
            lambda o: o.update(method="aes-256-gcm"),
        ],
    }
    for proxy in base:
        reference = canonical_identity(proxy.outbound)
        for mutate in mutations[proxy.kind]:
            changed = copy.deepcopy(proxy.outbound)
            mutate(changed)
            assert canonical_identity(changed) != reference, (proxy.kind, mutate)
