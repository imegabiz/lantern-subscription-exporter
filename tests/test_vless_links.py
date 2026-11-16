import copy
from urllib.parse import parse_qsl, quote, urlsplit

import pytest

from lantern_exporter.errors import ValidationError
from lantern_exporter.extract import extract
from lantern_exporter.links import build_link, check_link

UUID = "11111111-2222-4333-8444-555555555555"
OTHER_UUID = "99999999-2222-4333-8444-555555555555"
KEY = "A" * 43
OTHER_KEY = "B" * 43

FULL = {
    "type": "vless",
    "tag": "v",
    "server": "192.0.2.2",
    "server_port": 443,
    "uuid": UUID,
    "flow": "xtls-rprx-vision",
    "network": "tcp",
    "packet_encoding": "xudp",
    "tls": {
        "enabled": True,
        "server_name": "www.example.com",
        "utls": {"enabled": True, "fingerprint": "chrome"},
        "reality": {"enabled": True, "public_key": KEY, "short_id": "0011aabb"},
    },
}


def proxy_for(raw):
    result = extract({"options": {"outbounds": [raw]}})
    assert len(result.proxies) == 1, result.skipped
    return result.proxies[0]


def variant(**changes):
    raw = copy.deepcopy(FULL)
    for key, value in changes.items():
        if value is None:
            raw.pop(key, None)
        else:
            raw[key] = value
    return raw


def split(link):
    head, _, fragment = link.partition("#")
    base, _, query = head.partition("?")
    return base, parse_qsl(query, keep_blank_values=True), fragment


def join(base, pairs, fragment):
    query = "&".join("%s=%s" % (quote(key, safe=""), quote(value, safe="")) for key, value in pairs)
    return "%s?%s#%s" % (base, query, fragment)


def edit(link, function):
    base, pairs, fragment = split(link)
    pairs = function(list(pairs))
    return join(base, pairs, fragment)


def drop(link, name):
    return edit(link, lambda pairs: [(k, v) for k, v in pairs if k != name])


def change(link, name, value):
    return edit(link, lambda pairs: [(k, value if k == name else v) for k, v in pairs])


def add(link, name, value):
    return edit(link, lambda pairs: pairs + [(name, value)])


@pytest.fixture
def full():
    proxy = proxy_for(FULL)
    return proxy, build_link(proxy, "name")


ALL_PARAMS = ["encryption", "type", "flow", "packetEncoding", "security", "sni", "fp", "pbk", "sid"]
CHANGED = {
    "encryption": "aes-128-gcm",
    "type": "ws",
    "flow": "xtls-rprx-vision-udp443",
    "packetEncoding": "packetaddr",
    "security": "tls",
    "sni": "www.other.com",
    "fp": "firefox",
    "pbk": OTHER_KEY,
    "sid": "ffff",
}


def test_the_complete_link_contains_exactly_the_expected_parameters(full):
    _, link = full
    _, pairs, _ = split(link)
    assert sorted(k for k, _ in pairs) == sorted(ALL_PARAMS)
    assert dict(pairs) == {
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


def test_the_untouched_complete_link_is_accepted(full):
    proxy, link = full
    check_link(link, proxy)


def test_parameter_order_does_not_matter(full):
    proxy, link = full
    check_link(edit(link, lambda pairs: list(reversed(pairs))), proxy)


@pytest.mark.parametrize("name", ALL_PARAMS)
def test_a_removed_parameter_is_rejected(full, name):
    proxy, link = full
    with pytest.raises(ValidationError) as info:
        check_link(drop(link, name), proxy)
    assert "missing=" + name in str(info.value)


@pytest.mark.parametrize("name", ALL_PARAMS)
def test_a_changed_parameter_is_rejected(full, name):
    proxy, link = full
    with pytest.raises(ValidationError) as info:
        check_link(change(link, name, CHANGED[name]), proxy)
    assert "changed=" + name in str(info.value)


@pytest.mark.parametrize("name", ALL_PARAMS)
def test_a_parameter_set_to_an_empty_value_is_rejected(full, name):
    proxy, link = full
    with pytest.raises(ValidationError):
        check_link(change(link, name, ""), proxy)


@pytest.mark.parametrize("name", ALL_PARAMS)
def test_a_repeated_parameter_with_the_same_value_is_rejected(full, name):
    proxy, link = full
    value = dict(split(link)[1])[name]
    with pytest.raises(ValidationError) as info:
        check_link(add(link, name, value), proxy)
    assert "repeats" in str(info.value)


@pytest.mark.parametrize("name", ALL_PARAMS)
def test_a_repeated_parameter_with_a_contradicting_value_is_rejected(full, name):
    proxy, link = full
    with pytest.raises(ValidationError) as info:
        check_link(add(link, name, CHANGED[name]), proxy)
    assert "repeats" in str(info.value)


@pytest.mark.parametrize("name", ALL_PARAMS)
def test_a_contradicting_value_placed_first_is_rejected(full, name):
    proxy, link = full
    with pytest.raises(ValidationError):
        check_link(edit(link, lambda pairs: [(name, CHANGED[name])] + pairs), proxy)


@pytest.mark.parametrize("extra", ["allowInsecure", "insecure", "headerType", "path", "host", "alpn", "mode", "serviceName", "spx"])
def test_a_parameter_that_the_source_does_not_have_is_rejected(full, extra):
    proxy, link = full
    with pytest.raises(ValidationError) as info:
        check_link(add(link, extra, "1"), proxy)
    assert "unexpected=" + extra in str(info.value)


def test_uuid_correct_is_accepted_and_changed_is_rejected(full):
    proxy, link = full
    check_link(link, proxy)
    with pytest.raises(ValidationError):
        check_link(link.replace(UUID, OTHER_UUID), proxy)


def test_server_correct_is_accepted_and_changed_is_rejected(full):
    proxy, link = full
    check_link(link, proxy)
    with pytest.raises(ValidationError):
        check_link(link.replace("@192.0.2.2:", "@192.0.2.3:"), proxy)


def test_server_port_correct_is_accepted_and_changed_is_rejected(full):
    proxy, link = full
    check_link(link, proxy)
    with pytest.raises(ValidationError):
        check_link(link.replace(":443?", ":444?"), proxy)


def test_the_scheme_is_checked(full):
    proxy, link = full
    with pytest.raises(ValidationError):
        check_link(link.replace("vless://", "vmess://", 1), proxy)


def test_userinfo_with_a_password_is_rejected(full):
    proxy, link = full
    with pytest.raises(ValidationError):
        check_link(link.replace(UUID + "@", UUID + ":secret@"), proxy)


def test_an_unexpected_path_is_rejected(full):
    proxy, link = full
    with pytest.raises(ValidationError):
        check_link(link.replace(":443?", ":443/extra?"), proxy)


@pytest.mark.parametrize("query_suffix", ["&", "&&", "&flag", "&=x"])
def test_malformed_query_tokens_are_rejected(full, query_suffix):
    proxy, link = full
    head, _, fragment = link.partition("#")
    with pytest.raises(ValidationError):
        check_link(head + query_suffix + "#" + fragment, proxy)


def test_a_missing_fragment_is_rejected(full):
    proxy, link = full
    with pytest.raises(ValidationError):
        check_link(link.split("#")[0], proxy)


def test_a_non_numeric_port_is_rejected_cleanly(full):
    proxy, link = full
    with pytest.raises(ValidationError):
        check_link(link.replace(":443?", ":abc?"), proxy)


def test_host_letter_case_is_not_a_difference():
    proxy = proxy_for(variant(server="Example.COM"))
    link = build_link(proxy, "n").replace("Example.COM", "example.com")
    check_link(link, proxy)


def test_ipv6_hosts_are_checked():
    proxy = proxy_for(variant(server="2001:db8::1"))
    link = build_link(proxy, "n")
    check_link(link, proxy)
    with pytest.raises(ValidationError):
        check_link(link.replace("2001:db8::1", "2001:db8::2"), proxy)


MINIMAL = [
    (
        "no tls",
        variant(flow=None, network=None, packet_encoding=None, tls=None, server="10.0.0.2"),
        {"encryption": "none", "type": "tcp", "security": "none"},
    ),
    (
        "network only",
        variant(flow=None, packet_encoding=None, tls=None, server="10.0.0.2"),
        {"encryption": "none", "type": "tcp", "security": "none"},
    ),
    (
        "packet encoding only",
        variant(flow=None, network=None, tls=None, server="10.0.0.2"),
        {"encryption": "none", "type": "tcp", "security": "none", "packetEncoding": "xudp"},
    ),
    (
        "tls with flow only",
        variant(network=None, packet_encoding=None, tls={"enabled": True}),
        {"encryption": "none", "type": "tcp", "security": "tls", "flow": "xtls-rprx-vision"},
    ),
    (
        "tls with sni only",
        variant(flow=None, network=None, packet_encoding=None, tls={"enabled": True, "server_name": "a.example.com"}),
        {"encryption": "none", "type": "tcp", "security": "tls", "sni": "a.example.com"},
    ),
    (
        "tls with fingerprint only",
        variant(
            flow=None,
            network=None,
            packet_encoding=None,
            tls={"enabled": True, "utls": {"enabled": True, "fingerprint": "safari"}},
        ),
        {"encryption": "none", "type": "tcp", "security": "tls", "fp": "safari"},
    ),
    (
        "tls with sni and fingerprint",
        variant(
            flow=None,
            network=None,
            packet_encoding=None,
            tls={"enabled": True, "server_name": "a.example.com", "utls": {"enabled": True, "fingerprint": "safari"}},
        ),
        {"encryption": "none", "type": "tcp", "security": "tls", "sni": "a.example.com", "fp": "safari"},
    ),
    (
        "reality without short id",
        variant(
            flow=None,
            network=None,
            packet_encoding=None,
            tls={
                "enabled": True,
                "server_name": "a.example.com",
                "utls": {"enabled": True, "fingerprint": "chrome"},
                "reality": {"enabled": True, "public_key": KEY},
            },
        ),
        {
            "encryption": "none",
            "type": "tcp",
            "security": "reality",
            "sni": "a.example.com",
            "fp": "chrome",
            "pbk": KEY,
            "sid": "",
        },
    ),
]


@pytest.mark.parametrize("label,raw,expected", MINIMAL, ids=[m[0] for m in MINIMAL])
def test_a_link_contains_exactly_what_the_source_has(label, raw, expected):
    proxy = proxy_for(raw)
    link = build_link(proxy, "n")
    assert dict(split(link)[1]) == expected
    assert len(split(link)[1]) == len(expected)
    check_link(link, proxy)


ABSENT = [
    (label, raw, name)
    for label, raw, expected in MINIMAL
    for name in ["flow", "packetEncoding", "sni", "fp", "pbk", "sid"]
    if name not in expected
]


@pytest.mark.parametrize("label,raw,name", ABSENT, ids=["%s+%s" % (a[0], a[2]) for a in ABSENT])
def test_adding_a_parameter_that_the_source_lacks_is_rejected(label, raw, name):
    proxy = proxy_for(raw)
    link = build_link(proxy, "n")
    with pytest.raises(ValidationError):
        check_link(add(link, name, CHANGED.get(name, "x")), proxy)


@pytest.mark.parametrize("label,raw,expected", MINIMAL, ids=[m[0] for m in MINIMAL])
def test_removing_any_present_parameter_is_rejected(label, raw, expected):
    proxy = proxy_for(raw)
    link = build_link(proxy, "n")
    for name in expected:
        with pytest.raises(ValidationError):
            check_link(drop(link, name), proxy)


def test_an_empty_short_id_must_stay_present_and_empty():
    raw = variant(
        flow=None,
        network=None,
        packet_encoding=None,
        tls={
            "enabled": True,
            "server_name": "a.example.com",
            "utls": {"enabled": True, "fingerprint": "chrome"},
            "reality": {"enabled": True, "public_key": KEY},
        },
    )
    proxy = proxy_for(raw)
    link = build_link(proxy, "n")
    with pytest.raises(ValidationError):
        check_link(change(link, "sid", "00"), proxy)
    with pytest.raises(ValidationError):
        check_link(drop(link, "sid"), proxy)


def test_the_encoded_name_never_influences_the_validation(full):
    proxy, link = full
    check_link(link.split("#")[0] + "#" + quote("any other name", safe=""), proxy)


def test_urlsplit_sees_a_single_query_string(full):
    _, link = full
    assert link.count("?") == 1 and link.count("#") == 1
    assert urlsplit(link).fragment
