import json

import pytest

from lantern_exporter.errors import ValidationError
from lantern_exporter.extract import extract
from lantern_exporter.links import certificate_pin
from lantern_exporter.xray import build_config, render_config, validate_config


@pytest.fixture
def proxies(config_response):
    return extract(config_response).proxies


@pytest.fixture
def config(proxies):
    return build_config(proxies)


def outbound(config, suffix):
    return next(o for o in config["outbounds"] if o["tag"].endswith(suffix))


def test_tags_protocols_and_order(config):
    assert [(o["tag"], o["protocol"]) for o in config["outbounds"]] == [
        ("lantern-01-ss", "shadowsocks"),
        ("lantern-02-vless", "vless"),
        ("lantern-03-hy2", "hysteria"),
        ("direct", "freedom"),
        ("block", "blackhole"),
    ]


def test_shadowsocks_outbound(config, proxies):
    settings = outbound(config, "-ss")["settings"]
    source = proxies[0].outbound
    assert settings == {
        "address": source["server"],
        "port": source["server_port"],
        "method": source["method"],
        "password": source["password"],
    }


def test_vless_reality_outbound(config, proxies):
    item = outbound(config, "-vless")
    reality = item["streamSettings"]["realitySettings"]
    source = proxies[1].outbound
    assert item["settings"]["id"] == source["uuid"]
    assert item["settings"]["flow"] == "xtls-rprx-vision"
    assert item["settings"]["encryption"] == "none"
    assert item["streamSettings"]["security"] == "reality"
    assert reality["password"] == source["tls"]["reality"]["public_key"]
    assert reality["serverName"] == "www.amazon.com" and reality["fingerprint"] == "chrome"
    assert "shortId" not in reality


def test_vless_reality_short_id_is_kept(config_response):
    config_response["options"]["outbounds"][1]["tls"]["reality"]["short_id"] = "a1b2c3d4"
    built = build_config(extract(config_response).proxies)
    assert outbound(built, "-vless")["streamSettings"]["realitySettings"]["shortId"] == "a1b2c3d4"


def test_hysteria2_outbound_pins_the_certificate_and_sends_noise(config, proxies):
    item = outbound(config, "-hy2")
    stream = item["streamSettings"]
    source = proxies[2].outbound
    assert item["settings"] == {"version": 2, "address": source["server"], "port": source["server_port"]}
    assert stream["network"] == "hysteria" and stream["security"] == "tls"
    assert stream["hysteriaSettings"] == {"version": 2, "auth": source["password"]}
    tls = stream["tlsSettings"]
    assert tls["serverName"] == "api.push.apple.com" and tls["alpn"] == ["h3"]
    assert tls["pinnedPeerCertSha256"] == certificate_pin(source["tls"]["certificate"])
    assert "allowInsecure" not in tls
    mask = stream["finalmask"]["udp"][0]
    assert mask["type"] == "noise"
    assert mask["settings"]["noise"][0]["rand"] == "8-64"


def test_routing_balancer_observatory_and_inbounds(config):
    routing = config["routing"]
    assert routing["balancers"][0]["selector"] == ["lantern-"]
    assert routing["balancers"][0]["fallbackTag"] == "lantern-01-ss"
    assert routing["balancers"][0]["strategy"] == {"type": "leastPing"}
    assert routing["rules"][0]["outboundTag"] == "direct"
    assert routing["rules"][1] == {"type": "field", "domain": ["domain:ir", "geosite:category-ir"], "outboundTag": "direct"}
    assert routing["rules"][2] == {"type": "field", "ip": ["geoip:ir"], "outboundTag": "direct"}
    assert routing["domainStrategy"] == "AsIs"
    assert routing["rules"][-1]["balancerTag"] == "lantern-balancer"
    assert config["observatory"]["subjectSelector"] == ["lantern-"]
    assert [(i["protocol"], i["port"]) for i in config["inbounds"]] == [("socks", 10808), ("http", 10809)]
    assert all(i["listen"] == "127.0.0.1" for i in config["inbounds"])


def test_rendering_is_stable_json(config):
    first = render_config(config)
    assert first.endswith(b"\n") and json.loads(first) == config
    assert render_config(build_config(extract(json.load(open("tests/fixtures/config_response.json"))).proxies)) == first


def test_empty_input_is_rejected():
    with pytest.raises(ValidationError):
        build_config([])


def test_validation_catches_broken_configs(config):
    broken = json.loads(json.dumps(config))
    broken["routing"]["balancers"][0]["fallbackTag"] = "nope"
    with pytest.raises(ValidationError):
        validate_config(broken, 3)
    broken = json.loads(json.dumps(config))
    broken["routing"]["rules"][0]["outboundTag"] = "nope"
    with pytest.raises(ValidationError):
        validate_config(broken, 3)
    broken = json.loads(json.dumps(config))
    broken["routing"]["rules"][-1]["balancerTag"] = "nope"
    with pytest.raises(ValidationError):
        validate_config(broken, 3)
    broken = json.loads(json.dumps(config))
    broken["outbounds"][1]["tag"] = "lantern-01-ss"
    with pytest.raises(ValidationError):
        validate_config(broken, 3)
    with pytest.raises(ValidationError):
        validate_config(config, 2)


def test_remarks_name_the_config_like_tcb(config):
    assert config["remarks"] == "\U0001F47D Anonymous Lantern \U0001F680"
    assert list(config)[0] == "remarks"


def test_missing_remarks_is_rejected(config):
    broken = json.loads(json.dumps(config))
    broken["remarks"] = " "
    with pytest.raises(ValidationError):
        validate_config(broken, 3)
