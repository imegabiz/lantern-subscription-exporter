import json
import logging
import uuid

import pytest

from lantern_exporter import constants as C
from lantern_exporter import pipeline
from lantern_exporter.errors import (
    ApiError,
    ExtractionError,
    StateExistsError,
    StateMissingError,
    StateUnreadableError,
    ValidationError,
)
from lantern_exporter.pipeline import ensure_no_state_in_files, run
from lantern_exporter.state import generate_key_text, load_encrypted_state, parse_key

from conftest import FakeResponse, FakeSession

TOKEN = "secret-token-value"


def layout(tmp_path):
    return tmp_path / "state" / "lantern-state.enc", tmp_path / "out", tmp_path / "legacy" / "state.json"


def go(make_client, session, tmp_path, key, **kwargs):
    state_path, out, legacy = layout(tmp_path)
    kwargs.setdefault("legacy_state_path", legacy)
    return run(make_client(session), state_path, out, key, **kwargs)


def snapshot(directory):
    return {p.name: p.read_bytes() for p in directory.iterdir()} if directory.exists() else {}


def calls(session):
    return [c["url"].rsplit("/", 1)[1] for c in session.calls]


def bootstrapped(make_session, make_client, tmp_path, key, **kwargs):
    session = make_session()
    result = go(make_client, session, tmp_path, key, bootstrap="create", **kwargs)
    return result


def test_first_run_without_state_and_without_bootstrap_stops_and_creates_nothing(make_session, make_client, tmp_path, key):
    session = make_session()
    with pytest.raises(StateMissingError):
        go(make_client, session, tmp_path, key)
    assert session.calls == []
    assert snapshot(layout(tmp_path)[1]) == {}
    assert not layout(tmp_path)[0].exists()


def test_bootstrap_create_makes_one_account_and_an_encrypted_state(make_session, make_client, tmp_path, key):
    session = make_session()
    result = go(make_client, session, tmp_path, key, bootstrap="create")
    state_path, out, _ = layout(tmp_path)
    assert calls(session) == ["user-create", "config-new"]
    assert result.state_written is True
    saved = load_encrypted_state(state_path, key)
    assert saved.user_id == 424242 and saved.token == TOKEN
    raw = state_path.read_bytes()
    assert TOKEN.encode() not in raw and saved.device_id.encode() not in raw
    assert sorted(snapshot(out)) == ["singbox.json", "sub.txt", "xray.json"]


def test_normal_run_reuses_the_state_and_never_rewrites_it(make_session, make_client, tmp_path, key):
    bootstrapped(make_session, make_client, tmp_path, key)
    state_path = layout(tmp_path)[0]
    before = state_path.read_bytes()
    session = make_session()
    result = go(make_client, session, tmp_path, key)
    assert calls(session) == ["config-new"]
    assert result.state_written is False and result.changed == []
    assert state_path.read_bytes() == before


def test_wrong_key_stops_without_creating_an_account(make_session, make_client, tmp_path, key):
    bootstrapped(make_session, make_client, tmp_path, key)
    before_state = layout(tmp_path)[0].read_bytes()
    before_out = snapshot(layout(tmp_path)[1])
    session = make_session()
    with pytest.raises(StateUnreadableError):
        go(make_client, session, tmp_path, parse_key(generate_key_text()))
    assert session.calls == []
    assert layout(tmp_path)[0].read_bytes() == before_state
    assert snapshot(layout(tmp_path)[1]) == before_out


@pytest.mark.parametrize(
    "damage",
    [
        lambda b: b[: len(b) // 2],
        lambda b: b.replace(b'"ciphertext": "', b'"ciphertext": "AAAA'),
        lambda b: b"",
        lambda b: b"garbage",
    ],
)
def test_corrupt_or_tampered_state_stops_without_creating_an_account(make_session, make_client, tmp_path, key, damage):
    bootstrapped(make_session, make_client, tmp_path, key)
    state_path = layout(tmp_path)[0]
    state_path.write_bytes(damage(state_path.read_bytes()))
    before_out = snapshot(layout(tmp_path)[1])
    session = make_session()
    with pytest.raises(StateUnreadableError):
        go(make_client, session, tmp_path, key)
    assert session.calls == []
    assert snapshot(layout(tmp_path)[1]) == before_out


def test_create_refuses_to_replace_an_existing_state(make_session, make_client, tmp_path, key):
    bootstrapped(make_session, make_client, tmp_path, key)
    session = make_session()
    with pytest.raises(StateExistsError):
        go(make_client, session, tmp_path, key, bootstrap="create")
    assert session.calls == []


def test_recreate_replaces_the_account_and_keeps_the_device_id(make_session, make_client, tmp_path, key):
    bootstrapped(make_session, make_client, tmp_path, key)
    old = load_encrypted_state(layout(tmp_path)[0], key)
    session = make_session(user={"userId": 777, "token": "new-token-value"})
    go(make_client, session, tmp_path, key, bootstrap="recreate")
    new = load_encrypted_state(layout(tmp_path)[0], key)
    assert calls(session) == ["user-create", "config-new"]
    assert new.user_id == 777 and new.token == "new-token-value" and new.device_id == old.device_id


def test_recreate_works_even_when_the_old_state_is_unreadable(make_session, make_client, tmp_path, key):
    bootstrapped(make_session, make_client, tmp_path, key)
    layout(tmp_path)[0].write_bytes(b"broken")
    session = make_session(user={"userId": 5, "token": "fresh-token"})
    go(make_client, session, tmp_path, key, bootstrap="recreate")
    assert load_encrypted_state(layout(tmp_path)[0], key).user_id == 5


def write_legacy(tmp_path, user_id=4242, token="legacy-token-value"):
    legacy = layout(tmp_path)[2]
    legacy.parent.mkdir(parents=True, exist_ok=True)
    device = str(uuid.uuid4())
    legacy.write_text(json.dumps({"device_id": device, "user_id": user_id, "token": token}), encoding="utf-8")
    return device


def test_migration_moves_the_old_account_without_creating_a_new_one(make_session, make_client, tmp_path, key):
    device = write_legacy(tmp_path)
    session = make_session()
    result = go(make_client, session, tmp_path, key, bootstrap="migrate")
    saved = load_encrypted_state(layout(tmp_path)[0], key)
    assert (saved.device_id, saved.user_id, saved.token) == (device, 4242, "legacy-token-value")
    assert calls(session) == ["config-new"]
    assert result.state_written is True
    assert not layout(tmp_path)[2].exists()
    assert b"legacy-token-value" not in layout(tmp_path)[0].read_bytes()


def test_migration_sends_the_migrated_account_to_the_api(make_session, make_client, tmp_path, key):
    device = write_legacy(tmp_path, user_id=4242)
    session = make_session()
    go(make_client, session, tmp_path, key, bootstrap="migrate")
    body = json.loads(session.calls[0]["data"])
    assert body["device_id"] == device and body["user_id"] == "4242" and body["pro_token"] == "legacy-token-value"


def test_migration_without_a_legacy_file_stops_and_creates_nothing(make_session, make_client, tmp_path, key):
    session = make_session()
    with pytest.raises(StateMissingError):
        go(make_client, session, tmp_path, key, bootstrap="migrate")
    assert session.calls == [] and not layout(tmp_path)[0].exists()


def test_migration_with_a_corrupt_legacy_file_stops_and_creates_nothing(make_session, make_client, tmp_path, key):
    legacy = layout(tmp_path)[2]
    legacy.parent.mkdir(parents=True)
    legacy.write_text("{broken", encoding="utf-8")
    session = make_session()
    with pytest.raises(StateUnreadableError):
        go(make_client, session, tmp_path, key, bootstrap="migrate")
    assert session.calls == [] and not layout(tmp_path)[0].exists() and legacy.exists()


def test_migration_refuses_when_an_encrypted_state_exists(make_session, make_client, tmp_path, key):
    bootstrapped(make_session, make_client, tmp_path, key)
    write_legacy(tmp_path)
    session = make_session()
    with pytest.raises(StateExistsError):
        go(make_client, session, tmp_path, key, bootstrap="migrate")
    assert layout(tmp_path)[2].exists()


@pytest.mark.parametrize("status", [401, 403])
def test_rejected_credentials_never_create_an_account_automatically(make_session, make_client, tmp_path, key, status):
    bootstrapped(make_session, make_client, tmp_path, key)
    before_out = snapshot(layout(tmp_path)[1])
    before_state = layout(tmp_path)[0].read_bytes()
    session = FakeSession(
        {
            "/user-create": lambda n: FakeResponse(200, {"userId": 1, "token": "new"}),
            "/config-new": lambda n: FakeResponse(status, {}),
        }
    )
    with pytest.raises(ApiError) as info:
        go(make_client, session, tmp_path, key)
    assert "recreate" in str(info.value) and info.value.status == status
    assert calls(session) == ["config-new"]
    assert snapshot(layout(tmp_path)[1]) == before_out
    assert layout(tmp_path)[0].read_bytes() == before_state


def test_user_create_failure_does_not_leave_a_state_file(make_client, tmp_path, key):
    session = FakeSession({"/user-create": lambda n: FakeResponse(500, {})})
    with pytest.raises(ApiError):
        go(make_client, session, tmp_path, key, bootstrap="create")
    assert session.count("/user-create") == 1
    assert not layout(tmp_path)[0].exists()


def test_api_failure_keeps_previous_output(make_session, make_client, tmp_path, key):
    bootstrapped(make_session, make_client, tmp_path, key)
    before = snapshot(layout(tmp_path)[1])
    with pytest.raises(ApiError):
        go(make_client, make_session(config_status=500), tmp_path, key)
    assert snapshot(layout(tmp_path)[1]) == before


def test_empty_result_keeps_previous_output(make_session, make_client, tmp_path, key, config_response):
    bootstrapped(make_session, make_client, tmp_path, key)
    before = snapshot(layout(tmp_path)[1])
    config_response["options"]["outbounds"] = [o for o in config_response["options"]["outbounds"] if o["type"] == "samizdat"]
    with pytest.raises(ValidationError):
        go(make_client, make_session(config=config_response), tmp_path, key)
    assert snapshot(layout(tmp_path)[1]) == before


def test_malformed_response_keeps_previous_output(make_session, make_client, tmp_path, key):
    bootstrapped(make_session, make_client, tmp_path, key)
    before = snapshot(layout(tmp_path)[1])
    with pytest.raises(ExtractionError):
        go(make_client, make_session(config={"options": {}}), tmp_path, key)
    assert snapshot(layout(tmp_path)[1]) == before


def test_min_configs_is_enforced(make_session, make_client, tmp_path, key):
    session = make_session()
    with pytest.raises(ValidationError):
        go(make_client, session, tmp_path, key, bootstrap="create", min_configs=4)
    assert snapshot(layout(tmp_path)[1]) == {}


def test_rotated_config_updates_all_three_files(make_session, make_client, tmp_path, key, config_response):
    bootstrapped(make_session, make_client, tmp_path, key)
    config_response["options"]["outbounds"][0]["server"] = "192.0.2.99"
    result = go(make_client, make_session(config=config_response), tmp_path, key)
    assert sorted(result.changed) == ["singbox.json", "sub.txt", "xray.json"]
    assert "@192.0.2.99:443" in (layout(tmp_path)[1] / "sub.txt").read_text(encoding="utf-8")


def test_hysteria2_is_left_out_of_share_links_by_default_but_not_of_the_json_files(make_session, make_client, tmp_path, key):
    result = go(make_client, make_session(), tmp_path, key, bootstrap="create")
    out = layout(tmp_path)[1]
    links = (out / "sub.txt").read_text(encoding="utf-8").splitlines()
    assert [link.split("://")[0] for link in links] == ["ss", "vless"]
    assert result.link_count == 2 and result.links_omitted == 1 and result.count == 3
    profile = json.loads((out / "singbox.json").read_text(encoding="utf-8"))
    assert [o["type"] for o in profile["outbounds"] if o["type"] in ("shadowsocks", "vless", "hysteria2")] == [
        "shadowsocks",
        "vless",
        "hysteria2",
    ]
    xray = json.loads((out / "xray.json").read_text(encoding="utf-8"))
    assert [o["protocol"] for o in xray["outbounds"] if o["tag"].startswith("lantern-")] == [
        "shadowsocks",
        "vless",
        "hysteria",
    ]


def test_hysteria2_links_can_be_enabled_explicitly(make_session, make_client, tmp_path, key):
    result = go(make_client, make_session(), tmp_path, key, bootstrap="create", hysteria2_links="include")
    links = (layout(tmp_path)[1] / "sub.txt").read_text(encoding="utf-8").splitlines()
    assert [link.split("://")[0] for link in links] == ["ss", "vless", "hysteria2"]
    assert result.links_omitted == 0


def only_hysteria2(config_response):
    config_response["options"]["outbounds"] = [
        o for o in config_response["options"]["outbounds"] if o["type"] == "hysteria2x"
    ]
    return config_response


def test_only_hysteria2_available_fails_cleanly_when_links_are_omitted(make_session, make_client, tmp_path, key, config_response):
    session = make_session(config=only_hysteria2(config_response))
    with pytest.raises(ValidationError) as info:
        go(make_client, session, tmp_path, key, bootstrap="create")
    assert "Hysteria2" in str(info.value)
    assert snapshot(layout(tmp_path)[1]) == {}


def test_only_hysteria2_available_is_published_when_links_are_included(make_session, make_client, tmp_path, key, config_response):
    session = make_session(config=only_hysteria2(config_response))
    result = go(make_client, session, tmp_path, key, bootstrap="create", hysteria2_links="include")
    assert result.count == 1 and result.kinds == {"hysteria2": 1}
    assert (layout(tmp_path)[1] / "sub.txt").read_text(encoding="utf-8").startswith("hysteria2://")


def test_exceeding_the_safety_ceiling_publishes_nothing_instead_of_truncating(make_session, make_client, tmp_path, key, monkeypatch):
    monkeypatch.setattr(C, "MAX_CONFIGS", 2)
    session = make_session()
    with pytest.raises(ValidationError) as info:
        go(make_client, session, tmp_path, key, bootstrap="create")
    assert "ceiling" in str(info.value)
    assert snapshot(layout(tmp_path)[1]) == {}


def test_a_failing_output_builder_replaces_none_of_the_files(make_session, make_client, tmp_path, key, monkeypatch, config_response):
    bootstrapped(make_session, make_client, tmp_path, key)
    before = snapshot(layout(tmp_path)[1])
    config_response["options"]["outbounds"][0]["server"] = "192.0.2.123"

    def broken(proxies):
        raise ValidationError("xray builder failed")

    monkeypatch.setattr(pipeline, "build_xray_config", broken)
    with pytest.raises(ValidationError):
        go(make_client, make_session(config=config_response), tmp_path, key)
    assert snapshot(layout(tmp_path)[1]) == before


def test_outputs_never_contain_account_data_or_private_keys(make_session, make_client, tmp_path, key):
    go(make_client, make_session(), tmp_path, key, bootstrap="create")
    state = load_encrypted_state(layout(tmp_path)[0], key)
    for name, content in snapshot(layout(tmp_path)[1]).items():
        assert state.token.encode() not in content, name
        assert state.device_id.encode() not in content, name
        assert b"PRIVATE KEY" not in content, name


def test_the_publication_guard_refuses_files_that_contain_account_data(make_session, make_client, tmp_path, key):
    go(make_client, make_session(), tmp_path, key, bootstrap="create")
    state = load_encrypted_state(layout(tmp_path)[0], key)
    with pytest.raises(ValidationError):
        ensure_no_state_in_files({"a.json": ("x " + state.token).encode()}, state)
    with pytest.raises(ValidationError):
        ensure_no_state_in_files({"a.json": state.device_id.encode()}, state)
    ensure_no_state_in_files({"a.json": b"clean"}, state)


def test_logs_and_output_never_show_the_key_or_the_token(make_session, make_client, tmp_path, key_text, caplog, capsys):
    key = parse_key(key_text)
    with caplog.at_level(logging.DEBUG):
        go(make_client, make_session(), tmp_path, key, bootstrap="create")
        go(make_client, make_session(), tmp_path, key)
    state = load_encrypted_state(layout(tmp_path)[0], key)
    seen = caplog.text + capsys.readouterr().out
    for secret in (key_text, state.token, state.device_id):
        assert secret not in seen


def test_run_reports_exact_counters_and_junk_notice(make_session, make_client, tmp_path, key):
    result = go(make_client, make_session(), tmp_path, key, bootstrap="create")
    assert result.counts == {"total": 5, "usable": 3, "utility": 0, "unsupported": 2, "invalid": 0, "duplicate": 0}
    assert result.skipped == {"unsupported_type:samizdat": 2}
    assert result.junk_not_expressible == 1


def test_the_guard_does_not_misfire_on_a_very_short_token_but_still_catches_quoted_leaks():
    from lantern_exporter.state import State

    state = State("6f1c1f0e-0b0a-4c63-9d2c-4a7d1f2f3a11", 5, "t")
    ensure_no_state_in_files({"a.txt": b"shadowsocks vless tuic"}, state)
    with pytest.raises(ValidationError):
        ensure_no_state_in_files({"a.json": b'{"token": "t"}'}, state)
