import json

import pytest

from lantern_exporter.errors import ApiError, ExtractionError, ValidationError
from lantern_exporter.pipeline import run
from lantern_exporter.state import load_state

from conftest import FakeResponse, FakeSession


def paths(tmp_path):
    return tmp_path / "state.json", tmp_path / "out"


def test_full_run_writes_files_and_state(tmp_path, make_session, make_client):
    state_path, out = paths(tmp_path)
    session = make_session()
    result = run(make_client(session), state_path, out)
    assert result.count == 2 and result.kinds == {"shadowsocks": 1, "vless": 1}
    assert sorted(result.changed) == ["singbox.json", "sub.txt"]
    links = (out / "sub.txt").read_text(encoding="utf-8").splitlines()
    assert len(links) == 2 and links[0].startswith("ss://") and links[1].startswith("vless://")
    profile = json.loads((out / "singbox.json").read_text(encoding="utf-8"))
    assert len([o for o in profile["outbounds"] if o["type"] in ("shadowsocks", "vless")]) == 2
    state = load_state(state_path)
    assert state.user_id == 424242 and state.token == "secret-token-value"
    assert [c["url"].rsplit("/", 1)[1] for c in session.calls] == ["user-create", "config-new"]


def test_second_run_reuses_user_and_changes_nothing(tmp_path, make_session, make_client):
    state_path, out = paths(tmp_path)
    run(make_client(make_session()), state_path, out)
    session = make_session()
    result = run(make_client(session), state_path, out)
    assert result.changed == []
    assert [c["url"].rsplit("/", 1)[1] for c in session.calls] == ["config-new"]


def test_rotated_config_updates_files(tmp_path, make_session, make_client, config_response):
    state_path, out = paths(tmp_path)
    run(make_client(make_session()), state_path, out)
    config_response["options"]["outbounds"][0]["server"] = "192.0.2.99"
    result = run(make_client(make_session(config=config_response)), state_path, out)
    assert sorted(result.changed) == ["singbox.json", "sub.txt"]
    assert "@192.0.2.99:443" in (out / "sub.txt").read_text(encoding="utf-8")


def snapshot(out):
    return {p.name: p.read_bytes() for p in out.iterdir()}


def test_api_failure_keeps_previous_output(tmp_path, make_session, make_client):
    state_path, out = paths(tmp_path)
    run(make_client(make_session()), state_path, out)
    before = snapshot(out)
    with pytest.raises(ApiError):
        run(make_client(make_session(config_status=500)), state_path, out)
    assert snapshot(out) == before


def test_empty_result_keeps_previous_output(tmp_path, make_session, make_client, config_response):
    state_path, out = paths(tmp_path)
    run(make_client(make_session()), state_path, out)
    before = snapshot(out)
    config_response["options"]["outbounds"] = [
        o for o in config_response["options"]["outbounds"] if o["type"] == "samizdat"
    ]
    with pytest.raises(ValidationError):
        run(make_client(make_session(config=config_response)), state_path, out)
    assert snapshot(out) == before


def test_malformed_response_keeps_previous_output(tmp_path, make_session, make_client):
    state_path, out = paths(tmp_path)
    run(make_client(make_session()), state_path, out)
    before = snapshot(out)
    with pytest.raises(ExtractionError):
        run(make_client(make_session(config={"options": {}})), state_path, out)
    assert snapshot(out) == before


def test_min_configs_is_enforced(tmp_path, make_session, make_client):
    state_path, out = paths(tmp_path)
    with pytest.raises(ValidationError):
        run(make_client(make_session()), state_path, out, min_configs=3)
    assert not out.exists() or not any(out.iterdir())


def test_rejected_credentials_trigger_one_fresh_user(tmp_path, make_client, config_response):
    state_path, out = paths(tmp_path)
    first = FakeSession(
        {
            "/user-create": lambda n: FakeResponse(200, {"userId": 1, "token": "old"}),
            "/config-new": lambda n: FakeResponse(200, config_response),
        }
    )
    run(make_client(first), state_path, out)

    def config(n):
        return FakeResponse(403, {}) if n == 1 else FakeResponse(200, config_response)

    second = FakeSession(
        {"/user-create": lambda n: FakeResponse(200, {"userId": 2, "token": "new"}), "/config-new": config}
    )
    result = run(make_client(second), state_path, out)
    assert result.count == 2
    assert load_state(state_path).user_id == 2
    assert [c["url"].rsplit("/", 1)[1] for c in second.calls] == ["config-new", "user-create", "config-new"]


def test_persistent_auth_failure_is_not_retried_forever(tmp_path, make_client):
    state_path, out = paths(tmp_path)
    session = FakeSession(
        {
            "/user-create": lambda n: FakeResponse(200, {"userId": 1, "token": "t"}),
            "/config-new": lambda n: FakeResponse(401, {}),
        }
    )
    with pytest.raises(ApiError):
        run(make_client(session), state_path, out)
    assert [c["url"].rsplit("/", 1)[1] for c in session.calls] == [
        "user-create",
        "config-new",
        "user-create",
        "config-new",
    ]


def test_user_creation_failure_surfaces(tmp_path, make_session, make_client):
    state_path, out = paths(tmp_path)
    with pytest.raises(ApiError):
        run(make_client(make_session(user_status=503)), state_path, out)
    assert not out.exists() or not any(out.iterdir())


def test_failure_still_logs_what_was_skipped_and_no_secrets(tmp_path, make_session, make_client, config_response, caplog):
    import logging

    state_path, out = paths(tmp_path)
    config_response["options"]["outbounds"] = [
        o for o in config_response["options"]["outbounds"] if o["type"] in ("samizdat", "hysteria2x")
    ]
    with caplog.at_level(logging.INFO, logger="lantern_exporter"):
        with pytest.raises(ValidationError):
            run(make_client(make_session(config=config_response)), state_path, out)
    text = caplog.text
    assert "country=IR" in text and "outbounds=3" in text
    assert "unsupported_type:samizdat" in text and "unsupported_type:hysteria2x" in text
    assert "fakepassword" not in text and "secret-token-value" not in text
