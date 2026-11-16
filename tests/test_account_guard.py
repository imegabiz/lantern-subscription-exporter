import json
import logging

import pytest

from lantern_exporter.errors import ValidationError
from lantern_exporter.pipeline import ensure_no_state_in_files
from lantern_exporter.pipeline import run
from lantern_exporter.state import State

DEVICE = "6f1c1f0e-0b0a-4c63-9d2c-4a7d1f2f3a11"
TOKEN = "account-token-0123456789"


def state(user_id=5):
    return State(DEVICE, user_id, TOKEN)


def guard(files, user_id=5):
    ensure_no_state_in_files(files, state(user_id))


def test_a_device_id_in_a_file_is_refused():
    with pytest.raises(ValidationError) as info:
        guard({"x.json": ('{"note": "%s"}' % DEVICE).encode()})
    assert "device id" in str(info.value) and DEVICE not in str(info.value)


def test_a_token_in_a_file_is_refused():
    with pytest.raises(ValidationError) as info:
        guard({"sub.txt": ("ss://a@h:1#" + TOKEN).encode()})
    assert "token" in str(info.value) and TOKEN not in str(info.value)


@pytest.mark.parametrize(
    "document",
    [
        {"user_id": 5},
        {"userId": 5},
        {"userid": 5},
        {"UserID": 5},
        {"user_id": "5"},
        {"user_id": " 5 "},
        {"X-Lantern-User-Id": "5"},
        {"x_lantern_user_id": 5},
        {"nested": {"deeper": [{"user_id": 5}]}},
        [{"outbounds": [{"tag": "t", "userId": 5}]}],
    ],
)
def test_a_user_id_under_an_identifying_key_is_refused(document):
    with pytest.raises(ValidationError) as info:
        guard({"singbox.json": json.dumps(document).encode()})
    assert "user id" in str(info.value)


@pytest.mark.parametrize(
    "text",
    [
        "vless://u@h:443?encryption=none&userid=5#n",
        "vless://u@h:443?user_id=5#n",
        "X-Lantern-User-Id: 5",
        '"user_id": 5, broken json',
        "userId=5&x=1",
        "USER-ID : 5",
    ],
)
def test_a_user_id_in_text_form_is_refused(text):
    with pytest.raises(ValidationError):
        guard({"sub.txt": text.encode()})


def test_the_error_never_contains_the_account_values():
    with pytest.raises(ValidationError) as info:
        guard({"x.json": b'{"user_id": 5}'})
    message = str(info.value)
    assert TOKEN not in message and DEVICE not in message


@pytest.mark.parametrize("user_id", [5, 80, 443, 8443, 10, 1])
def test_ordinary_numbers_such_as_ports_and_ips_are_not_mistaken_for_the_user_id(user_id):
    outbound = {
        "type": "shadowsocks",
        "tag": "n%d" % user_id,
        "server": "192.0.2.%d" % (user_id % 250),
        "server_port": user_id,
        "method": "aes-256-gcm",
        "password": "pw%dx%d" % (user_id, user_id),
    }
    document = {"outbounds": [outbound], "listen_port": user_id, "port": user_id}
    links = "ss://abc@192.0.2.%d:%d#%d\nvless://u@h:%d?sid=%d#x" % (user_id % 250, user_id, user_id, user_id, user_id)
    guard({"singbox.json": json.dumps(document).encode(), "sub.txt": links.encode()}, user_id=user_id)


def test_numbers_under_other_keys_are_not_flagged():
    document = {"user": 5, "users": [5], "uid": 5, "user_identity": 5, "userid_hint": 5, "server_port": 5, "id": 5}
    guard({"x.json": json.dumps(document).encode()})


def test_text_that_only_looks_similar_is_not_flagged():
    guard({"sub.txt": b"user_identity=5 super_userid=5 userid=55 user id 5 userid=5a"})


def test_a_different_user_id_value_is_not_flagged():
    guard({"x.json": b'{"user_id": 6}'})


def test_clean_files_and_empty_files_pass():
    guard({"sub.txt": b"", "x.json": b"{}"})


def test_logs_never_show_any_account_value(make_session, make_client, tmp_path, key, caplog, capsys):
    session = make_session(user={"userId": 8123456, "token": "log-token-value-987654"})
    with caplog.at_level(logging.DEBUG):
        run(
            make_client(session),
            tmp_path / "state" / "s.enc",
            tmp_path / "out",
            key,
            bootstrap="create",
            legacy_state_path=tmp_path / "legacy.json",
        )
        run(make_client(session), tmp_path / "state" / "s.enc", tmp_path / "out", key)
    seen = caplog.text + capsys.readouterr().out
    assert "8123456" not in seen and "log-token-value-987654" not in seen
    assert "user_id" not in seen.lower() and "userid" not in seen.lower()


def test_published_files_of_a_real_run_pass_the_guard_with_the_real_account(make_session, make_client, tmp_path, key):
    session = make_session(user={"userId": 443, "token": "real-run-token-value-1"})
    run(
        make_client(session),
        tmp_path / "state" / "s.enc",
        tmp_path / "out",
        key,
        bootstrap="create",
        legacy_state_path=tmp_path / "legacy.json",
    )
    files = {p.name: p.read_bytes() for p in (tmp_path / "out").iterdir()}
    ensure_no_state_in_files(files, State("00000000-0000-4000-8000-000000000000", 443, "real-run-token-value-1"))
