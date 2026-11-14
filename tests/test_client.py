import json

import pytest

from lantern_exporter.errors import ApiError
from lantern_exporter.state import new_state

from conftest import FakeResponse, FakeSession


def test_create_user_success_and_headers(make_session, make_client):
    session = make_session()
    client = make_client(session, country="IR")
    state = client.create_user(new_state())
    assert state.user_id == 424242 and state.token == "secret-token-value"
    call = session.calls[0]
    assert call["url"] == "https://api.getiantem.org/user-create"
    headers = call["headers"]
    assert headers["X-Lantern-Device-Id"] == state.device_id
    assert headers["X-Lantern-App"] == "lantern"
    assert headers["X-Lantern-Client-Country"] == "IR"
    assert "X-Lantern-User-Id" not in headers
    assert "X-Lantern-Pro-Token" not in headers
    assert len(headers["X-Lantern-Rand"]) < 300


@pytest.mark.parametrize(
    "payload",
    [
        {"token": "t"},
        {"userId": 0, "token": "t"},
        {"userId": True, "token": "t"},
        {"userId": 5},
        {"userId": 5, "token": ""},
        {"userId": 5, "token": "t", "error": "bad"},
        ["list"],
    ],
)
def test_create_user_rejects_bad_payloads(make_session, make_client, payload):
    client = make_client(make_session(user=payload))
    with pytest.raises(ApiError):
        client.create_user(new_state())


def test_create_user_http_error(make_session, make_client):
    client = make_client(make_session(user_status=500))
    with pytest.raises(ApiError) as info:
        client.create_user(new_state())
    assert info.value.status == 500


def test_fetch_config_request_shape(make_session, make_client, config_response):
    session = make_session()
    client = make_client(session, country="IR", singbox_version="1.12.0")
    state = new_state().with_user(9, "tok")
    data = client.fetch_config(state)
    assert data == config_response
    call = session.calls[0]
    assert call["url"] == "https://df.iantem.io/api/v1/config-new"
    assert call["headers"]["X-Lantern-User-Id"] == "9"
    assert call["headers"]["Content-Type"] == "application/json"
    assert call["headers"]["X-Lantern-Client-Country"] == "IR"
    assert "X-Lantern-Pro-Token" not in call["headers"]
    body = json.loads(call["data"])
    assert body["device_id"] == state.device_id
    assert body["user_id"] == "9"
    assert body["pro_token"] == "tok"
    assert body["backend"] == "sing-box"
    assert body["singbox_version"] == "1.12.0"
    assert "samizdat" in body["protocols"] and "shadowsocks" in body["protocols"]
    assert call["timeout"] == (15, 45)


def test_fetch_config_requires_user(make_session, make_client):
    client = make_client(make_session())
    with pytest.raises(ApiError):
        client.fetch_config(new_state())


def test_fetch_config_http_status_is_reported(make_session, make_client):
    client = make_client(make_session(config_status=403))
    with pytest.raises(ApiError) as info:
        client.fetch_config(new_state().with_user(1, "t"))
    assert info.value.status == 403


def test_fetch_config_invalid_json(make_client):
    session = FakeSession({"/config-new": lambda n: FakeResponse(200, raw="<html>")})
    with pytest.raises(ApiError):
        make_client(session).fetch_config(new_state().with_user(1, "t"))


def test_fetch_config_non_object(make_client):
    session = FakeSession({"/config-new": lambda n: FakeResponse(200, payload=[1, 2])})
    with pytest.raises(ApiError):
        make_client(session).fetch_config(new_state().with_user(1, "t"))


def test_network_error_is_wrapped(make_client, connection_error):
    session = FakeSession({"/config-new": lambda n: connection_error})
    with pytest.raises(ApiError) as info:
        make_client(session).fetch_config(new_state().with_user(1, "t"))
    assert "boom" not in str(info.value)
