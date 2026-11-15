import email.utils
import json
import logging

import pytest
import requests

from lantern_exporter import constants as C
from lantern_exporter.client import parse_retry_after
from lantern_exporter.errors import ApiError
from lantern_exporter.state import new_state

from conftest import FakeResponse, FakeSession

DEVICE = "6f1c1f0e-0b0a-4c63-9d2c-4a7d1f2f3a11"


def user_state():
    return new_state().with_user(9, "tok-value")


def test_create_user_success_and_headers(make_session, make_client):
    session = make_session()
    client = make_client(session, country="IR")
    assert client.create_user(DEVICE) == (424242, "secret-token-value")
    call = session.calls[0]
    assert call["url"] == "https://api.getiantem.org/user-create"
    headers = call["headers"]
    assert headers["X-Lantern-Device-Id"] == DEVICE
    assert headers["X-Lantern-App"] == "lantern"
    assert headers["X-Lantern-App-Version"] == "10.0.5"
    assert headers["X-Lantern-Client-Country"] == "IR"
    assert "X-Lantern-User-Id" not in headers and "X-Lantern-Pro-Token" not in headers
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
    with pytest.raises(ApiError):
        make_client(make_session(user=payload)).create_user(DEVICE)


@pytest.mark.parametrize("status", [429, 500, 502, 503, 504])
def test_create_user_is_never_retried_on_http_errors(make_client, sleeps, status):
    session = FakeSession({"/user-create": lambda n: FakeResponse(status, {})})
    with pytest.raises(ApiError) as info:
        make_client(session).create_user(DEVICE)
    assert session.count("/user-create") == 1
    assert sleeps == []
    assert info.value.status == status


@pytest.mark.parametrize("error", [requests.ConnectionError("x"), requests.Timeout("x"), requests.ReadTimeout("x")])
def test_create_user_is_never_retried_on_network_errors(make_client, sleeps, error):
    session = FakeSession({"/user-create": lambda n: error})
    with pytest.raises(ApiError):
        make_client(session).create_user(DEVICE)
    assert session.count("/user-create") == 1
    assert sleeps == []


def test_create_user_429_reports_retry_after_without_waiting(make_client, sleeps):
    session = FakeSession({"/user-create": lambda n: FakeResponse(429, {}, headers={"Retry-After": "90"})})
    with pytest.raises(ApiError) as info:
        make_client(session).create_user(DEVICE)
    assert "Retry-After: 90" in str(info.value)
    assert session.count("/user-create") == 1 and sleeps == []


def test_user_create_response_that_never_arrives_cannot_create_a_second_account(make_client, sleeps):
    session = FakeSession({"/user-create": lambda n: requests.ReadTimeout("no answer")})
    client = make_client(session)
    with pytest.raises(ApiError):
        client.create_user(DEVICE)
    assert session.count("/user-create") == 1


def test_fetch_config_request_shape(make_session, make_client, config_response):
    session = make_session()
    client = make_client(session, country="IR")
    state = user_state()
    assert client.fetch_config(state) == config_response
    call = session.calls[0]
    assert call["url"] == "https://df.iantem.io/api/v1/config-new"
    headers = call["headers"]
    assert headers["X-Lantern-User-Id"] == "9"
    assert headers["Content-Type"] == "application/json"
    assert headers["X-Lantern-Client-Country"] == "IR"
    assert "X-Lantern-Pro-Token" not in headers
    body = json.loads(call["data"])
    assert body["device_id"] == state.device_id and body["user_id"] == "9"
    assert body["pro_token"] == "tok-value"
    assert body["backend"] == "sing-box"
    assert body["singbox_version"] == "v1.14.2-lantern.3"
    assert body["protocols"] == ["shadowsocks", "vless", "hysteria2x"]
    assert "preferred_location" not in body and "capabilities" not in body
    assert call["timeout"] == (15, 45)


def test_advertised_protocols_are_exactly_what_the_project_can_publish():
    assert C.ADVERTISED_PROTOCOLS == ("shadowsocks", "vless", "hysteria2x")


def test_country_header_can_be_disabled(make_session, make_client):
    session = make_session()
    make_client(session, country="").fetch_config(user_state())
    assert "X-Lantern-Client-Country" not in session.calls[0]["headers"]


def test_fetch_config_requires_user(make_session, make_client):
    with pytest.raises(ApiError):
        make_client(make_session()).fetch_config(new_state())


def test_fetch_config_invalid_json(make_client):
    session = FakeSession({"/config-new": lambda n: FakeResponse(200, raw="<html>")})
    with pytest.raises(ApiError):
        make_client(session).fetch_config(user_state())


def test_fetch_config_non_object(make_client):
    session = FakeSession({"/config-new": lambda n: FakeResponse(200, payload=[1, 2])})
    with pytest.raises(ApiError):
        make_client(session).fetch_config(user_state())


@pytest.mark.parametrize("status", [400, 401, 403, 404])
def test_client_errors_are_not_retried(make_client, sleeps, status):
    session = FakeSession({"/config-new": lambda n: FakeResponse(status, {})})
    with pytest.raises(ApiError) as info:
        make_client(session).fetch_config(user_state())
    assert info.value.status == status and session.count("/config-new") == 1 and sleeps == []


def test_503_then_success_waits_with_backoff(make_client, sleeps, config_response):
    answers = [FakeResponse(503, {}), FakeResponse(200, config_response)]
    session = FakeSession({"/config-new": lambda n: answers[n - 1]})
    assert make_client(session).fetch_config(user_state()) == config_response
    assert session.count("/config-new") == 2
    assert len(sleeps) == 1 and C.RETRY_BASE_DELAY <= sleeps[0] <= C.RETRY_BASE_DELAY + C.RETRY_JITTER


def test_retries_are_never_back_to_back(make_client, sleeps):
    session = FakeSession({"/config-new": lambda n: FakeResponse(500, {})})
    with pytest.raises(ApiError):
        make_client(session).fetch_config(user_state())
    assert session.count("/config-new") == 3
    assert len(sleeps) == 2
    assert sleeps[0] >= C.RETRY_BASE_DELAY and sleeps[1] >= 2 * C.RETRY_BASE_DELAY
    assert all(delay <= C.RETRY_MAX_DELAY for delay in sleeps)


def test_429_with_retry_after_seconds_is_respected(make_client, sleeps, config_response):
    answers = [FakeResponse(429, {}, headers={"Retry-After": "37"}), FakeResponse(200, config_response)]
    session = FakeSession({"/config-new": lambda n: answers[n - 1]})
    make_client(session).fetch_config(user_state())
    assert 37 <= sleeps[0] <= 38


def test_429_with_retry_after_http_date_is_respected(make_client, sleeps, config_response):
    when = email.utils.formatdate(1000 + 30, usegmt=True)
    answers = [FakeResponse(429, {}, headers={"Retry-After": when}), FakeResponse(200, config_response)]
    session = FakeSession({"/config-new": lambda n: answers[n - 1]})
    make_client(session).fetch_config(user_state())
    assert 29 <= sleeps[0] <= 31


def test_429_with_huge_retry_after_stops_without_waiting(make_client, sleeps):
    session = FakeSession({"/config-new": lambda n: FakeResponse(429, {}, headers={"Retry-After": "600"})})
    with pytest.raises(ApiError) as info:
        make_client(session).fetch_config(user_state())
    assert session.count("/config-new") == 1 and sleeps == []
    assert info.value.status == 429


def test_429_without_retry_after_uses_backoff_then_gives_up(make_client, sleeps):
    session = FakeSession({"/config-new": lambda n: FakeResponse(429, {})})
    with pytest.raises(ApiError) as info:
        make_client(session).fetch_config(user_state())
    assert session.count("/config-new") == 3 and len(sleeps) == 2
    assert info.value.status == 429


def test_network_error_is_retried_for_config_requests(make_client, sleeps, config_response):
    answers = [requests.ConnectionError("x"), FakeResponse(200, config_response)]
    session = FakeSession({"/config-new": lambda n: answers[n - 1]})
    assert make_client(session).fetch_config(user_state()) == config_response
    assert len(sleeps) == 1


def test_network_error_message_does_not_leak_details(make_client):
    session = FakeSession({"/config-new": lambda n: requests.ConnectionError("secret-host-detail")})
    with pytest.raises(ApiError) as info:
        make_client(session).fetch_config(user_state())
    assert "secret-host-detail" not in str(info.value)


def test_logs_never_contain_account_data(make_client, caplog, config_response):
    state = user_state()
    answers = [FakeResponse(503, {}), FakeResponse(200, config_response)]
    session = FakeSession({"/config-new": lambda n: answers[n - 1]})
    with caplog.at_level(logging.DEBUG, logger="lantern_exporter"):
        make_client(session).fetch_config(state)
    assert "retrying" in caplog.text
    assert state.token not in caplog.text and state.device_id not in caplog.text


@pytest.mark.parametrize(
    "value,expected",
    [(None, None), ("", None), ("  ", None), ("0", 0.0), ("45", 45.0), ("garbage", None), ("-5", None)],
)
def test_parse_retry_after_values(value, expected):
    assert parse_retry_after(value, now=1000.0) == expected


def test_parse_retry_after_past_date_is_zero():
    past = email.utils.formatdate(10, usegmt=True)
    assert parse_retry_after(past, now=1000.0) == 0.0
