import copy
import json
import random
from pathlib import Path

import pytest
import requests

from lantern_exporter.state import generate_key_text, parse_key

FIXTURE = Path(__file__).parent / "fixtures" / "config_response.json"


class FakeResponse:
    def __init__(self, status=200, payload=None, raw=None, headers=None):
        self.status_code = status
        self._payload = payload
        self._raw = raw
        self.headers = headers or {}

    def json(self):
        if self._raw is not None:
            return json.loads(self._raw)
        return copy.deepcopy(self._payload)


class FakeSession:
    def __init__(self, routes):
        self.routes = routes
        self.calls = []

    def post(self, url, headers=None, data=None, timeout=None):
        self.calls.append({"url": url, "headers": dict(headers or {}), "data": data, "timeout": timeout})
        for suffix, handler in self.routes.items():
            if url.endswith(suffix):
                result = handler(len([c for c in self.calls if c["url"].endswith(suffix)]))
                if isinstance(result, Exception):
                    raise result
                return result
        raise AssertionError("unexpected url " + url)

    def count(self, suffix):
        return len([c for c in self.calls if c["url"].endswith(suffix)])


@pytest.fixture
def config_response():
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


@pytest.fixture
def user_payload():
    return {"userId": 424242, "token": "secret-token-value", "userLevel": "free"}


@pytest.fixture
def key_text():
    return generate_key_text()


@pytest.fixture
def key(key_text):
    return parse_key(key_text)


@pytest.fixture
def sleeps():
    return []


@pytest.fixture
def make_session(config_response, user_payload):
    def factory(user=None, config=None, user_status=200, config_status=200):
        routes = {
            "/user-create": lambda n: FakeResponse(user_status, user if user is not None else user_payload),
            "/config-new": lambda n: FakeResponse(config_status, config if config is not None else config_response),
        }
        return FakeSession(routes)

    return factory


@pytest.fixture
def make_client(sleeps):
    from lantern_exporter.client import LanternClient

    def factory(session, **kwargs):
        kwargs.setdefault("sleep", sleeps.append)
        kwargs.setdefault("rng", random.Random(7))
        kwargs.setdefault("clock", lambda: 1000.0)
        return LanternClient(session=session, **kwargs)

    return factory


@pytest.fixture
def connection_error():
    return requests.ConnectionError("boom")
