import json
import random
import string

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from . import constants as C
from .errors import ApiError


def build_session():
    session = requests.Session()
    retry = Retry(
        total=C.RETRY_TOTAL,
        backoff_factor=C.RETRY_BACKOFF,
        status_forcelist=C.RETRY_STATUSES,
        allowed_methods=frozenset(["POST"]),
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


class LanternClient:
    def __init__(
        self,
        session=None,
        country=C.DEFAULT_COUNTRY,
        platform=C.DEFAULT_PLATFORM,
        app_version=C.DEFAULT_APP_VERSION,
        singbox_version=C.DEFAULT_SINGBOX_VERSION,
        locale=C.DEFAULT_LOCALE,
        user_agent=C.DEFAULT_USER_AGENT,
        pro_server_url=C.PRO_SERVER_URL,
        config_base_url=C.CONFIG_BASE_URL,
        rng=None,
    ):
        self.session = session if session is not None else build_session()
        self.country = country
        self.platform = platform
        self.app_version = app_version
        self.singbox_version = singbox_version
        self.locale = locale
        self.user_agent = user_agent
        self.pro_server_url = pro_server_url.rstrip("/")
        self.config_base_url = config_base_url.rstrip("/")
        self.rng = rng if rng is not None else random.SystemRandom()

    def _noise(self):
        size = self.rng.randrange(0, 300)
        return "".join(self.rng.choice(string.ascii_lowercase) for _ in range(size))

    def _headers(self, state, include_token):
        headers = {
            "User-Agent": self.user_agent,
            "Accept": "application/json",
            C.HEADER_APP_VERSION: self.app_version,
            C.HEADER_VERSION: self.app_version,
            C.HEADER_PLATFORM: self.platform,
            C.HEADER_APP_NAME: C.APP_NAME,
            C.HEADER_DEVICE_ID: state.device_id,
            C.HEADER_NOISE: self._noise(),
        }
        if state.user_id > 0:
            headers[C.HEADER_USER_ID] = str(state.user_id)
        if include_token and state.token:
            headers[C.HEADER_PRO_TOKEN] = state.token
        if self.country:
            headers[C.HEADER_CLIENT_COUNTRY] = self.country
        return headers

    def _post(self, url, headers, body):
        try:
            response = self.session.post(
                url,
                headers=headers,
                data=body,
                timeout=(C.CONNECT_TIMEOUT, C.READ_TIMEOUT),
            )
        except requests.RequestException as exc:
            raise ApiError("request to %s failed: %s" % (url, type(exc).__name__)) from exc
        return response

    def create_user(self, state):
        url = self.pro_server_url + "/user-create"
        headers = self._headers(state.without_user(), include_token=False)
        response = self._post(url, headers, None)
        if response.status_code != 200:
            raise ApiError("user-create returned HTTP %d" % response.status_code, response.status_code)
        try:
            data = response.json()
        except ValueError as exc:
            raise ApiError("user-create returned invalid JSON") from exc
        if not isinstance(data, dict):
            raise ApiError("user-create returned an unexpected payload")
        if data.get("error"):
            raise ApiError("user-create reported an error")
        user_id = data.get("userId")
        token = data.get("token")
        if isinstance(user_id, bool) or not isinstance(user_id, int) or user_id <= 0:
            raise ApiError("user-create response has no valid userId")
        if not isinstance(token, str) or not token:
            raise ApiError("user-create response has no token")
        return state.with_user(user_id, token)

    def _config_body(self, state):
        body = {
            "device_id": state.device_id,
            "singbox_version": self.singbox_version,
            "platform": self.platform,
            "app_name": C.APP_NAME,
            "user_id": str(state.user_id),
            "pro_token": state.token,
            "backend": "sing-box",
            "locale": self.locale,
            "protocols": list(C.ADVERTISED_PROTOCOLS),
        }
        return json.dumps(body).encode("utf-8")

    def fetch_config(self, state):
        if not state.has_user:
            raise ApiError("cannot fetch config without a user")
        url = self.config_base_url + "/config-new"
        headers = self._headers(state, include_token=False)
        headers["Content-Type"] = "application/json"
        headers["Cache-Control"] = "no-cache"
        response = self._post(url, headers, self._config_body(state))
        if response.status_code != 200:
            raise ApiError("config-new returned HTTP %d" % response.status_code, response.status_code)
        try:
            data = response.json()
        except ValueError as exc:
            raise ApiError("config-new returned invalid JSON") from exc
        if not isinstance(data, dict):
            raise ApiError("config-new returned an unexpected payload")
        return data
