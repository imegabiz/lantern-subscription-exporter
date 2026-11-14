import json
import os
import tempfile
import uuid
from dataclasses import dataclass, replace
from pathlib import Path


@dataclass(frozen=True)
class State:
    device_id: str
    user_id: int = 0
    token: str = ""

    @property
    def has_user(self):
        return self.user_id > 0 and bool(self.token)

    def with_user(self, user_id, token):
        return replace(self, user_id=int(user_id), token=str(token))

    def without_user(self):
        return replace(self, user_id=0, token="")


def new_state():
    return State(device_id=str(uuid.uuid4()))


def _valid_device_id(value):
    if not isinstance(value, str):
        return False
    try:
        uuid.UUID(value)
    except ValueError:
        return False
    return True


def load_state(path):
    path = Path(path)
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return new_state()
    if not isinstance(raw, dict) or not _valid_device_id(raw.get("device_id")):
        return new_state()
    user_id = raw.get("user_id", 0)
    token = raw.get("token", "")
    if isinstance(user_id, bool) or not isinstance(user_id, int) or user_id < 0:
        user_id = 0
    if not isinstance(token, str):
        token = ""
    state = State(device_id=raw["device_id"], user_id=user_id, token=token)
    if not state.has_user:
        return state.without_user()
    return state


def save_state(path, state):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(
        {"device_id": state.device_id, "user_id": state.user_id, "token": state.token},
        indent=2,
    )
    fd, tmp_name = tempfile.mkstemp(dir=str(path.parent), prefix=".state-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp_name, 0o600)
        os.replace(tmp_name, path)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise
