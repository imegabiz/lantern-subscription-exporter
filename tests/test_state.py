import json
import os
import stat
import uuid

from lantern_exporter.state import State, load_state, new_state, save_state


def test_new_state_has_uuid_and_no_user():
    state = new_state()
    uuid.UUID(state.device_id)
    assert not state.has_user


def test_roundtrip_and_permissions(tmp_path):
    path = tmp_path / "sub" / "state.json"
    state = new_state().with_user(77, "tok")
    save_state(path, state)
    assert load_state(path) == state
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert [p.name for p in path.parent.iterdir()] == ["state.json"]


def test_missing_file_creates_fresh_state(tmp_path):
    state = load_state(tmp_path / "none.json")
    assert state.device_id and not state.has_user


def test_corrupt_file_creates_fresh_state(tmp_path):
    path = tmp_path / "state.json"
    path.write_text("{not json", encoding="utf-8")
    assert load_state(path).device_id


def test_invalid_device_id_is_replaced(tmp_path):
    path = tmp_path / "state.json"
    path.write_text(json.dumps({"device_id": "nope", "user_id": 5, "token": "t"}), encoding="utf-8")
    state = load_state(path)
    assert state.device_id != "nope"
    assert not state.has_user


def test_half_user_is_dropped(tmp_path):
    path = tmp_path / "state.json"
    device = str(uuid.uuid4())
    path.write_text(json.dumps({"device_id": device, "user_id": 5, "token": ""}), encoding="utf-8")
    state = load_state(path)
    assert state.device_id == device
    assert state.user_id == 0


def test_bad_types_are_sanitised(tmp_path):
    path = tmp_path / "state.json"
    device = str(uuid.uuid4())
    path.write_text(json.dumps({"device_id": device, "user_id": True, "token": 5}), encoding="utf-8")
    assert load_state(path) == State(device_id=device)
