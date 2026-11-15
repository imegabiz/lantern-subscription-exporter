import base64
import json
import os
import stat
import uuid

import pytest

from lantern_exporter.errors import StateError, StateKeyError, StateMissingError, StateUnreadableError
from lantern_exporter.state import (
    ALGORITHM,
    ENVELOPE_VERSION,
    State,
    decrypt_state,
    encrypt_state,
    generate_key_text,
    load_encrypted_state,
    load_legacy_state,
    new_state,
    parse_key,
    remove_legacy_state,
    save_encrypted_state,
)

TOKEN = "super-secret-token-value"


@pytest.fixture
def state():
    return new_state().with_user(31337, TOKEN)


def test_new_state_has_uuid_and_no_user():
    fresh = new_state()
    uuid.UUID(fresh.device_id)
    assert not fresh.has_user


def test_round_trip(state, key):
    assert decrypt_state(encrypt_state(state, key), key) == state


def test_envelope_is_versioned_and_never_plain_text(state, key):
    blob = encrypt_state(state, key)
    envelope = json.loads(blob)
    assert envelope["version"] == ENVELOPE_VERSION == 1
    assert envelope["algorithm"] == ALGORITHM == "AES-256-GCM"
    assert set(envelope) == {"version", "algorithm", "nonce", "ciphertext"}
    assert len(base64.b64decode(envelope["nonce"])) == 12
    for secret in (TOKEN.encode(), state.device_id.encode(), b"31337", b"user_id", b"token"):
        assert secret not in blob


def test_every_encryption_uses_a_fresh_nonce(state, key):
    blobs = [encrypt_state(state, key) for _ in range(20)]
    nonces = {json.loads(b)["nonce"] for b in blobs}
    assert len(nonces) == 20
    assert len({json.loads(b)["ciphertext"] for b in blobs}) == 20


def test_wrong_key_is_rejected(state, key):
    blob = encrypt_state(state, key)
    other = parse_key(generate_key_text())
    with pytest.raises(StateUnreadableError):
        decrypt_state(blob, other)


@pytest.mark.parametrize("field", ["ciphertext", "nonce"])
def test_tampered_fields_are_rejected(state, key, field):
    envelope = json.loads(encrypt_state(state, key))
    raw = bytearray(base64.b64decode(envelope[field]))
    raw[0] ^= 1
    envelope[field] = base64.b64encode(bytes(raw)).decode()
    with pytest.raises(StateUnreadableError):
        decrypt_state(json.dumps(envelope).encode(), key)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda e: e.update(version=2),
        lambda e: e.update(version=0),
        lambda e: e.update(algorithm="AES-128-GCM"),
        lambda e: e.pop("nonce"),
        lambda e: e.update(nonce="!!!"),
        lambda e: e.update(ciphertext="AAAA"),
        lambda e: e.update(nonce=base64.b64encode(b"short").decode()),
    ],
)
def test_malformed_envelopes_are_rejected(state, key, mutate):
    envelope = json.loads(encrypt_state(state, key))
    mutate(envelope)
    with pytest.raises(StateUnreadableError):
        decrypt_state(json.dumps(envelope).encode(), key)


@pytest.mark.parametrize("blob", [b"", b"not json", b"[]", b"\xff\xfe", b"null"])
def test_garbage_is_rejected(key, blob):
    with pytest.raises(StateUnreadableError):
        decrypt_state(blob, key)


def test_truncated_file_is_rejected(state, key):
    blob = encrypt_state(state, key)
    with pytest.raises(StateUnreadableError):
        decrypt_state(blob[: len(blob) // 2], key)


def test_plaintext_with_valid_ciphertext_but_bad_content_is_rejected(key):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    from lantern_exporter.state import ASSOCIATED_DATA

    nonce = os.urandom(12)
    bad = AESGCM(key).encrypt(nonce, json.dumps({"device_id": "x"}).encode(), ASSOCIATED_DATA)
    envelope = {
        "version": 1,
        "algorithm": "AES-256-GCM",
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(bad).decode(),
    }
    with pytest.raises(StateUnreadableError):
        decrypt_state(json.dumps(envelope).encode(), key)


def test_associated_data_binds_the_header(state, key):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    envelope = json.loads(encrypt_state(state, key))
    nonce = base64.b64decode(envelope["nonce"])
    ciphertext = base64.b64decode(envelope["ciphertext"])
    with pytest.raises(Exception):
        AESGCM(key).decrypt(nonce, ciphertext, b"another-header")


def test_save_and_load_file(tmp_path, state, key):
    path = tmp_path / "state" / "lantern-state.enc"
    save_encrypted_state(path, state, key)
    assert load_encrypted_state(path, key) == state
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    raw = path.read_bytes()
    assert TOKEN.encode() not in raw and state.device_id.encode() not in raw
    assert [p.name for p in path.parent.iterdir()] == ["lantern-state.enc"]


def test_missing_file_is_a_distinct_error(tmp_path, key):
    with pytest.raises(StateMissingError):
        load_encrypted_state(tmp_path / "none.enc", key)


def test_failed_save_keeps_the_previous_file(tmp_path, state, key, monkeypatch):
    path = tmp_path / "s.enc"
    save_encrypted_state(path, state, key)
    before = path.read_bytes()
    other = state.with_user(1, "another-token")
    real_fsync = os.fsync

    def broken(fd):
        raise OSError("disk full")

    monkeypatch.setattr("lantern_exporter.state.os.fsync", broken)
    with pytest.raises(OSError):
        save_encrypted_state(path, other, key)
    monkeypatch.setattr("lantern_exporter.state.os.fsync", real_fsync)
    assert path.read_bytes() == before
    assert [p.name for p in tmp_path.iterdir()] == ["s.enc"]


def test_user_less_state_cannot_be_encrypted(key):
    with pytest.raises(StateError):
        encrypt_state(new_state(), key)


@pytest.mark.parametrize("value", ["", "   ", None])
def test_unset_key_is_rejected(value):
    with pytest.raises(StateKeyError):
        parse_key(value)


@pytest.mark.parametrize("value", ["not base64 at all!!", "QUJD", base64.b64encode(b"x" * 31).decode(), base64.b64encode(b"x" * 33).decode()])
def test_bad_keys_are_rejected_without_echoing_them(value):
    with pytest.raises(StateKeyError) as info:
        parse_key(value)
    assert value not in str(info.value)


def test_generated_keys_are_valid_and_distinct():
    first, second = generate_key_text(), generate_key_text()
    assert first != second
    assert len(parse_key(first)) == 32
    assert len(parse_key(first + "\n")) == 32


def test_legacy_state_loading_and_removal(tmp_path):
    path = tmp_path / "state.json"
    device = str(uuid.uuid4())
    path.write_text(json.dumps({"device_id": device, "user_id": 9, "token": "legacy-token"}), encoding="utf-8")
    assert load_legacy_state(path) == State(device, 9, "legacy-token")
    remove_legacy_state(path)
    assert not path.exists()
    remove_legacy_state(path)
    with pytest.raises(StateMissingError):
        load_legacy_state(path)


@pytest.mark.parametrize(
    "content",
    [
        "{bad",
        json.dumps({"device_id": "nope", "user_id": 5, "token": "t"}),
        json.dumps({"device_id": str(uuid.uuid4()), "user_id": 0, "token": "t"}),
        json.dumps({"device_id": str(uuid.uuid4()), "user_id": 5, "token": ""}),
        json.dumps({"device_id": str(uuid.uuid4()), "user_id": True, "token": "t"}),
    ],
)
def test_incomplete_legacy_state_is_rejected(tmp_path, content):
    path = tmp_path / "state.json"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(StateUnreadableError):
        load_legacy_state(path)
