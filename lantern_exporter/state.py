import base64
import binascii
import json
import os
import tempfile
import uuid
from dataclasses import dataclass, replace
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .errors import StateError, StateKeyError, StateMissingError, StateUnreadableError

ENVELOPE_VERSION = 1
ALGORITHM = "AES-256-GCM"
NONCE_BYTES = 12
KEY_BYTES = 32
ASSOCIATED_DATA = ("lantern-exporter-state|v%d|%s" % (ENVELOPE_VERSION, ALGORITHM)).encode("ascii")


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


def _state_from_mapping(raw):
    if not isinstance(raw, dict):
        raise StateUnreadableError("state content is not an object")
    device_id = raw.get("device_id")
    user_id = raw.get("user_id")
    token = raw.get("token")
    if not _valid_device_id(device_id):
        raise StateUnreadableError("state has an invalid device id")
    if isinstance(user_id, bool) or not isinstance(user_id, int) or user_id <= 0:
        raise StateUnreadableError("state has an invalid user id")
    if not isinstance(token, str) or not token:
        raise StateUnreadableError("state has no token")
    return State(device_id=device_id, user_id=user_id, token=token)


def parse_key(value):
    if not isinstance(value, str) or not value.strip():
        raise StateKeyError("the state encryption key is not set")
    compact = "".join(value.split())
    padded = compact + "=" * (-len(compact) % 4)
    try:
        key = base64.b64decode(padded.encode("ascii"), altchars=b"-_", validate=True)
    except (binascii.Error, ValueError, UnicodeError):
        raise StateKeyError("the state encryption key is not valid base64")
    if len(key) != KEY_BYTES:
        raise StateKeyError("the state encryption key must decode to exactly 32 bytes")
    return key


def generate_key_text():
    return base64.b64encode(os.urandom(KEY_BYTES)).decode("ascii")


def encrypt_state(state, key):
    if not state.has_user:
        raise StateError("refusing to encrypt a state without a user")
    plaintext = json.dumps(
        {"device_id": state.device_id, "user_id": state.user_id, "token": state.token},
        separators=(",", ":"),
    ).encode("utf-8")
    nonce = os.urandom(NONCE_BYTES)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, ASSOCIATED_DATA)
    envelope = {
        "version": ENVELOPE_VERSION,
        "algorithm": ALGORITHM,
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }
    return (json.dumps(envelope, indent=2) + "\n").encode("utf-8")


def decrypt_state(blob, key):
    try:
        envelope = json.loads(blob.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise StateUnreadableError("the state file is not a valid envelope")
    if not isinstance(envelope, dict):
        raise StateUnreadableError("the state file is not a valid envelope")
    if envelope.get("version") != ENVELOPE_VERSION:
        raise StateUnreadableError("the state file has an unsupported version")
    if envelope.get("algorithm") != ALGORITHM:
        raise StateUnreadableError("the state file uses an unsupported algorithm")
    try:
        nonce = base64.b64decode(envelope["nonce"].encode("ascii"), validate=True)
        ciphertext = base64.b64decode(envelope["ciphertext"].encode("ascii"), validate=True)
    except (KeyError, AttributeError, binascii.Error, ValueError, UnicodeError):
        raise StateUnreadableError("the state file has a malformed nonce or ciphertext")
    if len(nonce) != NONCE_BYTES or len(ciphertext) < 16:
        raise StateUnreadableError("the state file has a malformed nonce or ciphertext")
    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, ASSOCIATED_DATA)
    except InvalidTag:
        raise StateUnreadableError("the state file cannot be decrypted: wrong key or the file was changed")
    try:
        raw = json.loads(plaintext.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise StateUnreadableError("the decrypted state is not valid")
    return _state_from_mapping(raw)


def _atomic_write(path, content):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=str(path.parent), prefix=".state-", suffix=".tmp")
    try:
        os.chmod(tmp_name, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, path)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def state_exists(path):
    return Path(path).is_file()


def load_encrypted_state(path, key):
    path = Path(path)
    try:
        blob = path.read_bytes()
    except FileNotFoundError:
        raise StateMissingError("no encrypted state file exists yet")
    except OSError:
        raise StateUnreadableError("the state file cannot be read")
    return decrypt_state(blob, key)


def save_encrypted_state(path, state, key):
    blob = encrypt_state(state, key)
    if decrypt_state(blob, key) != state:
        raise StateError("the encrypted state did not round-trip")
    _atomic_write(path, blob)


def load_legacy_state(path):
    path = Path(path)
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise StateMissingError("no legacy state file was found to migrate")
    except (OSError, ValueError):
        raise StateUnreadableError("the legacy state file is not readable")
    return _state_from_mapping(raw)


def remove_legacy_state(path):
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
