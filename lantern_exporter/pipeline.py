import json
import logging
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from . import constants as C
from .errors import ApiError, StateError, StateExistsError, ValidationError
from .extract import extract
from .links import build_link, unique_names
from .output import write_files
from .singbox import RESERVED_TAGS, build_profile, render_profile
from .state import (
    State,
    load_encrypted_state,
    load_legacy_state,
    remove_legacy_state,
    save_encrypted_state,
    state_exists,
)
from .xray import build_config as build_xray_config, render_config as render_xray_config

log = logging.getLogger("lantern_exporter")

AUTH_STATUSES = (401, 403)


@dataclass
class Result:
    count: int
    changed: list
    skipped: dict = field(default_factory=dict)
    response_country: str = ""
    kinds: dict = field(default_factory=dict)
    counts: dict = field(default_factory=dict)
    link_count: int = 0
    links_omitted: int = 0
    junk_not_expressible: int = 0
    state_written: bool = False


def _new_account(client, state_path, key, device_id):
    user_id, token = client.create_user(device_id)
    state = State(device_id=device_id).with_user(user_id, token)
    save_encrypted_state(state_path, state, key)
    return state


def prepare_state(client, state_path, key, bootstrap, legacy_state_path):
    if bootstrap == "none":
        return load_encrypted_state(state_path, key), False
    if bootstrap == "create":
        if state_exists(state_path):
            raise StateExistsError(
                "an encrypted state file already exists; use bootstrap 'recreate' to replace the account on purpose"
            )
        log.info("creating the Lantern account for the first time")
        return _new_account(client, state_path, key, str(uuid.uuid4())), True
    if bootstrap == "recreate":
        device_id = str(uuid.uuid4())
        if state_exists(state_path):
            try:
                device_id = load_encrypted_state(state_path, key).device_id
            except StateError:
                log.warning("the existing state could not be read, a new device id is used")
        log.info("creating a replacement Lantern account")
        return _new_account(client, state_path, key, device_id), True
    if bootstrap == "migrate":
        if state_exists(state_path):
            raise StateExistsError("an encrypted state file already exists, nothing to migrate")
        legacy = load_legacy_state(legacy_state_path)
        save_encrypted_state(state_path, legacy, key)
        remove_legacy_state(legacy_state_path)
        log.info("the legacy account state was migrated into the encrypted state file")
        return legacy, True
    raise ValidationError("unknown bootstrap mode")


def fetch_with_saved_account(client, state):
    try:
        return client.fetch_config(state)
    except ApiError as exc:
        if exc.status in AUTH_STATUSES:
            raise ApiError(
                "the server rejected the saved account (HTTP %d); if this repeats, run the workflow "
                "manually with bootstrap set to recreate" % exc.status,
                exc.status,
            ) from exc
        raise


def ensure_no_state_in_files(files, state):
    token = state.token.encode("utf-8")
    secrets = [state.device_id.encode("utf-8")]
    secrets.append(token if len(token) >= 8 else b'"' + token + b'"')
    for name, content in files.items():
        for secret in secrets:
            if secret and secret in content:
                raise ValidationError("account data was found in %s, refusing to publish" % name)


def render(extraction, min_configs, hysteria2_links=C.DEFAULT_HYSTERIA2_LINKS):
    proxies = extraction.proxies
    if len(proxies) < min_configs:
        raise ValidationError(
            "only %d usable configs found, at least %d required" % (len(proxies), min_configs)
        )
    if len(proxies) > C.MAX_CONFIGS:
        raise ValidationError(
            "%d usable configs exceed the safety ceiling of %d, nothing is published"
            % (len(proxies), C.MAX_CONFIGS)
        )
    names = unique_names(proxies, reserved=RESERVED_TAGS)
    pairs = [
        (proxy, name)
        for proxy, name in zip(proxies, names)
        if proxy.kind != "hysteria2" or hysteria2_links == "include"
    ]
    omitted = len(proxies) - len(pairs)
    if not pairs:
        raise ValidationError(
            "no usable config can be published as a share link; Hysteria2 links are %s by default "
            "because Hiddify ignores the certificate pin" % ("omitted" if hysteria2_links == "omit" else "disabled")
        )
    links = [build_link(proxy, name) for proxy, name in pairs]
    profile = build_profile(proxies, names)
    xray_config = build_xray_config(proxies)
    files = {
        C.SUBSCRIPTION_LINKS_FILE: ("\n".join(links) + "\n").encode("utf-8"),
        C.SUBSCRIPTION_SINGBOX_FILE: render_profile(profile),
        C.SUBSCRIPTION_XRAY_FILE: render_xray_config(xray_config),
    }
    verify_consistency(files, len(proxies), len(pairs))
    return files, omitted


def verify_consistency(files, proxy_count, link_count):
    links = files[C.SUBSCRIPTION_LINKS_FILE].decode("utf-8").splitlines()
    if len(links) != link_count or any(not line.strip() for line in links):
        raise ValidationError("the share link list is inconsistent")
    profile = json.loads(files[C.SUBSCRIPTION_SINGBOX_FILE].decode("utf-8"))
    in_profile = [o for o in profile["outbounds"] if o["type"] in ("shadowsocks", "vless", "hysteria2")]
    if len(in_profile) != proxy_count:
        raise ValidationError("the sing-box profile is inconsistent")
    xray_config = json.loads(files[C.SUBSCRIPTION_XRAY_FILE].decode("utf-8"))
    in_xray = [o for o in xray_config["outbounds"] if str(o.get("tag", "")).startswith("lantern-")]
    if len(in_xray) != proxy_count:
        raise ValidationError("the xray config is inconsistent")


def run(
    client,
    state_path,
    output_dir,
    key,
    bootstrap="none",
    legacy_state_path=C.DEFAULT_LEGACY_STATE_FILE,
    min_configs=C.MIN_CONFIGS,
    hysteria2_links=C.DEFAULT_HYSTERIA2_LINKS,
):
    state, state_written = prepare_state(client, state_path, key, bootstrap, legacy_state_path)
    response = fetch_with_saved_account(client, state)
    extraction = extract(response)
    if client.country and extraction.country and client.country.upper() != extraction.country.upper():
        log.warning(
            "server answered for country %s while %s was requested",
            extraction.country,
            client.country,
        )
    kinds = {}
    for proxy in extraction.proxies:
        kinds[proxy.kind] = kinds.get(proxy.kind, 0) + 1
    log.info(
        "response: country=%s counts=%s usable=%s skipped=%s",
        extraction.country or "unknown",
        extraction.counts,
        dict(sorted(kinds.items())) or "none",
        dict(sorted(extraction.skipped.items())) or "none",
    )
    files, omitted = render(extraction, min_configs, hysteria2_links)
    ensure_no_state_in_files(files, state)
    changed = write_files(Path(output_dir), files)
    junk = sum(1 for p in extraction.proxies if p.kind == "hysteria2" and p.outbound.get("pre_initial_junk"))
    return Result(
        count=len(extraction.proxies),
        changed=changed,
        skipped=dict(extraction.skipped),
        response_country=extraction.country,
        kinds=kinds,
        counts=dict(extraction.counts),
        link_count=len(extraction.proxies) - omitted,
        links_omitted=omitted,
        junk_not_expressible=junk,
        state_written=state_written,
    )
