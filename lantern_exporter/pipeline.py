import logging
from dataclasses import dataclass, field
from pathlib import Path

from . import constants as C
from .errors import ApiError, ExtractionError, ValidationError
from .extract import extract
from .links import build_link, unique_names
from .output import write_files
from .singbox import RESERVED_TAGS, build_profile, render_profile
from .state import load_state, save_state

log = logging.getLogger("lantern_exporter")

AUTH_STATUSES = (401, 403)


@dataclass
class Result:
    count: int
    changed: list
    skipped: dict = field(default_factory=dict)
    response_country: str = ""
    kinds: dict = field(default_factory=dict)


def _ensure_user(client, state, state_path):
    if state.has_user:
        return state
    log.info("creating an anonymous Lantern user")
    state = client.create_user(state)
    save_state(state_path, state)
    return state


def _fetch(client, state, state_path):
    state = _ensure_user(client, state, state_path)
    try:
        return client.fetch_config(state), state
    except ApiError as exc:
        if exc.status not in AUTH_STATUSES:
            raise
        log.warning("config request was rejected with HTTP %s, creating a fresh user", exc.status)
    state = client.create_user(state.without_user())
    save_state(state_path, state)
    return client.fetch_config(state), state


def render(extraction, min_configs):
    proxies = extraction.proxies
    if len(proxies) < min_configs:
        raise ValidationError(
            "only %d usable configs found, at least %d required" % (len(proxies), min_configs)
        )
    names = unique_names(proxies, reserved=RESERVED_TAGS)
    links = [build_link(proxy, name) for proxy, name in zip(proxies, names)]
    profile = build_profile(proxies, names)
    return {
        C.SUBSCRIPTION_LINKS_FILE: ("\n".join(links) + "\n").encode("utf-8"),
        C.SUBSCRIPTION_SINGBOX_FILE: render_profile(profile),
    }


def run(client, state_path, output_dir, min_configs=C.MIN_CONFIGS):
    state = load_state(state_path)
    save_state(state_path, state)
    response, state = _fetch(client, state, state_path)
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
        "response: country=%s outbounds=%d usable=%s skipped=%s",
        extraction.country or "unknown",
        len(response.get("options", {}).get("outbounds", [])),
        dict(sorted(kinds.items())) or "none",
        dict(sorted(extraction.skipped.items())) or "none",
    )
    files = render(extraction, min_configs)
    changed = write_files(Path(output_dir), files)
    return Result(
        count=len(extraction.proxies),
        changed=changed,
        skipped=dict(extraction.skipped),
        response_country=extraction.country,
        kinds=kinds,
    )
