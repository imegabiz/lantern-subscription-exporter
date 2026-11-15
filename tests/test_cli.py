import random

import pytest

from lantern_exporter import __main__ as cli
from lantern_exporter import constants as C
from lantern_exporter.client import LanternClient
from lantern_exporter.errors import StateUnreadableError
from lantern_exporter.state import parse_key

from conftest import FakeResponse, FakeSession


@pytest.fixture
def wired(monkeypatch, tmp_path, config_response, user_payload, key_text):
    session = FakeSession(
        {
            "/user-create": lambda n: FakeResponse(200, user_payload),
            "/config-new": lambda n: FakeResponse(200, config_response),
        }
    )
    captured = {}

    def factory(**kwargs):
        captured.update(kwargs)
        return LanternClient(session=session, sleep=lambda s: None, rng=random.Random(1), **kwargs)

    monkeypatch.setattr(cli, "LanternClient", factory)
    monkeypatch.setenv(C.STATE_KEY_ENV, key_text)
    monkeypatch.delenv("LANTERN_BOOTSTRAP", raising=False)
    monkeypatch.delenv("LANTERN_HYSTERIA2_LINKS", raising=False)
    base = ["--output-dir", str(tmp_path / "out"), "--state-file", str(tmp_path / "s" / "state.enc")]
    return session, captured, base, tmp_path


def test_generate_key_prints_a_valid_key(capsys):
    assert cli.main(["--generate-key"]) == 0
    printed = capsys.readouterr().out.strip()
    assert len(parse_key(printed)) == 32


def test_missing_key_stops_before_any_request(wired, monkeypatch, capsys):
    session, _, base, _ = wired
    monkeypatch.delenv(C.STATE_KEY_ENV)
    assert cli.main(base) == 1
    assert session.calls == []
    assert "not set" in capsys.readouterr().out


def test_invalid_key_stops_without_echoing_it(wired, monkeypatch, capsys):
    session, _, base, _ = wired
    monkeypatch.setenv(C.STATE_KEY_ENV, "definitely-not-a-key")
    assert cli.main(base) == 1
    assert session.calls == []
    assert "definitely-not-a-key" not in capsys.readouterr().out


def test_unknown_bootstrap_mode_is_rejected():
    with pytest.raises(SystemExit) as info:
        cli.main(["--bootstrap", "delete-everything"])
    assert info.value.code == 2


def test_first_run_without_bootstrap_fails_and_asks_for_a_manual_start(wired, capsys):
    session, _, base, _ = wired
    assert cli.main(base) == 1
    assert session.calls == []
    assert "previous output kept" in capsys.readouterr().out


def test_bootstrap_create_succeeds_and_reports_the_state_file(wired, capsys):
    session, _, base, tmp = wired
    assert cli.main(base + ["--bootstrap", "create"]) == 0
    text = capsys.readouterr().out
    assert "encrypted state file was written" in text
    assert "Hysteria2 config(s) were left out of sub.txt" in text
    assert "pre_initial_junk" in text
    assert (tmp / "s" / "state.enc").exists() and (tmp / "out" / "xray.json").exists()


def test_environment_bootstrap_mode_is_used(wired, monkeypatch):
    session, _, base, tmp = wired
    monkeypatch.setenv("LANTERN_BOOTSTRAP", "create")
    assert cli.main(base) == 0
    assert session.count("/user-create") == 1


def test_empty_environment_bootstrap_means_none(wired, monkeypatch):
    session, _, base, _ = wired
    monkeypatch.setenv("LANTERN_BOOTSTRAP", "")
    assert cli.main(base) == 1
    assert session.calls == []


def test_hysteria2_links_environment_switch(wired, monkeypatch):
    session, _, base, tmp = wired
    monkeypatch.setenv("LANTERN_HYSTERIA2_LINKS", "include")
    assert cli.main(base + ["--bootstrap", "create"]) == 0
    assert "hysteria2://" in (tmp / "out" / "sub.txt").read_text(encoding="utf-8")


def test_client_receives_the_verified_default_identity(wired):
    _, captured, base, _ = wired
    cli.main(base + ["--bootstrap", "create"])
    assert captured["app_version"] == "10.0.5"
    assert captured["singbox_version"] == "v1.14.2-lantern.3"
    assert captured["country"] == "IR"


def test_blank_country_disables_the_header(wired):
    _, captured, base, _ = wired
    cli.main(base + ["--bootstrap", "create", "--country", ""])
    assert captured["country"] == ""


def test_unreadable_state_exits_with_an_error_and_makes_no_request(wired, capsys):
    session, _, base, tmp = wired
    assert cli.main(base + ["--bootstrap", "create"]) == 0
    (tmp / "s" / "state.enc").write_bytes(b"corrupted")
    session.calls.clear()
    assert cli.main(base) == 1
    assert session.calls == []
    text = capsys.readouterr().out
    assert "previous output kept" in text and "state" in text


def test_min_configs_below_one_is_refused(wired, capsys):
    _, _, base, _ = wired
    assert cli.main(base + ["--min-configs", "0"]) == 2
