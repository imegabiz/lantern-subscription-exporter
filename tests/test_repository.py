import json
import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
UPDATE = ROOT / ".github" / "workflows" / "update-subscription.yml"
TESTS = ROOT / ".github" / "workflows" / "tests.yml"
FIXTURE = ROOT / "tests" / "fixtures" / "config_response.json"
USES = re.compile(r"^[\w.-]+/[\w.-]+(/[\w./-]+)?@[0-9a-f]{40}$")


def load(path):
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if "on" not in data and True in data:
        data["on"] = data.pop(True)
    return data


def all_steps(workflow):
    for job in workflow["jobs"].values():
        for step in job["steps"]:
            yield step


@pytest.fixture(scope="module")
def update():
    return load(UPDATE)


@pytest.fixture(scope="module")
def tests_workflow():
    return load(TESTS)


def test_the_hourly_schedule_is_unchanged_and_there_is_exactly_one(update):
    assert update["on"]["schedule"] == [{"cron": "23 * * * *"}]


def test_manual_runs_are_possible_with_a_closed_set_of_bootstrap_choices(update):
    inputs = update["on"]["workflow_dispatch"]["inputs"]["bootstrap"]
    assert inputs["type"] == "choice" and inputs["default"] == "none"
    assert inputs["options"] == ["none", "create", "recreate", "migrate-from-cache"]


def test_updates_never_run_concurrently_and_are_never_cancelled(update):
    assert update["concurrency"]["group"] == "update-subscription"
    assert update["concurrency"]["cancel-in-progress"] is False


def test_update_workflow_has_least_privilege(update):
    assert update["permissions"] == {}
    assert update["jobs"]["update"]["permissions"] == {"contents": "write"}


def test_tests_workflow_is_read_only_and_has_no_secrets(tests_workflow):
    assert tests_workflow["permissions"] == {"contents": "read"}
    text = TESTS.read_text(encoding="utf-8")
    assert "secrets." not in text and "GITHUB_TOKEN" not in text


@pytest.mark.parametrize("path", [UPDATE, TESTS])
def test_no_dangerous_triggers(path):
    text = path.read_text(encoding="utf-8")
    assert "pull_request_target" not in text
    assert "workflow_run" not in text
    assert "repository_dispatch" not in text


@pytest.mark.parametrize("path", [UPDATE, TESTS])
def test_every_action_is_pinned_to_a_full_commit_sha(path):
    uses = [step["uses"] for step in all_steps(load(path)) if "uses" in step]
    assert uses
    for reference in uses:
        assert USES.match(reference), reference


def test_pull_request_checkouts_do_not_keep_credentials(tests_workflow):
    for step in all_steps(tests_workflow):
        if step.get("uses", "").startswith("actions/checkout"):
            assert step["with"]["persist-credentials"] is False


def test_the_secret_is_used_only_by_the_update_workflow_and_only_in_one_step(update):
    carriers = [s for s in all_steps(update) if "secrets.LANTERN_STATE_ENCRYPTION_KEY" in json.dumps(s)]
    assert len(carriers) == 1
    assert list(carriers[0]["env"]) == ["LANTERN_STATE_ENCRYPTION_KEY", "LANTERN_BOOTSTRAP", "LANTERN_HYSTERIA2_LINKS"]
    assert "secrets." not in TESTS.read_text(encoding="utf-8")


def test_actions_cache_is_never_used_to_save_state(update):
    steps = list(all_steps(update))
    cache_steps = [s for s in steps if "actions/cache" in s.get("uses", "")]
    assert len(cache_steps) == 1
    step = cache_steps[0]
    assert step["uses"].startswith("actions/cache/restore@")
    assert "migrate-from-cache" in step["if"]
    assert "cache/save" not in UPDATE.read_text(encoding="utf-8")


def test_user_input_is_not_interpolated_into_shell_scripts(update):
    for step in all_steps(update):
        script = step.get("run", "")
        assert "${{" not in script


def test_the_commit_step_only_stages_the_four_allowed_files(update):
    step = next(s for s in all_steps(update) if s.get("name") == "Commit changes")
    assert step["if"].replace(" ", "") == "${{always()}}"
    script = step["run"]
    assert "state/lantern-state.enc subscription/sub.txt subscription/singbox.json subscription/xray.json" in script
    assert "git add -A" not in script and "git add ." not in script and "git add --all" not in script
    assert "Unexpected files are staged" in script
    assert "set -x" not in script and "echo $" not in script


def test_secrets_are_never_echoed(update):
    text = UPDATE.read_text(encoding="utf-8")
    assert "echo" not in text.replace('echo "No changes to commit"', "").replace(
        'echo "Unexpected files are staged, refusing to commit"', ""
    )


def test_python_dependencies_are_pinned_exactly():
    for name in ("requirements.txt", "requirements-dev.txt"):
        for line in (ROOT / name).read_text(encoding="utf-8").splitlines():
            if line and not line.startswith("-r"):
                assert "==" in line, line


def test_pip_caching_never_involves_account_data(update):
    setup = next(s for s in all_steps(update) if s.get("uses", "").startswith("actions/setup-python"))
    assert setup["with"]["cache"] == "pip"
    assert setup["with"]["cache-dependency-path"] == "requirements.txt"


def test_runtime_secrets_directories_are_ignored_by_git():
    ignored = (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    assert ".state/" in ignored and ".cores/" in ignored


def test_the_core_lock_file_is_complete_and_checksummed():
    lock = json.loads((ROOT / "tools" / "cores.lock.json").read_text(encoding="utf-8"))
    assert {"xray", "sing-box", "hiddify-core", "geoip", "geosite"} <= set(lock)
    for versions in lock.values():
        for entry in versions.values():
            assert re.fullmatch(r"[0-9a-f]{64}", entry["sha256"])
            assert entry["url"].startswith("https://github.com/")
    assert set(lock["xray"]) == {"v26.3.23", "v26.11.9"}


def test_ci_matrix_matches_the_lock_file():
    lock = json.loads((ROOT / "tools" / "cores.lock.json").read_text(encoding="utf-8"))
    matrix = load(TESTS)["jobs"]["cores"]["strategy"]["matrix"]["xray"]
    assert sorted(matrix) == sorted(lock["xray"])


def test_operational_outputs_never_contain_fixture_or_state_data():
    fixture_text = FIXTURE.read_text(encoding="utf-8")
    markers = ["11111111-2222-4333-8444-555555555555", "192.0.2.11", "192.0.2.12", "192.0.2.13"]
    certificate = json.loads(fixture_text)["options"]["outbounds"][3]["tls"]["certificate"]
    markers.append(certificate.splitlines()[1])
    for folder in ("subscription", "state"):
        for path in (ROOT / folder).glob("*"):
            if path.is_file() and path.name != ".gitkeep":
                content = path.read_text(encoding="utf-8", errors="replace")
                for marker in markers:
                    assert marker not in content, (path.name, marker)
                assert "PRIVATE KEY" not in content


def test_no_plaintext_state_file_is_tracked_in_the_repository():
    for relative in (".state/state.json", "state/state.json", "state.json"):
        assert not (ROOT / relative).exists()
    for path in (ROOT / "state").glob("*") if (ROOT / "state").exists() else []:
        if path.name.endswith(".enc"):
            envelope = json.loads(path.read_text(encoding="utf-8"))
            assert set(envelope) == {"version", "algorithm", "nonce", "ciphertext"}


def test_python_sources_contain_no_comments():
    for path in (ROOT / "lantern_exporter").glob("*.py"):
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            assert not line.strip().startswith("#"), (path.name, number)


def test_readme_documents_the_key_facts():
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    for fragment in (
        "LANTERN_STATE_ENCRYPTION_KEY",
        "AES-256-GCM",
        "26.3.23",
        "1.14.0",
        "pinSHA256",
        "pre_initial_junk",
        "never sends it",
        "never retried",
        "migrate-from-cache",
        "Actions → Caches",
        "23 * * * *",
        "LANTERN_HYSTERIA2_LINKS",
        "public",
        "packet encoding",
        "empty (0 bytes)",
        "vless_without_security",
        "never written empty",
        "X-Lantern-User-Id",
    ):
        assert fragment in text, fragment


import subprocess


def _git(cwd, *args):
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, check=True).stdout


def _commit_script():
    step = next(s for s in all_steps(load(UPDATE)) if s.get("name") == "Commit changes")
    return step["run"]


@pytest.fixture
def sandbox(tmp_path):
    remote = tmp_path / "remote.git"
    work = tmp_path / "work"
    subprocess.run(["git", "init", "-q", "--bare", "-b", "main", str(remote)], check=True)
    subprocess.run(["git", "init", "-q", "-b", "main", str(work)], check=True)
    _git(work, "config", "user.name", "tester")
    _git(work, "config", "user.email", "tester@example.invalid")
    _git(work, "remote", "add", "origin", str(remote))
    (work / ".gitignore").write_text(".state/\n", encoding="utf-8")
    (work / "README.md").write_text("x\n", encoding="utf-8")
    _git(work, "add", ".")
    _git(work, "commit", "-q", "-m", "init")
    _git(work, "push", "-q", "-u", "origin", "main")
    return work, remote


def _run_commit_step(work):
    return subprocess.run(["bash", "-c", _commit_script()], cwd=work, capture_output=True, text=True)


def _write_outputs(work, state=True, outputs=True):
    if state:
        (work / "state").mkdir(exist_ok=True)
        (work / "state" / "lantern-state.enc").write_text('{"version":1}\n', encoding="utf-8")
    if outputs:
        (work / "subscription").mkdir(exist_ok=True)
        for name in ("sub.txt", "singbox.json", "xray.json"):
            (work / "subscription" / name).write_text("data-" + name + "\n", encoding="utf-8")


def test_commit_step_publishes_exactly_the_four_files_and_never_plaintext_state(sandbox):
    work, remote = sandbox
    _write_outputs(work)
    (work / ".state").mkdir()
    (work / ".state" / "state.json").write_text('{"token":"plain"}', encoding="utf-8")
    (work / "stray.txt").write_text("not allowed\n", encoding="utf-8")
    result = _run_commit_step(work)
    assert result.returncode == 0, result.stdout + result.stderr
    files = _git(remote, "ls-tree", "-r", "--name-only", "main").split()
    assert sorted(files) == [
        ".gitignore",
        "README.md",
        "state/lantern-state.enc",
        "subscription/singbox.json",
        "subscription/sub.txt",
        "subscription/xray.json",
    ]


def test_commit_step_does_nothing_when_nothing_changed(sandbox):
    work, remote = sandbox
    _write_outputs(work)
    assert _run_commit_step(work).returncode == 0
    before = _git(remote, "rev-parse", "main")
    result = _run_commit_step(work)
    assert result.returncode == 0 and "No changes to commit" in result.stdout
    assert _git(remote, "rev-parse", "main") == before


def test_commit_step_refuses_when_something_unexpected_is_already_staged(sandbox):
    work, remote = sandbox
    _write_outputs(work)
    (work / "evil.txt").write_text("secret\n", encoding="utf-8")
    _git(work, "add", "evil.txt")
    before = _git(remote, "rev-parse", "main")
    result = _run_commit_step(work)
    assert result.returncode == 1 and "Unexpected files are staged" in result.stdout
    assert _git(remote, "rev-parse", "main") == before


def test_commit_step_saves_a_new_state_even_when_no_outputs_exist_yet(sandbox):
    work, remote = sandbox
    _write_outputs(work, state=True, outputs=False)
    assert _run_commit_step(work).returncode == 0
    files = _git(remote, "ls-tree", "-r", "--name-only", "main").split()
    assert "state/lantern-state.enc" in files and not any(f.startswith("subscription/") for f in files)


def test_commit_step_with_nothing_at_all_is_harmless(sandbox):
    work, remote = sandbox
    before = _git(remote, "rev-parse", "main")
    result = _run_commit_step(work)
    assert result.returncode == 0 and "No changes to commit" in result.stdout
    assert _git(remote, "rev-parse", "main") == before
