import os

import pytest

from lantern_exporter import output
from lantern_exporter.errors import OutputError
from lantern_exporter.output import write_files


def test_writes_and_reports_changes(tmp_path):
    changed = write_files(tmp_path, {"a.txt": b"one\n", "b.json": b"{}\n"})
    assert sorted(changed) == ["a.txt", "b.json"]
    assert (tmp_path / "a.txt").read_bytes() == b"one\n"


def test_unchanged_content_is_not_rewritten(tmp_path):
    write_files(tmp_path, {"a.txt": b"one\n"})
    before = os.stat(tmp_path / "a.txt").st_mtime_ns
    assert write_files(tmp_path, {"a.txt": b"one\n"}) == []
    assert os.stat(tmp_path / "a.txt").st_mtime_ns == before


def test_only_changed_files_are_replaced(tmp_path):
    write_files(tmp_path, {"a.txt": b"one\n", "b.txt": b"two\n"})
    assert write_files(tmp_path, {"a.txt": b"one\n", "b.txt": b"three\n"}) == ["b.txt"]


def test_empty_content_is_refused_and_old_file_survives(tmp_path):
    write_files(tmp_path, {"a.txt": b"one\n"})
    with pytest.raises(OutputError):
        write_files(tmp_path, {"a.txt": b""})
    assert (tmp_path / "a.txt").read_bytes() == b"one\n"


def test_failure_while_staging_leaves_everything_untouched(tmp_path, monkeypatch):
    write_files(tmp_path, {"a.txt": b"old-a\n", "b.txt": b"old-b\n"})
    real_fsync = os.fsync
    calls = {"n": 0}

    def flaky(fd):
        calls["n"] += 1
        if calls["n"] == 2:
            raise OSError("disk full")
        return real_fsync(fd)

    monkeypatch.setattr(output.os, "fsync", flaky)
    with pytest.raises(OutputError):
        write_files(tmp_path, {"a.txt": b"new-a\n", "b.txt": b"new-b\n"})
    assert (tmp_path / "a.txt").read_bytes() == b"old-a\n"
    assert (tmp_path / "b.txt").read_bytes() == b"old-b\n"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["a.txt", "b.txt"]


def test_a_failure_while_replacing_restores_every_earlier_file(tmp_path, monkeypatch):
    write_files(tmp_path, {"a.txt": b"old-a\n", "b.txt": b"old-b\n", "c.txt": b"old-c\n"})
    real_replace = os.replace
    state = {"count": 0}

    def flaky(src, dst):
        state["count"] += 1
        if state["count"] == 3:
            raise OSError("rename failed")
        return real_replace(src, dst)

    monkeypatch.setattr(output.os, "replace", flaky)
    with pytest.raises(OutputError):
        write_files(tmp_path, {"a.txt": b"new-a\n", "b.txt": b"new-b\n", "c.txt": b"new-c\n"})
    monkeypatch.setattr(output.os, "replace", real_replace)
    assert (tmp_path / "a.txt").read_bytes() == b"old-a\n"
    assert (tmp_path / "b.txt").read_bytes() == b"old-b\n"
    assert (tmp_path / "c.txt").read_bytes() == b"old-c\n"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["a.txt", "b.txt", "c.txt"]


def test_a_failed_first_publication_leaves_no_partial_files(tmp_path, monkeypatch):
    real_replace = os.replace
    state = {"count": 0}

    def flaky(src, dst):
        state["count"] += 1
        if state["count"] == 2:
            raise OSError("rename failed")
        return real_replace(src, dst)

    monkeypatch.setattr(output.os, "replace", flaky)
    with pytest.raises(OutputError):
        write_files(tmp_path, {"a.txt": b"a\n", "b.txt": b"b\n"})
    monkeypatch.setattr(output.os, "replace", real_replace)
    assert list(tmp_path.iterdir()) == []
