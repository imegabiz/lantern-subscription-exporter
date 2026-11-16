import os
import tempfile
from pathlib import Path

from .errors import OutputError


def _atomic_write(directory, target, content):
    fd, tmp_name = tempfile.mkstemp(dir=str(directory), prefix=".tmp-", suffix=".part")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp_name, 0o644)
        os.replace(tmp_name, target)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def write_files(directory, files, allow_empty=()):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    pending = []
    for name, content in files.items():
        if not isinstance(content, bytes) or (not content and name not in allow_empty):
            raise OutputError("refusing to write empty content for %s" % name)
        target = directory / name
        try:
            current = target.read_bytes()
        except OSError:
            current = None
        if current != content:
            pending.append((name, target, content, current))
    staged = []
    try:
        for name, target, content, current in pending:
            fd, tmp_name = tempfile.mkstemp(dir=str(directory), prefix=".tmp-", suffix=".part")
            staged.append((name, target, tmp_name, current))
            with os.fdopen(fd, "wb") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(tmp_name, 0o644)
    except OSError as exc:
        _discard(staged)
        raise OutputError("failed to stage output files: %s" % type(exc).__name__) from exc
    replaced = []
    try:
        for name, target, tmp_name, current in staged:
            os.replace(tmp_name, target)
            replaced.append((name, target, current))
    except OSError as exc:
        _rollback(directory, replaced)
        _discard([item for item in staged if item[0] not in {r[0] for r in replaced}])
        raise OutputError("failed to publish output files, previous files restored: %s" % type(exc).__name__) from exc
    return [name for name, _, _ in replaced]


def _discard(staged):
    for _, _, tmp_name, _ in staged:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass


def _rollback(directory, replaced):
    for name, target, previous in replaced:
        try:
            if previous is None:
                os.unlink(target)
            else:
                _atomic_write(directory, target, previous)
        except OSError:
            pass
