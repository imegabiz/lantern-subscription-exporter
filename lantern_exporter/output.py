import os
import tempfile
from pathlib import Path

from .errors import OutputError


def write_files(directory, files):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    pending = []
    for name, content in files.items():
        if not isinstance(content, bytes) or not content:
            raise OutputError("refusing to write empty content for %s" % name)
        target = directory / name
        try:
            current = target.read_bytes()
        except OSError:
            current = None
        if current != content:
            pending.append((name, target, content))
    staged = []
    try:
        for name, target, content in pending:
            fd, tmp_name = tempfile.mkstemp(dir=str(directory), prefix=".tmp-", suffix=".part")
            staged.append((name, target, tmp_name))
            with os.fdopen(fd, "wb") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(tmp_name, 0o644)
        changed = []
        for name, target, tmp_name in staged:
            os.replace(tmp_name, target)
            changed.append(name)
        staged = []
        return changed
    except OSError as exc:
        raise OutputError("failed to write output files: %s" % type(exc).__name__) from exc
    finally:
        for _, _, tmp_name in staged:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
