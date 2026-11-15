import argparse
import hashlib
import json
import os
import shutil
import stat
import sys
import tarfile
import urllib.request
import zipfile
from pathlib import Path

LOCK = Path(__file__).with_name("cores.lock.json")
ALLOWED_HOSTS = ("https://github.com/",)


def sha256_of(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def download(url, target):
    if not url.startswith(ALLOWED_HOSTS):
        raise SystemExit("refusing to download from an unexpected host: %s" % url)
    request = urllib.request.Request(url, headers={"User-Agent": "lantern-exporter-ci"})
    with urllib.request.urlopen(request, timeout=300) as response, open(target, "wb") as out:
        shutil.copyfileobj(response, out)


def safe_extract_tar(archive, destination):
    with tarfile.open(archive) as bundle:
        root = destination.resolve()
        for member in bundle.getmembers():
            if not (destination / member.name).resolve().is_relative_to(root):
                raise SystemExit("unsafe path in archive")
        bundle.extractall(destination, filter="data")


def safe_extract_zip(archive, destination):
    with zipfile.ZipFile(archive) as bundle:
        root = destination.resolve()
        for name in bundle.namelist():
            if not (destination / name).resolve().is_relative_to(root):
                raise SystemExit("unsafe path in archive")
        bundle.extractall(destination)


def fetch(name, version, entry, dest):
    folder = dest / name
    folder.mkdir(parents=True, exist_ok=True)
    archive = folder / ("download-" + version.replace("/", "_"))
    download(entry["url"], archive)
    actual = sha256_of(archive)
    if actual != entry["sha256"]:
        archive.unlink()
        raise SystemExit("checksum mismatch for %s %s: expected %s got %s" % (name, version, entry["sha256"], actual))
    target_dir = folder / version
    if target_dir.exists():
        shutil.rmtree(target_dir)
    target_dir.mkdir(parents=True)
    if entry["format"] == "zip":
        safe_extract_zip(archive, target_dir)
    elif entry["format"] == "tar.gz":
        safe_extract_tar(archive, target_dir)
    else:
        shutil.copyfile(archive, target_dir / entry["binary"])
    archive.unlink()
    binary = target_dir / entry["binary"]
    if not binary.exists():
        raise SystemExit("expected file %s was not found after extraction" % entry["binary"])
    if name in ("xray", "sing-box", "hiddify-core"):
        binary.chmod(binary.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return binary


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--dest", default=".cores")
    parser.add_argument("--xray", required=True)
    parser.add_argument("--sing-box", default="v1.14.4")
    parser.add_argument("--hiddify-core", default="v5.9.1")
    parser.add_argument("--geoip", default="202611080027")
    parser.add_argument("--geosite", default="20261115005626")
    args = parser.parse_args(argv)
    lock = json.loads(LOCK.read_text(encoding="utf-8"))
    dest = Path(args.dest).resolve()
    wanted = {
        "xray": args.xray,
        "sing-box": args.sing_box,
        "hiddify-core": args.hiddify_core,
        "geoip": args.geoip,
        "geosite": args.geosite,
    }
    paths = {}
    for name, version in wanted.items():
        if version not in lock.get(name, {}):
            raise SystemExit("%s %s is not in the lock file" % (name, version))
        paths[name] = fetch(name, version, lock[name][version], dest)
    asset_dir = dest / "geo"
    asset_dir.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(paths["geoip"], asset_dir / "geoip.dat")
    shutil.copyfile(paths["geosite"], asset_dir / "geosite.dat")
    exports = {
        "XRAY_BIN": str(paths["xray"]),
        "SING_BOX_BIN": str(paths["sing-box"]),
        "HIDDIFY_BIN": str(paths["hiddify-core"]),
        "XRAY_ASSET_DIR": str(asset_dir),
    }
    env_file = os.environ.get("GITHUB_ENV")
    for key, value in exports.items():
        print("%s=%s" % (key, value))
    if env_file:
        with open(env_file, "a", encoding="utf-8") as handle:
            for key, value in exports.items():
                handle.write("%s=%s\n" % (key, value))
    return 0


if __name__ == "__main__":
    sys.exit(main())
