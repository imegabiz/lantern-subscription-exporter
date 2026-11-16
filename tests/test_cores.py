import json
import os
import re
import shutil
import socket
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest
import requests

from lantern_exporter.client import LanternClient
from lantern_exporter.pipeline import run
from lantern_exporter.state import generate_key_text, parse_key

from conftest import FakeResponse, FakeSession

pytestmark = pytest.mark.cores

SS_KEY = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
UUID = "11111111-2222-4333-8444-555555555555"
BODY = b"LANTERN-LOOPBACK-OK"


def binary(env_name, default):
    value = os.environ.get(env_name) or shutil.which(default)
    return value if value and Path(value).exists() else None


XRAY = binary("XRAY_BIN", "xray")
SING_BOX = binary("SING_BOX_BIN", "sing-box")
HIDDIFY = binary("HIDDIFY_BIN", "hiddify-core")
GEO_ASSETS = os.environ.get("XRAY_ASSET_DIR")
need_geo = pytest.mark.skipif(
    not GEO_ASSETS or not (Path(GEO_ASSETS) / "geosite.dat").exists(), reason="geo assets not available"
)


need_xray = pytest.mark.skipif(XRAY is None, reason="xray binary not available")
need_singbox = pytest.mark.skipif(SING_BOX is None, reason="sing-box binary not available")
need_hiddify = pytest.mark.skipif(HIDDIFY is None, reason="hiddify-core binary not available")


XRAY_FREEDOM = {
    "protocol": "freedom",
    "settings": {"finalRules": [{"action": "allow", "network": "tcp,udp", "ip": ["127.0.0.0/8"]}]},
}


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_port(port, timeout=15):
    deadline = time.time() + timeout
    while time.time() < deadline:
        with socket.socket() as sock:
            sock.settimeout(0.3)
            if sock.connect_ex(("127.0.0.1", port)) == 0:
                return
        time.sleep(0.1)
    raise AssertionError("port %d did not open" % port)


class Target(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", str(len(BODY)))
        self.end_headers()
        self.wfile.write(BODY)

    def log_message(self, *args):
        pass


@pytest.fixture
def target():
    server = HTTPServer(("127.0.0.1", 0), Target)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield "http://127.0.0.1:%d/" % server.server_address[1]
    server.shutdown()


@pytest.fixture
def procs():
    running = []
    yield running
    for proc in running:
        proc.terminate()
    for proc in running:
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


def spawn(procs, argv, cwd, env=None):
    log = open(Path(cwd) / ("proc-%d.log" % len(procs)), "wb")
    proc = subprocess.Popen(argv, cwd=str(cwd), stdout=log, stderr=subprocess.STDOUT, env=env)
    procs.append(proc)
    return proc


def fetch_through(proxy_port, url):
    proxies = {"http": "http://127.0.0.1:%d" % proxy_port}
    return requests.get(url, proxies=proxies, timeout=15).content


def generate(tmp_path, outbounds, locations=None):
    response = {
        "country": "IR",
        "options": {"outbounds": outbounds},
        "outbound_locations": locations or {},
    }
    session = FakeSession(
        {
            "/user-create": lambda n: FakeResponse(200, {"userId": 1, "token": "core-test-token-long-value"}),
            "/config-new": lambda n: FakeResponse(200, response),
        }
    )
    out = tmp_path / "sub"
    run(
        LanternClient(session=session),
        tmp_path / "state" / "state.enc",
        out,
        parse_key(generate_key_text()),
        bootstrap="create",
        hysteria2_links="include",
    )
    return out


def ss_outbound(port):
    return {
        "type": "shadowsocks",
        "tag": "ss-1",
        "server": "127.0.0.1",
        "server_port": port,
        "method": "2022-blake3-chacha20-poly1305",
        "password": SS_KEY,
    }


def x25519():
    text = subprocess.run([XRAY, "x25519"], capture_output=True, text=True, check=True).stdout
    private = re.search(r"PrivateKey:\s*(\S+)", text).group(1)
    public = re.search(r"Password \(PublicKey\):\s*(\S+)", text).group(1)
    return private, public


def reality_outbound(port, public):
    return {
        "type": "vless",
        "tag": "vless-1",
        "server": "127.0.0.1",
        "server_port": port,
        "uuid": UUID,
        "flow": "xtls-rprx-vision",
        "tls": {
            "enabled": True,
            "server_name": "reality.example.com",
            "utls": {"enabled": True, "fingerprint": "chrome"},
            "reality": {"enabled": True, "public_key": public},
        },
    }


def pin_route(profile, tag_prefix, listen_port):
    target_tag = next(o["tag"] for o in profile["outbounds"] if o["type"] in ("shadowsocks", "vless", "hysteria2"))
    profile["route"] = {"final": target_tag}
    profile.pop("dns", None)
    profile.pop("experimental", None)
    for outbound in profile["outbounds"]:
        outbound.pop("domain_resolver", None)
    profile["inbounds"] = [
        {"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": listen_port}
    ]
    return profile


def write_json(path, data):
    Path(path).write_text(json.dumps(data), encoding="utf-8")
    return str(path)


def hiddify_env():
    env = dict(os.environ)
    env["LD_LIBRARY_PATH"] = str(Path(HIDDIFY).parent) + ":" + env.get("LD_LIBRARY_PATH", "")
    return env


def xray_client_from_links(tmp_path, links_file, listen_port):
    parsed = tmp_path / "xray_outbounds.json"
    subprocess.run(
        [HIDDIFY, "parse", "--xray", str(links_file), "-o", str(parsed)],
        check=True,
        capture_output=True,
        env=hiddify_env(),
        cwd=str(tmp_path),
        timeout=60,
    )
    outbounds = json.loads(parsed.read_text(encoding="utf-8"))["outbounds"]
    config = {
        "log": {"loglevel": "warning"},
        "inbounds": [{"listen": "127.0.0.1", "port": listen_port, "protocol": "http", "tag": "in"}],
        "outbounds": outbounds,
    }
    return write_json(tmp_path / "xray_client.json", config)


def singbox_server_ss(tmp_path, port):
    config = {
        "log": {"level": "warn"},
        "inbounds": [
            {
                "type": "shadowsocks",
                "tag": "in",
                "listen": "127.0.0.1",
                "listen_port": port,
                "method": "2022-blake3-chacha20-poly1305",
                "password": SS_KEY,
            }
        ],
        "outbounds": [{"type": "direct", "tag": "direct"}],
    }
    return write_json(tmp_path / "sb_server.json", config)


def xray_server_ss(tmp_path, port):
    config = {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "listen": "127.0.0.1",
                "port": port,
                "protocol": "shadowsocks",
                "settings": {"method": "2022-blake3-chacha20-poly1305", "password": SS_KEY, "network": "tcp,udp"},
            }
        ],
        "outbounds": [XRAY_FREEDOM],
    }
    return write_json(tmp_path / "xray_server_ss.json", config)


@pytest.fixture
def tls_dest(tmp_path):
    cert = tmp_path / "cert.pem"
    key = tmp_path / "key.pem"
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
            "-nodes", "-keyout", str(key), "-out", str(cert), "-days", "2", "-subj", "/CN=localhost",
            "-addext", "subjectAltName=DNS:localhost",
        ],
        check=True,
        capture_output=True,
    )
    port = free_port()
    log = open(tmp_path / "tls-dest.log", "wb")
    proc = subprocess.Popen(
        [
            "openssl", "s_server", "-accept", str(port), "-cert", str(cert), "-key", str(key),
            "-tls1_3", "-alpn", "h2,http/1.1", "-www", "-quiet",
        ],
        stdout=log,
        stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL,
    )
    wait_port(port)
    yield port
    proc.terminate()
    proc.wait(timeout=5)


def xray_server_reality(tmp_path, port, dest_port, private):
    config = {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "listen": "127.0.0.1",
                "port": port,
                "protocol": "vless",
                "settings": {"clients": [{"id": UUID, "flow": "xtls-rprx-vision"}], "decryption": "none"},
                "streamSettings": {
                    "network": "tcp",
                    "security": "reality",
                    "realitySettings": {
                        "dest": "127.0.0.1:%d" % dest_port,
                        "serverNames": ["reality.example.com"],
                        "privateKey": private,
                        "shortIds": [""],
                    },
                },
            }
        ],
        "outbounds": [XRAY_FREEDOM],
    }
    return write_json(tmp_path / "xray_server_reality.json", config)


def singbox_server_reality(tmp_path, port, dest_port, private):
    config = {
        "log": {"level": "warn"},
        "inbounds": [
            {
                "type": "vless",
                "tag": "in",
                "listen": "127.0.0.1",
                "listen_port": port,
                "users": [{"uuid": UUID, "flow": "xtls-rprx-vision"}],
                "tls": {
                    "enabled": True,
                    "server_name": "reality.example.com",
                    "reality": {
                        "enabled": True,
                        "handshake": {"server": "127.0.0.1", "server_port": dest_port},
                        "private_key": private,
                        "short_id": [""],
                    },
                },
            }
        ],
        "outbounds": [{"type": "direct", "tag": "direct"}],
    }
    return write_json(tmp_path / "sb_server_reality.json", config)


def singbox_keypair():
    text = subprocess.run([SING_BOX, "generate", "reality-keypair"], capture_output=True, text=True, check=True).stdout
    private = re.search(r"PrivateKey:\s*(\S+)", text).group(1)
    public = re.search(r"PublicKey:\s*(\S+)", text).group(1)
    return private, public


def make_cert(tmp_path, name):
    cert = tmp_path / "hy2-cert.pem"
    key = tmp_path / "hy2-key.pem"
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
            "-nodes", "-keyout", str(key), "-out", str(cert), "-days", "2", "-subj", "/CN=" + name,
            "-addext", "subjectAltName=DNS:" + name,
        ],
        check=True,
        capture_output=True,
    )
    return cert, key


def hysteria2x_outbound(port, pem):
    return {
        "type": "hysteria2x",
        "tag": "hy2x-1",
        "server": "127.0.0.1",
        "server_port": port,
        "password": "hy2-test-password",
        "tls": {"enabled": True, "server_name": "api.push.apple.com", "certificate": pem},
        "pre_initial_junk": True,
    }


def singbox_server_hysteria2(tmp_path, port, cert, key):
    config = {
        "log": {"level": "warn"},
        "inbounds": [
            {
                "type": "hysteria2",
                "tag": "in",
                "listen": "127.0.0.1",
                "listen_port": port,
                "users": [{"password": "hy2-test-password"}],
                "tls": {
                    "enabled": True,
                    "server_name": "api.push.apple.com",
                    "certificate_path": str(cert),
                    "key_path": str(key),
                },
            }
        ],
        "outbounds": [{"type": "direct", "tag": "direct"}],
    }
    return write_json(tmp_path / "sb_server_hy2.json", config)


def hiddify_singbox_client_from_links(tmp_path, links_file, listen_port):
    parsed = tmp_path / "hiddify_outbounds.json"
    subprocess.run(
        [HIDDIFY, "parse", str(links_file), "-o", str(parsed)],
        check=True,
        capture_output=True,
        env=hiddify_env(),
        cwd=str(tmp_path),
        timeout=60,
    )
    outbound = json.loads(parsed.read_text(encoding="utf-8"))["outbounds"][0]
    config = {
        "log": {"level": "warn"},
        "inbounds": [{"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": listen_port}],
        "outbounds": [outbound, {"type": "direct", "tag": "direct"}],
        "route": {"final": outbound["tag"]},
    }
    return write_json(tmp_path / "hiddify_client.json", config)


@need_singbox
def test_singbox_check_accepts_generated_profile(tmp_path):
    cert, _ = make_cert(tmp_path, "api.push.apple.com")
    out = generate(
        tmp_path,
        [ss_outbound(8388), reality_outbound(443, "A" * 43), hysteria2x_outbound(8443, cert.read_text())],
    )
    result = subprocess.run([SING_BOX, "check", "-c", str(out / "singbox.json")], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


@need_hiddify
@need_xray
def test_hiddify_parses_links_and_xray_accepts_them(tmp_path):
    out = generate(tmp_path, [ss_outbound(8388), reality_outbound(443, "B" * 43)])
    config = xray_client_from_links(tmp_path, out / "sub.txt", free_port())
    result = subprocess.run([XRAY, "run", "-test", "-c", config], capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "Configuration OK" in result.stdout


@need_singbox
def test_singbox_client_connects_to_singbox_ss2022_server(tmp_path, procs, target):
    server_port, client_port = free_port(), free_port()
    out = generate(tmp_path, [ss_outbound(server_port)])
    profile = pin_route(json.loads((out / "singbox.json").read_text(encoding="utf-8")), "", client_port)
    spawn(procs, [SING_BOX, "run", "-c", singbox_server_ss(tmp_path, server_port)], tmp_path)
    wait_port(server_port)
    spawn(procs, [SING_BOX, "run", "-c", write_json(tmp_path / "sb_client.json", profile)], tmp_path)
    wait_port(client_port)
    assert fetch_through(client_port, target) == BODY


@need_singbox
@need_xray
def test_singbox_client_connects_to_xray_ss2022_server(tmp_path, procs, target):
    server_port, client_port = free_port(), free_port()
    out = generate(tmp_path, [ss_outbound(server_port)])
    profile = pin_route(json.loads((out / "singbox.json").read_text(encoding="utf-8")), "", client_port)
    spawn(procs, [XRAY, "run", "-c", xray_server_ss(tmp_path, server_port)], tmp_path)
    wait_port(server_port)
    spawn(procs, [SING_BOX, "run", "-c", write_json(tmp_path / "sb_client.json", profile)], tmp_path)
    wait_port(client_port)
    assert fetch_through(client_port, target) == BODY


@need_xray
@need_hiddify
def test_xray_client_from_generated_link_connects_ss2022(tmp_path, procs, target):
    server_port, client_port = free_port(), free_port()
    out = generate(tmp_path, [ss_outbound(server_port)])
    spawn(procs, [XRAY, "run", "-c", xray_server_ss(tmp_path, server_port)], tmp_path)
    wait_port(server_port)
    spawn(procs, [XRAY, "run", "-c", xray_client_from_links(tmp_path, out / "sub.txt", client_port)], tmp_path)
    wait_port(client_port)
    assert fetch_through(client_port, target) == BODY


@pytest.mark.xfail(
    strict=False,
    reason="observed with Xray 26.11.9 only: the sing-box 1.14.4 client is rejected by its Reality server; the same outbound works with Xray 26.3.23, with a sing-box server and through an Xray client",
)
@need_xray
@need_singbox
def test_singbox_client_connects_to_xray_vless_reality_vision(tmp_path, procs, target, tls_dest):
    server_port, client_port = free_port(), free_port()
    private, public = x25519()
    out = generate(tmp_path, [reality_outbound(server_port, public)])
    profile = pin_route(json.loads((out / "singbox.json").read_text(encoding="utf-8")), "", client_port)
    spawn(procs, [XRAY, "run", "-c", xray_server_reality(tmp_path, server_port, tls_dest, private)], tmp_path)
    wait_port(server_port)
    spawn(procs, [SING_BOX, "run", "-c", write_json(tmp_path / "sb_client.json", profile)], tmp_path)
    wait_port(client_port)
    assert fetch_through(client_port, target) == BODY


@need_xray
@need_hiddify
def test_xray_client_from_generated_link_connects_vless_reality_vision(tmp_path, procs, target, tls_dest):
    server_port, client_port = free_port(), free_port()
    private, public = x25519()
    out = generate(tmp_path, [reality_outbound(server_port, public)])
    spawn(procs, [XRAY, "run", "-c", xray_server_reality(tmp_path, server_port, tls_dest, private)], tmp_path)
    wait_port(server_port)
    spawn(procs, [XRAY, "run", "-c", xray_client_from_links(tmp_path, out / "sub.txt", client_port)], tmp_path)
    wait_port(client_port)
    assert fetch_through(client_port, target) == BODY


@need_singbox
def test_singbox_client_connects_to_singbox_vless_reality_vision(tmp_path, procs, target, tls_dest):
    server_port, client_port = free_port(), free_port()
    private, public = singbox_keypair()
    out = generate(tmp_path, [reality_outbound(server_port, public)])
    profile = pin_route(json.loads((out / "singbox.json").read_text(encoding="utf-8")), "", client_port)
    spawn(procs, [SING_BOX, "run", "-c", singbox_server_reality(tmp_path, server_port, tls_dest, private)], tmp_path)
    wait_port(server_port)
    spawn(procs, [SING_BOX, "run", "-c", write_json(tmp_path / "sb_client.json", profile)], tmp_path)
    wait_port(client_port)
    assert fetch_through(client_port, target) == BODY


@need_xray
@need_singbox
@need_hiddify
def test_xray_client_connects_to_singbox_vless_reality_vision(tmp_path, procs, target, tls_dest):
    server_port, client_port = free_port(), free_port()
    private, public = singbox_keypair()
    out = generate(tmp_path, [reality_outbound(server_port, public)])
    spawn(procs, [SING_BOX, "run", "-c", singbox_server_reality(tmp_path, server_port, tls_dest, private)], tmp_path)
    wait_port(server_port)
    spawn(procs, [XRAY, "run", "-c", xray_client_from_links(tmp_path, out / "sub.txt", client_port)], tmp_path)
    wait_port(client_port)
    assert fetch_through(client_port, target) == BODY


@need_singbox
def test_singbox_client_with_pinned_certificate_connects_to_hysteria2_server(tmp_path, procs, target):
    server_port, client_port = free_port(), free_port()
    cert, key = make_cert(tmp_path, "api.push.apple.com")
    out = generate(tmp_path, [hysteria2x_outbound(server_port, cert.read_text())])
    profile = pin_route(json.loads((out / "singbox.json").read_text(encoding="utf-8")), "", client_port)
    hy2 = next(o for o in profile["outbounds"] if o["type"] == "hysteria2")
    assert "insecure" not in hy2["tls"]
    spawn(procs, [SING_BOX, "run", "-c", singbox_server_hysteria2(tmp_path, server_port, cert, key)], tmp_path)
    time.sleep(2)
    spawn(procs, [SING_BOX, "run", "-c", write_json(tmp_path / "sb_client.json", profile)], tmp_path)
    wait_port(client_port)
    assert fetch_through(client_port, target) == BODY


@need_singbox
def test_pinned_certificate_client_rejects_a_server_with_another_certificate(tmp_path, procs, target):
    server_port, client_port = free_port(), free_port()
    trusted, _ = make_cert(tmp_path, "api.push.apple.com")
    other_dir = tmp_path / "other"
    other_dir.mkdir()
    other_cert, other_key = make_cert(other_dir, "api.push.apple.com")
    out = generate(tmp_path, [hysteria2x_outbound(server_port, trusted.read_text())])
    profile = pin_route(json.loads((out / "singbox.json").read_text(encoding="utf-8")), "", client_port)
    spawn(procs, [SING_BOX, "run", "-c", singbox_server_hysteria2(other_dir, server_port, other_cert, other_key)], tmp_path)
    time.sleep(2)
    spawn(procs, [SING_BOX, "run", "-c", write_json(tmp_path / "sb_client.json", profile)], tmp_path)
    wait_port(client_port)
    try:
        body = fetch_through(client_port, target)
    except requests.RequestException:
        body = b""
    assert body != BODY
    client_log = (tmp_path / "proc-1.log").read_text(encoding="utf-8", errors="replace")
    assert "unknown authority" in client_log


@need_singbox
@need_hiddify
def test_hiddify_parsed_hysteria2_link_connects(tmp_path, procs, target):
    server_port, client_port = free_port(), free_port()
    cert, key = make_cert(tmp_path, "api.push.apple.com")
    out = generate(tmp_path, [hysteria2x_outbound(server_port, cert.read_text())])
    spawn(procs, [SING_BOX, "run", "-c", singbox_server_hysteria2(tmp_path, server_port, cert, key)], tmp_path)
    time.sleep(2)
    config = hiddify_singbox_client_from_links(tmp_path, out / "sub.txt", client_port)
    spawn(procs, [SING_BOX, "run", "-c", config], tmp_path)
    wait_port(client_port)
    assert fetch_through(client_port, target) == BODY


@need_hiddify
def test_hiddify_keeps_every_generated_outbound_and_builds_its_own_inbounds(tmp_path):
    cert, _ = make_cert(tmp_path, "api.push.apple.com")
    out = generate(
        tmp_path,
        [ss_outbound(8388), reality_outbound(443, "A" * 43), hysteria2x_outbound(8443, cert.read_text())],
    )
    source = json.loads((out / "singbox.json").read_text(encoding="utf-8"))
    built = tmp_path / "hiddify_built.json"
    subprocess.run(
        [HIDDIFY, "build", "-c", str(out / "singbox.json"), "-o", str(built)],
        check=True,
        capture_output=True,
        env=hiddify_env(),
        cwd=str(tmp_path),
        timeout=60,
    )
    result = json.loads(built.read_text(encoding="utf-8"))
    wanted = {o["tag"]: o for o in source["outbounds"] if o["type"] in ("shadowsocks", "vless", "hysteria2")}
    kept = {o["tag"]: o for o in result["outbounds"] if o["tag"] in wanted}
    assert kept == wanted
    assert "tun-in" not in [i.get("tag") for i in result["inbounds"]]


@need_singbox
def test_tun_profile_passes_singbox_check_with_hysteria2_and_all_protocols(tmp_path):
    cert, _ = make_cert(tmp_path, "api.push.apple.com")
    out = generate(
        tmp_path,
        [ss_outbound(8388), reality_outbound(443, "A" * 43), hysteria2x_outbound(8443, cert.read_text())],
    )
    profile = json.loads((out / "singbox.json").read_text(encoding="utf-8"))
    assert any(i["type"] == "tun" for i in profile["inbounds"])
    result = subprocess.run([SING_BOX, "check", "-c", str(out / "singbox.json")], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


def xray_client_from_generated(out, tmp_path, listen_port):
    config = json.loads((out / "xray.json").read_text(encoding="utf-8"))
    first = next(o["tag"] for o in config["outbounds"] if o["tag"].startswith("lantern-"))
    config["inbounds"] = [{"tag": "http-in", "listen": "127.0.0.1", "port": listen_port, "protocol": "http"}]
    config["routing"] = {"rules": [{"type": "field", "network": "tcp,udp", "outboundTag": first}]}
    config.pop("observatory", None)
    return write_json(tmp_path / "xray_generated_client.json", config)


@need_xray
@need_geo
def test_xray_accepts_the_generated_config_unchanged(tmp_path):
    cert, _ = make_cert(tmp_path, "api.push.apple.com")
    out = generate(
        tmp_path,
        [ss_outbound(8388), reality_outbound(443, "A" * 43), hysteria2x_outbound(8443, cert.read_text())],
    )
    env = dict(os.environ, XRAY_LOCATION_ASSET=GEO_ASSETS)
    result = subprocess.run(
        [XRAY, "run", "-test", "-c", str(out / "xray.json")], capture_output=True, text=True, env=env
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "Configuration OK" in result.stdout


@need_xray
def test_generated_xray_config_connects_ss2022(tmp_path, procs, target):
    server_port, client_port = free_port(), free_port()
    out = generate(tmp_path, [ss_outbound(server_port)])
    spawn(procs, [XRAY, "run", "-c", xray_server_ss(tmp_path, server_port)], tmp_path)
    wait_port(server_port)
    spawn(procs, [XRAY, "run", "-c", xray_client_from_generated(out, tmp_path, client_port)], tmp_path)
    wait_port(client_port)
    assert fetch_through(client_port, target) == BODY


@need_xray
def test_generated_xray_config_connects_vless_reality_vision(tmp_path, procs, target, tls_dest):
    server_port, client_port = free_port(), free_port()
    private, public = x25519()
    out = generate(tmp_path, [reality_outbound(server_port, public)])
    spawn(procs, [XRAY, "run", "-c", xray_server_reality(tmp_path, server_port, tls_dest, private)], tmp_path)
    wait_port(server_port)
    spawn(procs, [XRAY, "run", "-c", xray_client_from_generated(out, tmp_path, client_port)], tmp_path)
    wait_port(client_port)
    assert fetch_through(client_port, target) == BODY


@need_xray
@need_singbox
def test_generated_xray_config_connects_to_stock_hysteria2_server_with_noise(tmp_path, procs, target):
    server_port, client_port = free_port(), free_port()
    cert, key = make_cert(tmp_path, "api.push.apple.com")
    out = generate(tmp_path, [hysteria2x_outbound(server_port, cert.read_text())])
    config = json.loads((out / "xray.json").read_text(encoding="utf-8"))
    stream = config["outbounds"][0]["streamSettings"]
    assert stream["finalmask"]["udp"][0]["type"] == "noise"
    spawn(procs, [SING_BOX, "run", "-c", singbox_server_hysteria2(tmp_path, server_port, cert, key)], tmp_path)
    time.sleep(2)
    spawn(procs, [XRAY, "run", "-c", xray_client_from_generated(out, tmp_path, client_port)], tmp_path)
    wait_port(client_port)
    assert fetch_through(client_port, target) == BODY


@need_xray
@need_singbox
def test_generated_xray_config_rejects_a_server_with_another_certificate(tmp_path, procs, target):
    server_port, client_port = free_port(), free_port()
    trusted, _ = make_cert(tmp_path, "api.push.apple.com")
    other_dir = tmp_path / "other"
    other_dir.mkdir()
    other_cert, other_key = make_cert(other_dir, "api.push.apple.com")
    out = generate(tmp_path, [hysteria2x_outbound(server_port, trusted.read_text())])
    spawn(procs, [SING_BOX, "run", "-c", singbox_server_hysteria2(other_dir, server_port, other_cert, other_key)], tmp_path)
    time.sleep(2)
    spawn(procs, [XRAY, "run", "-c", xray_client_from_generated(out, tmp_path, client_port)], tmp_path)
    wait_port(client_port)
    try:
        body = fetch_through(client_port, target)
    except requests.RequestException:
        body = b""
    assert body != BODY


@need_xray
def test_generated_xray_hysteria2_sends_a_short_junk_datagram_before_the_quic_initial(tmp_path, procs, target):
    listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listener.bind(("127.0.0.1", 0))
    listener.settimeout(0.5)
    server_port = listener.getsockname()[1]
    client_port = free_port()
    cert, _ = make_cert(tmp_path, "api.push.apple.com")
    out = generate(tmp_path, [hysteria2x_outbound(server_port, cert.read_text())])
    spawn(procs, [XRAY, "run", "-c", xray_client_from_generated(out, tmp_path, client_port)], tmp_path)
    wait_port(client_port)
    trigger = threading.Thread(target=lambda: _quiet_fetch(client_port, target), daemon=True)
    trigger.start()
    sizes = []
    deadline = time.time() + 6
    while time.time() < deadline and len(sizes) < 3:
        try:
            data, _ = listener.recvfrom(65535)
        except socket.timeout:
            continue
        sizes.append(len(data))
    listener.close()
    assert sizes, "no UDP datagram reached the listener"
    assert 8 <= sizes[0] <= 64
    assert any(size >= 1200 for size in sizes[1:])


def _quiet_fetch(port, url):
    try:
        requests.get(url, proxies={"http": "http://127.0.0.1:%d" % port}, timeout=5)
    except requests.RequestException:
        pass


def can_reach(host, port=443):
    try:
        with socket.create_connection((host, port), timeout=5):
            return True
    except OSError:
        return False


@need_singbox
@pytest.mark.skipif(not can_reach("raw.githubusercontent.com"), reason="rule set host is not reachable")
def test_full_singbox_profile_starts_downloads_rule_sets_and_keeps_private_traffic_direct(tmp_path, procs, target):
    client_port = free_port()
    cert, _ = make_cert(tmp_path, "api.push.apple.com")
    out = generate(
        tmp_path,
        [ss_outbound(8388), reality_outbound(443, "A" * 43), hysteria2x_outbound(8443, cert.read_text())],
    )
    profile = json.loads((out / "singbox.json").read_text(encoding="utf-8"))
    profile["log"] = {"level": "info"}
    profile["inbounds"] = [
        {"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": client_port}
    ]
    spawn(procs, [SING_BOX, "run", "-c", write_json(tmp_path / "sb_full.json", profile)], tmp_path)
    wait_port(client_port, timeout=60)
    assert fetch_through(client_port, target) == BODY
    deadline = time.time() + 30
    log_path = tmp_path / "proc-0.log"
    text = ""
    while time.time() < deadline:
        text = log_path.read_text(encoding="utf-8", errors="replace")
        if "geosite-ir" in text and "geoip-ir" in text:
            break
        time.sleep(1)
    assert "FATAL" not in text
    assert (tmp_path / "cache.db").exists()


@need_xray
@need_geo
def test_full_xray_config_loads_with_geo_assets_and_keeps_private_traffic_direct(tmp_path, procs, target):
    http_port, socks_port = free_port(), free_port()
    cert, _ = make_cert(tmp_path, "api.push.apple.com")
    out = generate(
        tmp_path,
        [ss_outbound(8388), reality_outbound(443, "A" * 43), hysteria2x_outbound(8443, cert.read_text())],
    )
    config = json.loads((out / "xray.json").read_text(encoding="utf-8"))
    config["inbounds"][0]["port"] = socks_port
    config["inbounds"][1]["port"] = http_port
    path = write_json(tmp_path / "xray_full.json", config)
    env = dict(os.environ, XRAY_LOCATION_ASSET=GEO_ASSETS)
    check = subprocess.run([XRAY, "run", "-test", "-c", path], capture_output=True, text=True, env=env)
    assert check.returncode == 0, check.stdout + check.stderr
    spawn(procs, [XRAY, "run", "-c", path], tmp_path, env=env)
    wait_port(http_port)
    assert fetch_through(http_port, target) == BODY


@need_hiddify
def test_hiddify_ignores_the_certificate_pin_which_is_why_hysteria2_links_are_opt_in(tmp_path):
    cert, _ = make_cert(tmp_path, "api.push.apple.com")
    out = generate(tmp_path, [hysteria2x_outbound(8443, cert.read_text())])
    link = (out / "sub.txt").read_text(encoding="utf-8")
    assert "pinSHA256=" in link and "insecure=1" in link
    parsed = tmp_path / "hiddify_parsed.json"
    subprocess.run(
        [HIDDIFY, "parse", str(out / "sub.txt"), "-o", str(parsed)],
        check=True,
        capture_output=True,
        env=hiddify_env(),
        cwd=str(tmp_path),
        timeout=60,
    )
    outbound = json.loads(parsed.read_text(encoding="utf-8"))["outbounds"][0]
    assert outbound["tls"]["insecure"] is True
    assert "certificate" not in outbound["tls"]
    assert not any("pin" in key.lower() or "sha256" in key.lower() for key in outbound["tls"])


@need_xray
@need_singbox
def test_generated_xray_hysteria2_without_the_junk_flag_sends_no_noise_datagram(tmp_path, procs, target):
    listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listener.bind(("127.0.0.1", 0))
    listener.settimeout(0.5)
    server_port = listener.getsockname()[1]
    client_port = free_port()
    cert, _ = make_cert(tmp_path, "api.push.apple.com")
    outbound = hysteria2x_outbound(server_port, cert.read_text())
    outbound["pre_initial_junk"] = False
    out = generate(tmp_path, [outbound])
    config = json.loads((out / "xray.json").read_text(encoding="utf-8"))
    assert "finalmask" not in config["outbounds"][0]["streamSettings"]
    spawn(procs, [XRAY, "run", "-c", xray_client_from_generated(out, tmp_path, client_port)], tmp_path)
    wait_port(client_port)
    trigger = threading.Thread(target=lambda: _quiet_fetch(client_port, target), daemon=True)
    trigger.start()
    sizes = []
    deadline = time.time() + 5
    while time.time() < deadline and len(sizes) < 2:
        try:
            data, _ = listener.recvfrom(65535)
        except socket.timeout:
            continue
        sizes.append(len(data))
    listener.close()
    assert sizes and sizes[0] >= 1200


VLESS_UUID = "11111111-2222-4333-8444-555555555555"


def plain_vless(port, **changes):
    base = {"type": "vless", "tag": "plain", "server": "127.0.0.1", "server_port": port, "uuid": VLESS_UUID}
    base.update(changes)
    return base


def xray_version(binary_path):
    text = subprocess.run([binary_path, "version"], capture_output=True, text=True, check=True).stdout
    return re.search(r"Xray (\d+\.\d+\.\d+)", text).group(1)


def xray_server_plain_vless(tmp_path, port):
    config = {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "listen": "127.0.0.1",
                "port": port,
                "protocol": "vless",
                "settings": {"clients": [{"id": VLESS_UUID}], "decryption": "none"},
            }
        ],
        "outbounds": [XRAY_FREEDOM],
    }
    return write_json(tmp_path / "xray_server_plain_vless.json", config)


SHAPES_WITH_SNI = {"tls-sni", "tls-sni-fp-xudp", "reality-sni", "reality-sni-xudp"}

VLESS_SHAPES = {
    "no-tls": plain_vless(8443),
    "no-tls-xudp": plain_vless(8443, packet_encoding="xudp"),
    "tls-sni": plain_vless(8443, tls={"enabled": True, "server_name": "a.example.com"}),
    "tls-no-sni": plain_vless(8443, tls={"enabled": True}),
    "tls-fp-no-sni": plain_vless(8443, tls={"enabled": True, "utls": {"enabled": True, "fingerprint": "chrome"}}),
    "tls-sni-fp-xudp": plain_vless(
        8443,
        packet_encoding="xudp",
        tls={"enabled": True, "server_name": "a.example.com", "utls": {"enabled": True, "fingerprint": "chrome"}},
    ),
    "reality-sni": plain_vless(
        8443,
        flow="xtls-rprx-vision",
        tls={
            "enabled": True,
            "server_name": "a.example.com",
            "utls": {"enabled": True, "fingerprint": "chrome"},
            "reality": {"enabled": True, "public_key": "A" * 43, "short_id": "0011"},
        },
    ),
    "reality-sni-xudp": plain_vless(
        8443,
        flow="xtls-rprx-vision",
        packet_encoding="xudp",
        tls={
            "enabled": True,
            "server_name": "a.example.com",
            "utls": {"enabled": True, "fingerprint": "chrome"},
            "reality": {"enabled": True, "public_key": "A" * 43},
        },
    ),
}


@need_xray
@need_geo
@pytest.mark.parametrize("shape", sorted(VLESS_SHAPES))
def test_real_xray_loads_every_vless_shape_from_the_generated_config(tmp_path, shape):
    out = generate(tmp_path, [VLESS_SHAPES[shape]])
    env = dict(os.environ, XRAY_LOCATION_ASSET=GEO_ASSETS)
    result = subprocess.run(
        [XRAY, "run", "-test", "-c", str(out / "xray.json")], capture_output=True, text=True, env=env
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "Configuration OK" in result.stdout


@need_singbox
@pytest.mark.parametrize("shape", sorted(VLESS_SHAPES))
def test_real_singbox_checks_every_vless_shape_from_the_generated_profile(tmp_path, shape):
    out = generate(tmp_path, [VLESS_SHAPES[shape]])
    result = subprocess.run([SING_BOX, "check", "-c", str(out / "singbox.json")], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    profile = json.loads((out / "singbox.json").read_text(encoding="utf-8"))
    vless_out = next(o for o in profile["outbounds"] if o["type"] == "vless")
    assert ("packet_encoding" in vless_out) is ("xudp" in shape)
    assert ("server_name" in vless_out.get("tls", {})) is (shape in SHAPES_WITH_SNI)


@need_xray
def test_real_xray_silently_accepts_an_invented_vless_field_so_none_is_ever_added(tmp_path):
    config = {
        "log": {"loglevel": "warning"},
        "inbounds": [{"listen": "127.0.0.1", "port": free_port(), "protocol": "http"}],
        "outbounds": [
            {
                "tag": "p",
                "protocol": "vless",
                "settings": {
                    "address": "127.0.0.1",
                    "port": 8443,
                    "id": VLESS_UUID,
                    "encryption": "none",
                    "packetEncoding": "xudp",
                    "definitelyNotAField": True,
                },
                "streamSettings": {"network": "raw"},
            }
        ],
    }
    result = subprocess.run([XRAY, "run", "-test", "-c", write_json(tmp_path / "bogus.json", config)], capture_output=True, text=True)
    assert result.returncode == 0 and "Configuration OK" in result.stdout


@need_xray
def test_real_xray_plaintext_vless_rule_matches_what_the_extractor_enforces(tmp_path):
    version = xray_version(XRAY)

    def loads(address):
        config = {
            "log": {"loglevel": "warning"},
            "inbounds": [{"listen": "127.0.0.1", "port": free_port(), "protocol": "http"}],
            "outbounds": [
                {
                    "tag": "p",
                    "protocol": "vless",
                    "settings": {"address": address, "port": 443, "id": VLESS_UUID, "encryption": "none"},
                    "streamSettings": {"network": "raw"},
                }
            ],
        }
        result = subprocess.run(
            [XRAY, "run", "-test", "-c", write_json(tmp_path / ("p-%s.json" % address), config)],
            capture_output=True,
            text=True,
        )
        return result.returncode == 0

    assert loads("10.0.0.2") and loads("127.0.0.1")
    public_loads = loads("8.8.8.8")
    expected = {"26.3.23": True, "26.11.9": False}
    assert public_loads == expected.get(version, public_loads)


@need_xray
def test_generated_xray_config_connects_plain_vless_to_a_real_xray_server(tmp_path, procs, target):
    server_port, client_port = free_port(), free_port()
    out = generate(tmp_path, [plain_vless(server_port)])
    spawn(procs, [XRAY, "run", "-c", xray_server_plain_vless(tmp_path, server_port)], tmp_path)
    wait_port(server_port)
    spawn(procs, [XRAY, "run", "-c", xray_client_from_generated(out, tmp_path, client_port)], tmp_path)
    wait_port(client_port)
    assert fetch_through(client_port, target) == BODY


@need_xray
def test_generated_xray_config_connects_plain_vless_with_xudp_in_the_source_just_the_same(tmp_path, procs, target):
    server_port, client_port = free_port(), free_port()
    out = generate(tmp_path, [plain_vless(server_port, packet_encoding="xudp")])
    assert "xudp" not in (out / "xray.json").read_text(encoding="utf-8").lower()
    spawn(procs, [XRAY, "run", "-c", xray_server_plain_vless(tmp_path, server_port)], tmp_path)
    wait_port(server_port)
    spawn(procs, [XRAY, "run", "-c", xray_client_from_generated(out, tmp_path, client_port)], tmp_path)
    wait_port(client_port)
    assert fetch_through(client_port, target) == BODY


@need_xray
@need_singbox
@pytest.mark.parametrize("encoding", [None, "xudp"])
def test_generated_singbox_profile_connects_plain_vless_with_and_without_packet_encoding(tmp_path, procs, target, encoding):
    server_port, client_port = free_port(), free_port()
    changes = {"packet_encoding": encoding} if encoding else {}
    out = generate(tmp_path, [plain_vless(server_port, **changes)])
    profile = pin_route(json.loads((out / "singbox.json").read_text(encoding="utf-8")), "", client_port)
    assert ("packet_encoding" in next(o for o in profile["outbounds"] if o["type"] == "vless")) is bool(encoding)
    spawn(procs, [XRAY, "run", "-c", xray_server_plain_vless(tmp_path, server_port)], tmp_path)
    wait_port(server_port)
    spawn(procs, [SING_BOX, "run", "-c", write_json(tmp_path / "sb_client.json", profile)], tmp_path)
    wait_port(client_port)
    assert fetch_through(client_port, target) == BODY


@need_hiddify
@pytest.mark.parametrize("encoding", [None, "xudp"])
def test_hiddify_applies_xudp_to_a_vless_link_with_or_without_the_parameter(tmp_path, encoding):
    changes = {"packet_encoding": encoding} if encoding else {}
    out = generate(tmp_path, [plain_vless(8443, **changes)])
    link = (out / "sub.txt").read_text(encoding="utf-8")
    assert ("packetEncoding=xudp" in link) is bool(encoding)
    parsed = tmp_path / "hiddify_pe.json"
    subprocess.run(
        [HIDDIFY, "parse", str(out / "sub.txt"), "-o", str(parsed)],
        check=True,
        capture_output=True,
        env=hiddify_env(),
        cwd=str(tmp_path),
        timeout=60,
    )
    outbound = json.loads(parsed.read_text(encoding="utf-8"))["outbounds"][0]
    assert outbound.get("packet_encoding") == "xudp"
