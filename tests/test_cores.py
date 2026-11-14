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
            "/user-create": lambda n: FakeResponse(200, {"userId": 1, "token": "t"}),
            "/config-new": lambda n: FakeResponse(200, response),
        }
    )
    out = tmp_path / "sub"
    run(LanternClient(session=session), tmp_path / "state.json", out)
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
    target_tag = next(o["tag"] for o in profile["outbounds"] if o["type"] in ("shadowsocks", "vless"))
    profile["route"]["final"] = target_tag
    profile["inbounds"][0]["listen_port"] = listen_port
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


@need_singbox
def test_singbox_check_accepts_generated_profile(tmp_path):
    out = generate(tmp_path, [ss_outbound(8388), reality_outbound(443, "A" * 43)])
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
    reason="observed: sing-box 1.14.4 client is rejected by an Xray 26.11.9 Reality server; the same outbound works with a sing-box server and through an Xray client",
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
