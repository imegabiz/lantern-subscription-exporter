# Lantern Subscription Exporter

A small Python job that asks the Lantern config service for the free proxy list, keeps only the proxies that standard clients can use, and publishes them as subscription files from a GitHub repository. It runs on GitHub Actions every hour and commits only when the result actually changed.

## Output

| File | Content | Use in |
| --- | --- | --- |
| `subscription/sub.txt` | One share link per line (`ss://`, `vless://`) | v2rayNG, Hiddify, NekoBox, Streisand and other link-based clients |
| `subscription/singbox.json` | Complete sing-box client profile: TUN inbound, DNS, routing rules, a selector and an automatic latency test group | Official sing-box apps (Android, iOS, desktop), Hiddify (JSON profile import) |

| `subscription/xray.json` | Complete Xray-core client configuration: SOCKS (10808) and HTTP (10809) inbounds, all proxies, a latency-based balancer | Xray-core and clients that accept a full Xray JSON configuration |

After setup, the subscription URLs are:

```
https://raw.githubusercontent.com/<your-user>/<your-repo>/main/subscription/sub.txt
https://raw.githubusercontent.com/<your-user>/<your-repo>/main/subscription/singbox.json
https://raw.githubusercontent.com/<your-user>/<your-repo>/main/subscription/xray.json
```

Hiddify reads only the proxy entries from `singbox.json` and builds its own inbounds, DNS and routing, so the extra sections do not affect it. The official sing-box apps need the TUN inbound to start the VPN.

## Naming and routing

The configs carry the same naming scheme as the TCB project:

- `xray.json`: `remarks` is `👽 Anonymous Lantern 🚀`, which Xray based clients show as the config name.
- `singbox.json`: the selector is `👽 Anonymous Lantern 🚀` and the automatic latency group is `👽 Anonymous Lantern 🌐`.
- `sub.txt`: every link has its own name, for example `🇩🇪 Germany · Frankfurt · SS`.

Clients that name a remote subscription from the URL or from HTTP headers (Hiddify uses `Profile-Title`, the file name or the URL fragment) cannot read the name from the JSON itself. Add `#👽 Anonymous Lantern 🚀` to the end of the subscription URL there.

Iranian traffic goes direct in `singbox.json` and `xray.json`, as in TCB: private networks, `.ir` domains, `geosite-ir` and `geoip-ir`.

- `singbox.json` downloads two rule sets from `raw.githubusercontent.com` (the same host that serves the subscription) on the first start and caches them. If that host is unreachable at the very first start, sing-box refuses to start.
- `xray.json` uses the standard `geosite:category-ir` and `geoip:ir` tags. The client needs the usual `geoip.dat` and `geosite.dat` files. Bare Xray-core without them refuses to load the config.

## What is included and what is not

Lantern serves several proxy protocols. Only the ones that mainstream clients understand are exported:

- Shadowsocks (including the 2022 ciphers)
- VLESS with TCP, Reality and `xtls-rprx-vision`
- Hysteria2, from Lantern's `hysteria2x` entries

`hysteria2x` is stock Hysteria2 plus a client-side evasion (`pre_initial_junk`). Lantern documents it as a drop-in client for an unmodified Hysteria2 server, so the exporter publishes it as a normal `hysteria2` entry without the evasion. The server certificate is self-signed. In `singbox.json` the certificate is embedded and verified. Share links cannot carry a certificate, so they use `insecure=1` together with `pinSHA256`; clients that ignore the pin accept any certificate for that connection.

In `xray.json` the Hysteria2 entry pins the server certificate (`pinnedPeerCertSha256`) and uses Xray's `finalmask` UDP `noise` to send one random 8 to 64 byte datagram before the QUIC Initial. This reproduces Lantern's `pre_initial_junk` evasion, which stock sing-box and share links cannot do.

Lantern's own protocols (for example `samizdat`) cannot be used by Hiddify, v2rayNG or stock sing-box and are skipped on purpose. Every run prints how many entries were skipped and why.

An entry is also skipped when it carries options the exporter cannot express in a share link without changing its meaning. Nothing is guessed or rewritten.

## Setup

1. Create a new GitHub repository and upload all files of this project, keeping the folder layout.
2. Open **Settings → Actions → General → Workflow permissions** and make sure **Read and write permissions** is selected.
3. Open the **Actions** tab, choose **Update Subscription** and press **Run workflow**.
4. When the run is green, `subscription/sub.txt` and `subscription/singbox.json` appear in the repository.

From then on the job runs by itself every hour.

## How it works

1. A device ID and an anonymous free Lantern account are created on the first run and stored in `.state/state.json`. The GitHub Actions cache keeps this file between runs, so a new account is not created every hour. If the cache is lost, a new anonymous account is created automatically.
2. The job requests the configuration the same way the official Lantern client does (`POST /config-new`) and asks for the Iran profile.
3. The response is validated strictly. Entries that are malformed, duplicated or unsupported are dropped.
4. Share links and the sing-box profile are generated and checked again (links are decoded back and compared with the source data).
5. Files are written through temporary files and atomic renames, and only when the content differs from what is already there.

## Failure behaviour

The previous `sub.txt` and `singbox.json` are never touched unless a complete, validated replacement exists. If Lantern is unreachable, answers with an error, returns a malformed response, or yields fewer usable configs than `LANTERN_MIN_CONFIGS`, the run fails (red in the Actions tab) and the old files stay exactly as they were.

## Configuration

All settings are optional environment variables or command-line flags.

| Variable | Flag | Default | Meaning |
| --- | --- | --- | --- |
| `LANTERN_COUNTRY` | `--country` | `IR` | Country profile requested from Lantern |
| `LANTERN_MIN_CONFIGS` | `--min-configs` | `1` | Minimum usable configs required to publish |
| `LANTERN_OUTPUT_DIR` | `--output-dir` | `subscription` | Output directory |
| `LANTERN_STATE_FILE` | `--state-file` | `.state/state.json` | Account state file |
| `LANTERN_APP_VERSION` | `--app-version` | `dev` | App version reported to Lantern |
| `LANTERN_SINGBOX_VERSION` | `--singbox-version` | `1.12.0` | sing-box version reported to Lantern |

Run locally:

```
python -m pip install -r requirements.txt
python -m lantern_exporter
```

## Tests

```
python -m pip install -r requirements-dev.txt
python -m pytest -v
```

The offline suite uses recorded response shapes with fake credentials and needs no network. The integration tests in `tests/test_cores.py` are skipped unless the binaries are available. To run them, set `XRAY_BIN`, `SING_BOX_BIN` and `HIDDIFY_BIN` to the paths of Xray-core, sing-box and hiddify-core. They validate the generated files with the real cores and push traffic through local loopback servers. Set `XRAY_ASSET_DIR` to a directory containing `geoip.dat` and `geosite.dat` to include the test of the full Xray config.

## Limitations

- The server decides which protocol types a request receives and changes them between requests. A run can contain no usable type at all. That run fails and the previous files stay in place.
- Lantern hands out proxies per client and per network location and rotates them. Entries can stop working or change at any time, and an entry that works for one network may not work for another.
- A public subscription sends many users to the same few servers. Expect them to be slower or to be blocked sooner than with a personal account.
- This project depends on an unofficial use of Lantern's service endpoints and may stop working if Lantern changes them.

## License

MIT
