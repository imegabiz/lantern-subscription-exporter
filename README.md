# Lantern Subscription Exporter

A small Python job that asks the Lantern config service for its free proxy list, keeps only the proxies that standard clients can use, and publishes them from a GitHub repository. It runs on GitHub Actions once an hour and commits only when something changed.

## What it publishes

| File | Content | Use it in |
| --- | --- | --- |
| `subscription/sub.txt` | One share link per line: `ss://` and `vless://` (see the Hysteria2 note below) | v2rayNG, NekoBox, Streisand and other link based clients; Hiddify for Shadowsocks and VLESS |
| `subscription/singbox.json` | Complete sing-box client profile: TUN inbound, DNS, routing, a selector and an automatic latency group, with Shadowsocks, VLESS and Hysteria2 | Official sing-box apps (needs sing-box 1.14.0 or newer); Hiddify (JSON profile import) |
| `subscription/xray.json` | Complete Xray-core client configuration: SOCKS (10808) and HTTP (10809) inbounds, all three protocols, a latency based balancer | Xray-core and clients that accept a full Xray JSON configuration |

After setup the files are available at:

```
https://raw.githubusercontent.com/<your-user>/<your-repo>/main/subscription/sub.txt
https://raw.githubusercontent.com/<your-user>/<your-repo>/main/subscription/singbox.json
https://raw.githubusercontent.com/<your-user>/<your-repo>/main/subscription/xray.json
```

### Important: the files are public if the repository is public

The subscription files contain working connection details: server addresses, passwords and keys of the Lantern proxies. In a public repository **anyone can read them**, and the Git history keeps every older version. They are Lantern's free shared proxies, not secrets, but they are not private either. Your own Lantern account data (device id, user id and token) is never written to these files; the exporter checks every file for it before publishing.

## Minimum client versions

- Xray-core **26.3.23 or newer** for `xray.json`. Older versions either fail to load the file or fail to connect. This was found by running every Xray release between 26.1.13 and 26.3.23 against the real loopback tests; 26.3.23 is the first one that passes all of them. The latest stable release tested is 26.11.9.
- sing-box **1.14.0 or newer** for `singbox.json`: its rule sets use the `http_client` option, which the sing-box documentation marks as new in 1.14.0. Tested with 1.14.4; older versions were not tested.
- The files `geoip.dat` and `geosite.dat` must be available to Xray for `xray.json`, because the routing uses the standard `geosite:category-ir` and `geoip:ir` tags. v2rayNG ships them. Bare Xray-core without them refuses to load the file.
- `singbox.json` downloads two rule sets from `raw.githubusercontent.com` on its first start and caches them. If that host is unreachable at the very first start, sing-box refuses to start. The subscription itself comes from the same host.

## Naming

- `xray.json`: `remarks` is `👽 Anonymous Lantern 🚀`, which Xray based clients show as the config name.
- `singbox.json`: the selector is `👽 Anonymous Lantern 🚀`, the automatic latency group is `👽 Anonymous Lantern 🌐`.
- `sub.txt`: every link has its own name, for example `🇩🇪 Germany · Frankfurt · SS`.
- Hiddify names a remote profile from the URL, not from the JSON. Add `#👽 Anonymous Lantern 🚀` to the end of the subscription URL there.

Iranian traffic goes direct in `singbox.json` and `xray.json`: private networks, `.ir` domains and the Iranian domain and IP lists.

## Protocols

| Protocol | In `sub.txt` | In `singbox.json` | In `xray.json` |
| --- | --- | --- | --- |
| Shadowsocks (2022 and AEAD ciphers) | yes | yes | yes |
| VLESS, TCP, Reality, `xtls-rprx-vision` | yes | yes | yes |
| Hysteria2 (from Lantern's `hysteria2x`) | **no, by default** | yes, certificate verified | yes, certificate pinned |

Lantern's own protocols such as `samizdat` cannot be used by any standard client and are skipped. Every run prints how many entries were skipped and why. Entries with options the exporter cannot express faithfully are skipped too, never silently rewritten.

### Hysteria2 versus Hysteria2x

`hysteria2x` is a stock Hysteria2 server with a client-side evasion called `pre_initial_junk`: before the QUIC handshake the client sends one random 8 to 64 byte UDP datagram, so that censors which only inspect the first packet of a UDP flow cannot read the server name. Lantern documents the value `false` as the default, and so does this project: a missing or `null` value means `false`.

| Client output | Can it send the junk datagram? |
| --- | --- |
| `xray.json` | **Yes.** When the value is `true`, the Hysteria2 outbound gets a `finalmask` UDP `noise` mask (8 to 64 bytes, resent every 30 to 60 seconds). This approximates Lantern's behaviour, which sends the datagram on each new UDP flow. When the value is `false` or missing, no mask is added. |
| `singbox.json` | **No.** Stock sing-box has no such option. The entry still works as a normal Hysteria2 connection, without the evasion. |
| Share links | **No.** The link format has no such parameter. |

So the full Hysteria2x behaviour is only available through `xray.json`. If a network blocks QUIC by server name, Hysteria2 from `singbox.json` may be unreliable.

### Certificate pinning and why Hysteria2 links are off by default

The Hysteria2 servers use a self-signed certificate. The exporter parses it, checks that it is a single valid certificate (not expired, no private key), and computes the SHA-256 fingerprint of its DER form. That is the exact format of the official Hysteria `pinSHA256` (lowercase hexadecimal), and the value Xray expects for `pinnedPeerCertSha256`. If Lantern replaces a server certificate, the next run computes the new fingerprint.

- `xray.json`: the fingerprint is pinned. A server with another certificate is rejected (tested).
- `singbox.json`: the certificate itself is embedded and used as the only trust anchor. A server with another certificate is rejected (tested).
- Share links: a link can only say `insecure=1&pinSHA256=...`. **v2rayNG applies the pin** (its source turns the insecure flag off when a pin is present). **Hiddify ignores the pin** (tested with Hiddify core 5.9.1: the imported outbound has `insecure` set and no pin), which means TLS verification is simply off for that connection and a network attacker could impersonate the server.

Because a single public `sub.txt` is used by many different clients, Hysteria2 links are **left out of `sub.txt` by default**. Hiddify users should import `singbox.json`, v2rayNG users can use `xray.json`. If you accept the risk for your audience you can turn the links on: in the repository go to **Settings → Secrets and variables → Actions → Variables → New repository variable**, name `LANTERN_HYSTERIA2_LINKS`, value `include`.

## Account state: how it is kept safe

The exporter needs a Lantern account (device id, user id, token). The state is stored in one encrypted file in the repository, `state/lantern-state.enc`.

- Algorithm: AES-256-GCM, a fresh random 12 byte nonce for every encryption, and the file format version is part of the authenticated data. The file is a small JSON envelope with `version`, `algorithm`, `nonce` and `ciphertext`; it contains no readable field.
- The key lives only in the GitHub Actions secret `LANTERN_STATE_ENCRYPTION_KEY`.
- The decrypted state exists only in memory while the job runs. It is never written to disk, Git, the Actions cache, an artifact or a log.
- The file is only rewritten when the account actually changes, so normal hourly runs do not create commits for it.
- The old Actions cache is not used any more.

Three situations are handled differently:

1. **No state file yet** (first setup): the scheduled run stops with a clear error. You start the first run by hand and choose `create` (below).
2. **Normal run**: the state is decrypted and used.
3. **Wrong key, damaged or modified state file**: the run stops with an error. **No new account is created.** Nothing is deleted. Fix the key, restore the file from Git history, or knowingly choose `recreate`.

A rejected account (HTTP 401 or 403 from Lantern) also stops the run. The exporter never creates an account on its own, because creating an account is not safe to repeat and a 403 can also mean a block rather than a bad account.

Limits of this approach, stated plainly:

- The encrypted file stays in Git history forever. If the key ever leaks, every old version of the file can be decrypted. Replace the key and use `recreate` if that happens.
- A repository with write access can read the secret through a workflow. Keep write access small.
- Secrets are not given to workflows triggered from forks, and the test workflow has no secret access at all.

## GitHub setup (step by step)

### 1. Create the encryption key

Use any computer that has Python:

```
python -m lantern_exporter --generate-key
```

(Run it inside the downloaded project folder after `python -m pip install -r requirements.txt`.) It prints one line of letters and numbers, for example `q3Zk...=`. Copy that line. Alternatives: `openssl rand -base64 32` on Linux or macOS, or on Android with Termux run `pkg install openssl` and then `openssl rand -base64 32`.

Do not share it and do not put it in the repository.

### 2. Add it as a secret

1. Open your repository on github.com.
2. Click **Settings** (the gear tab at the top of the repository).
3. In the left menu click **Secrets and variables**, then **Actions**.
4. Click the green button **New repository secret**.
5. In **Name** type exactly: `LANTERN_STATE_ENCRYPTION_KEY`
6. In **Secret** paste the line you copied.
7. Click **Add secret**.

### 3. Allow the workflow to save files

1. **Settings → Actions → General**.
2. Scroll to **Workflow permissions**.
3. Select **Read and write permissions** and click **Save**.

### 4. First start (new installation)

1. Open the **Actions** tab, click **Update Subscription** in the left list.
2. Click **Run workflow** (grey button on the right).
3. In **First setup or recovery** choose `create`.
4. Click the green **Run workflow** button.
5. Wait for the run to finish (about one minute). A green tick means success.

### 5. Moving from the old cache based version (if you used it before)

Do this instead of step 4. It keeps your existing Lantern account.

1. Run the workflow by hand as above and choose `migrate-from-cache`.
2. When it is green, check that the file `state/lantern-state.enc` now exists in the repository.
3. Delete the old caches, because they hold the account token in plain text: **Actions → Caches** (left menu, under "Management"), then click the bin icon next to every cache whose name starts with `lantern-state-`. Repeat until the list has no such entry.

The old caches are not deleted automatically, so you decide when.

### 6. How to check that everything works

- The run is green, and its log shows `usable configs:` and `files changed:`.
- The repository now contains `state/lantern-state.enc` (open it: it must look like a small JSON with `version`, `algorithm`, `nonce`, `ciphertext`, and no readable token).
- The next hourly run does not create a new `state/lantern-state.enc` commit and its log shows no line about creating an account.
- **Actions → Caches** has no `lantern-state-` entries.

### 7. Recovery

If a run fails with a message about the state:

- "wrong key or the file was changed": the secret does not match the file. Put the original key back in the secret. If it is lost, run by hand with `recreate`.
- "rejected the saved account": run by hand with `recreate`.

`recreate` creates a new account on purpose and replaces the encrypted file.

## Schedule and manual runs

The job runs every hour, at minute 23 (UTC) (`cron: "23 * * * *"`). GitHub may start a scheduled run a few minutes late, and sometimes skips one under load. The schedule is intentionally hourly; Lantern's own `poll_interval_seconds` does not change it. Runs never overlap and a running update is never cancelled by a newer one. A failed run does not trigger another run by itself.

To run by hand: **Actions → Update Subscription → Run workflow**, keep `none`, click the green button.

## What the exporter sends to Lantern

The request follows the official Lantern client (Radiance) source:

| Field | Value | Why |
| --- | --- | --- |
| App version (`X-Lantern-App-Version`) | `10.0.5` | The latest official Lantern release at the time of writing. |
| sing-box version (`singbox_version`) | `v1.14.2-lantern.3` | What the official client reports (its sing-box dependency). It is the only value known to be accepted by the server. |
| Platform | `linux` | A value the official client reports on Linux. |
| Protocols | `shadowsocks`, `vless`, `hysteria2x` | Exactly what this project can publish. The official client also sends only the protocols it supports, so the server can leave out `samizdat` and similar entries. |
| Capabilities | none | The project implements none of them. |

**Client country versus preferred location.** These are different things in Lantern. `preferred_location` is the exit country a user picks inside the app; this project **never sends it**. The project only sends the header `X-Lantern-Client-Country: IR`, which tells the server that the client is in Iran. In the official client that header exists as a developer override; it is not a documented production feature. The server has accepted it so far (its answers report country `IR`), but that can change. Set `LANTERN_COUNTRY` to an empty value to stop sending it.

If Lantern publishes new app versions, the values above can be changed with `LANTERN_APP_VERSION` and `LANTERN_SINGBOX_VERSION`.

## Retries and failure behaviour

- Account creation (`/user-create`) is **never retried**. A repeated request could create a second account if the first one succeeded but its answer was lost.
- Fetching the config (`/config-new`) is a read-only request in the official client and is retried up to 3 times in total, with growing waits (about 5 s, 10 s plus a random part), never back to back.
- For HTTP 429 and 503 the `Retry-After` header is respected. If it asks for more than 120 seconds the run stops instead of waiting.
- Nothing sensitive is logged.
- If anything fails, the three published files stay exactly as they were. The three files are written together: all are staged first, then replaced, and an earlier replacement is rolled back if a later one fails.
- The number of configs has a safety ceiling of 1000. Above it nothing is published (no silent truncation). Counts of extracted, duplicate, invalid, unsupported and ignored entries are printed on every run and add up exactly to the total.

## Duplicate detection

Two configs are duplicates only when everything that affects the connection is identical: for Shadowsocks the server, port, password and cipher; for VLESS the UUID, server, port, flow, network, packet encoding, server name, uTLS fingerprint, Reality public key and short id; for Hysteria2 the server, port, password, server name, certificate fingerprint and `pre_initial_junk`. Only formatting differences (letter case of host names, UUIDs and hexadecimal values, IPv6 notation, certificate line breaks) are ignored. A difference in any real parameter keeps both. A config that is really identical may stay in rare cases; a different one is never dropped for being similar.

## Configuration

Optional environment variables or flags.

| Variable | Flag | Default | Meaning |
| --- | --- | --- | --- |
| `LANTERN_STATE_ENCRYPTION_KEY` | none | none (required) | Base64 key, 32 bytes. Only as a secret. |
| `LANTERN_BOOTSTRAP` | `--bootstrap` | `none` | `none`, `create`, `recreate`, `migrate` |
| `LANTERN_HYSTERIA2_LINKS` | `--hysteria2-links` | `omit` | `include` adds Hysteria2 to `sub.txt` |
| `LANTERN_COUNTRY` | `--country` | `IR` | Client country header, empty disables it |
| `LANTERN_MIN_CONFIGS` | `--min-configs` | `1` | Minimum usable configs required to publish |
| `LANTERN_APP_VERSION` | `--app-version` | `10.0.5` | App version reported to Lantern |
| `LANTERN_SINGBOX_VERSION` | `--singbox-version` | `v1.14.2-lantern.3` | sing-box version reported to Lantern |
| `LANTERN_OUTPUT_DIR` | `--output-dir` | `subscription` | Output directory |
| `LANTERN_STATE_FILE` | `--state-file` | `state/lantern-state.enc` | Encrypted state file |

## Tests

```
python -m pip install -r requirements-dev.txt
python -m pytest -q
```

The offline tests need no network and no Lantern account. They cover the state encryption, wrong keys and tampering, deduplication, certificates, retry rules, atomic writes and the workflow security rules.

Tests that use real cores (Xray, sing-box, Hiddify core) are skipped when the binaries are missing, and they print why. In GitHub Actions the **Tests** workflow downloads pinned, checksum verified versions listed in `tools/cores.lock.json` (Xray 26.3.23 and 26.11.9, sing-box 1.14.4, Hiddify core 5.9.1, and the v2fly geo files) and runs everything, including loopback tests where real servers and clients exchange traffic. To do the same locally:

```
python tools/fetch_cores.py --xray v26.3.23
```

then export the printed `XRAY_BIN`, `SING_BOX_BIN`, `HIDDIFY_BIN` and `XRAY_ASSET_DIR` variables and run the tests. One test is marked as an expected failure: with Xray 26.11.9 as the server, the sing-box 1.14.4 client is rejected by its Reality server, while Xray 26.3.23 accepts it.

## Limitations

- Lantern decides which protocol types a request receives and changes them between requests. A run can contain no usable type at all. That run fails and the previous files stay in place.
- Lantern hands out proxies per client and network location and rotates them. Entries can stop working or change at any time, and an entry that works on one network may not work on another.
- A public subscription sends many users to the same few servers.
- The project depends on an unofficial use of Lantern's service endpoints and can stop working if Lantern changes them.

## License

MIT
