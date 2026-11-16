# proxy

Small helpers for running [sing-box](https://sing-box.sagernet.org/) on macOS or Linux from a VLESS/VMess/Trojan/Shadowsocks/Hysteria2 subscription.

| Script      | What it does                                                                 |
| ----------- | ---------------------------------------------------------------------------- |
| `sb-gen.py` | Turns a subscription (URL or local file) into a sing-box `config.json`.     |
| `sbx`       | Lists, tests and switches servers of a running sing-box via its Clash API. |

## Requirements

- sing-box 1.12+ (uses the new DNS server format and rule actions; tested on 1.14):
  - macOS: `brew install sing-box`
  - Linux: your distro's package or the [official install guide](https://sing-box.sagernet.org/installation/package-manager/)
- `python3` (stdlib only) for `sb-gen.py`
- `bash`, `curl`, `jq` for `sbx`
- The GeoIP rule set for your `--country` (default `ru`) at `/etc/sing-box/geoip-<code>.srs`. Not needed with `--country none`.

  ```sh
  sudo mkdir -p /etc/sing-box
  sudo curl -L -o /etc/sing-box/geoip-ru.srs https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-ru.srs
  ```

  For another country, replace `ru` with its code in both places. `sb-gen` warns and prints this command if the file is missing.

## Install

Symlink the scripts into a directory on your `PATH` (here `~/.local/bin`), so edits in the repo take effect right away:

```sh
mkdir -p ~/.local/bin
ln -s "$PWD/sb-gen.py" ~/.local/bin/sb-gen
ln -s "$PWD/sbx"       ~/.local/bin/sbx
chmod +x sb-gen.py sbx
```

Make sure `~/.local/bin` is on your `PATH` (e.g. in `~/.zshrc` or `~/.bashrc`):

```sh
export PATH="$HOME/.local/bin:$PATH"
```

## Usage

### 1. Generate a config

```sh
sb-gen 'https://SUBSCRIPTION/plain/config/' > config.json
```

The subscription can be a URL or a local file, plain or base64-encoded, one share link per line. Unsupported links are skipped with a `skip:` note on stderr.

Modes:

- `--mode tun` (default): a TUN interface captures all traffic, plus a local proxy on `127.0.0.1:2080`. Needs `sudo`.
- `--mode proxy`: no TUN, only the local proxy on `127.0.0.1:2080`, set as the system proxy while sing-box runs (macOS network settings; on Linux, the GNOME or KDE proxy setting, so it has no effect on a headless machine). Add `--no-system-proxy` to skip that. Runs without `sudo`.

Filtering (case-insensitive regex, matched against `"<tag> <server>"`, e.g. `vless | PL / VLESS (WS+TLS) #2 pl-globalcdn1.example.org`):

```sh
sb-gen --include 'cdn|PL /' --exclude 'hysteria2' 'https://SUBSCRIPTION/...' > config.json
```

`--exclude` is applied after `--include`.

Direct routing (local sites bypass the proxy):

- `--country ru` (default): `.ru` / `.рф` domains and Russian IPs go direct.
- `--country de`: any two-letter code. That country's TLD and GeoIP go direct. Extra TLDs are included for a few countries (`by`, `ua`, `kz`, `rs` IDN domains; `.uk` for `gb`).
- `--country none`: everything except private IPs goes through the proxy.

Other options:

- `--cache PATH`: cache file location. Defaults to `/etc/sing-box/cache.db` for `tun` and `~/.cache/sing-box/cache.db` for `proxy`.

### 2. Run sing-box

```sh
sing-box check -c config.json

# TUN mode
sudo sing-box run -c config.json

# proxy mode
sing-box run -c config.json
```

### 3. Manage servers with `sbx`

```sh
sbx ls           # test all servers in parallel, sorted by latency
sbx use <name>   # switch server: exact name first, then substring match
sbx use auto     # go back to automatic selection (fastest server)
sbx now          # show the current server (and what "auto" picked)
```

`sbx ls` writes progress to stderr and the sorted table to stdout, so `sbx ls 2>/dev/null | head` gives just the top results.

Environment variables:

| Variable           | Default                 | Meaning                                    |
| ------------------ | ----------------------- | ------------------------------------------ |
| `SBX_API`          | `http://127.0.0.1:9090` | Clash API address                          |
| `JOBS`             | `16`                    | servers tested in parallel                 |
| `DELAY_TIMEOUT_MS` | `15000`                 | per-server test timeout                    |
| `CURL_MAX`         | timeout + 2s            | seconds curl waits for one test            |
| `RETRIES`          | `1`                     | extra passes over servers that came back dead |

```sh
JOBS=32 DELAY_TIMEOUT_MS=5000 RETRIES=0 sbx ls
```

## What the generated config does

- Selector `proxy` (default `auto`) over all servers. `auto` is a `urltest` group that rechecks every 3 minutes against `gstatic.com/generate_204` with 100 ms tolerance.
- Direct routing for private IPs and the `--country` domains and GeoIP (by default `.ru` / `.рф` and RU IPs). Everything else goes through `proxy`.
- DNS over HTTPS to `1.1.1.1` through the proxy, local DNS for the `--country` domains. IPv4 only.
- Clash API on `127.0.0.1:9090` (used by `sbx`), with the selected server persisted in the cache file.
