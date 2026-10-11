<div align="center">

<img src="assets/logo.svg?v=2" alt="Omotam" width="420">

# Omotam

**A self-hosted DNS resolver for your LAN** — custom records, a web GUI, a REST API, an MCP server, and optional control over public resolvers.

</div>

---

## What does "омотам" mean?

**омотам** is a Bulgarian verb: *"to make something into a knot; to tangle threads, wires — or networks."* It's the opposite of untangling. That felt right for a tool that ties your devices' DNS into one place you control: you re-knot where names resolve, and (optionally) knot the public resolvers into your own.

**omotam** is the tool for exactly that: it serves DNS on your network, overrides the domains you choose (A / AAAA / TXT / CNAME, wildcards, blocks), forwards everything else upstream, and can record and export the queries flowing through it.

## Features

- Custom DNS records: `A`, `AAAA`, `TXT`, `CNAME`, wildcards (`*.home.lan`), and `BLOCK` (NXDOMAIN).
- `merge` mode: add a record (e.g. a `TXT`) *without* overriding the domain's normal public records.
- Forwards any domain that isn't overridden to an upstream resolver.
- Speaks DNS over **UDP + TCP**, **IPv4 + IPv6**.
- **Web GUI** (HTTPS) at `https://dns.settings` to manage everything.
- **REST API** for automation.
- **MCP server** so assistants (e.g. opencode) can manage records as tools.
- Optional **override mode**: make public resolvers (`1.1.1.1`, `8.8.8.8`, …) answer from this server on the host machine.
- Optional **query recording**: **Start Recording** / **End Recording** in the GUI, filter by timeframe, export CSV/JSON. *(Off by default.)*
- **Self-update**: checks GitHub for new releases and sends a Windows notification, with one-click **Update now**.
- **System tray icon**: shows **Omotam on / off**, double-click opens the UI, right-click has service controls and settings.

## Install

### Windows (GUI installer)

Run the installer (it self-elevates and downloads its bundled runtime):

```powershell
powershell -ExecutionPolicy Bypass -File .\install.ps1
```

The installer, in a retro grey-and-beveled **Windows 98** style, asks you:

- **Where** to install (default `%ProgramData%\omotam`).
- Whether to run as a **background service on boot** (Scheduled Task, SYSTEM, no window).
- Whether to **register the omotam MCP** in your opencode config.
- Whether to enable **HTTPS** and trust the local CA (so `https://dns.settings` is warning-free).

It then sets up the firewall and prints the URL to open.

### Manual / any OS

omotam is pure Python 3.9+ (only extra dependency is `cryptography`, used once to mint the local TLS cert):

```bash
pip install cryptography
python dns_server.py --config dns_hosts.json
```

Run as Administrator/root so it can bind port 53. Point a device's DNS at this machine and open the GUI.

## Quick start

1. Install and let it run as a service.
2. Point a device's DNS at this machine's IP.
3. Open the GUI (default `https://dns.settings/`, or `http://127.0.0.1:8080/`).
4. Add a record: domain `myhost.lan` → `192.168.1.50`. Save. Done.
5. Test: `nslookup myhost.lan 127.0.0.1`.

## The web GUI

- Edit upstream resolver, TTL, and the resolver addresses omotam answers for.
- Add/edit/delete records with type, value and a **Passthrough** (merge) checkbox.
- Toggle **override mode**.
- Optional **DNS query recording**: pick a range (15m/1h/24h or custom), view, **Export CSV/JSON**, Clear.
- Activity log + editable notes.

## REST API

Base: `http://<host>:8080` (or `https://dns.settings`). Auth is required only if you set `gui_token`/`api_token`; pass it as `?token=`, `X-API-Token`, or `Authorization: Bearer`.

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api/status` | Port, upstream, TTL, record count, recorded count |
| GET | `/api/records` | List all records |
| GET | `/api/records/{domain}` | Get one record |
| PUT | `/api/records/{domain}` | Replace a record |
| POST | `/api/records/{domain}` | Merge/append into a record (e.g. add a TXT) |
| DELETE | `/api/records/{domain}` | Delete a record |
| POST | `/api/settings` | Set `upstream`, `ttl`, `intercept_ips`, `record_queries` |
| GET | `/api/queries?since=&until=&limit=&format=csv\|json` | Recorded queries / export |
| POST | `/api/queries/clear` | Clear the recording |
| POST | `/api/reload` | Reload config from disk |

Example:

```bash
curl -X PUT http://127.0.0.1:8080/api/records/host.lan \
  -H "Content-Type: application/json" -d '{"A":["10.0.0.5"]}'
```

## MCP (use from an AI assistant)

`dns_mcp.py` is a dependency-free stdio MCP server exposing the API as tools: `list_dns_records`, `get_dns_record`, `set_dns_record`, `add_dns_txt_record`, `delete_dns_record`, `get_dns_status`, `set_dns_targets`, `get_dns_upstream`, `reload_dns`, `get_dns_queries`, `clear_dns_recording`.

opencode config:

```json
{
  "mcp": {
    "dns": {
      "type": "local",
      "command": ["python", "C:\\ProgramData\\omotam\\dns_mcp.py"],
      "enabled": true,
      "env": { "DNS_API_URL": "http://127.0.0.1:8080" }
    }
  }
}
```

Add `"DNS_API_TOKEN": "<token>"` to `env` if you set an API token.

## Tray icon

When installed, Omotam adds an icon in the notification area (started at logon by the scheduled task `omotam-tray`):

- **Green** = running (**Omotam on**), **red** = stopped (**Omotam off**).
- **Double-click** opens the web UI.
- **Right-click** opens the menu: Open Omotam / Open control panel, Start · Restart · Stop service, and **Settings** (Start recording, End recording, Check for updates, Open config file, Open data folder), plus Exit tray.

Turn it off with `-NoTray` at install time, or delete the `omotam-tray` task.

## Updates

Omotam checks the GitHub releases feed in the background (every 6h by default, `update_check` / `update_check_hours`). When a newer version exists:

- the GUI shows an **Update available** banner with an **Update now** button, and
- your browser raises a **Windows notification** ("Omotam update available") that you can click to update.

Update now stops the service, downloads the latest release, replaces the program files (your `dns_hosts.json`, certificates and notes are kept), and restarts the service. `POST /api/update/apply` does the same programmatically.

## Configuration (`dns_hosts.json`)

| Key | Meaning |
| --- | --- |
| `upstream`, `upstream_port` | Resolver for non-overridden domains |
| `port`, `bind` | DNS listener (53, `0.0.0.0`) |
| `ttl` | TTL for custom answers |
| `gui_enabled`, `gui_bind`, `gui_port` | Web GUI (HTTP) |
| `gui_tls`, `gui_tls_port`, `gui_hostname` | HTTPS + the name it serves |
| `gui_token`, `api_token` | Require auth when set |
| `intercept_enabled`, `intercept_ips`, `intercept_upstream` | Override mode |
| `record_queries` | Record DNS requests (default **false**) |
| `update_check`, `update_check_hours` | Background update checks (default on, every 6h) |
| `records` | `domain -> "1.2.3.4"` or `{ "A": [...], "AAAA": [...], "TXT": [...], "CNAME": "...", "merge": true, "block": true }` |

## Security

- Without `gui_token`/`api_token`, the API and GUI are **open** to anything that can reach the ports. On a shared LAN, set a token and/or `gui_bind: 127.0.0.1`.
- Override mode and query recording are opt-in and can be disabled at any time.
- The local CA is generated on first install and trusted in *this machine's* root store only.

## Uninstall

```powershell
powershell -ExecutionPolicy Bypass -File .\uninstall.ps1
```

Removes the scheduled task, firewall rules, hosts-file entry, and optionally the trusted CA and installed files.

## License

[MIT](LICENSE) © spacewalkingninja
