# SecTool endpoint agent

A tiny, zero-dependency agent you install on devices you want to investigate
(your desktop, a server, a NAS…). It maps the host's live network connections to
the **owning process** and keeps ~30 min of history, so when an alert fires about
traffic on a port, SecTool can tell you *exactly which program* owned that socket.

Just one file: `sectool-agent.mjs`. Requires **Node.js 18+** on the device.

## One-line install (recommended)

SecTool serves an installer on `http://<sectool-host>:7878`. On the device:

```powershell
# Windows (PowerShell)
irm http://192.168.0.60:7878/install.ps1 | iex
```
```bash
# Linux / macOS
curl -fsSL http://192.168.0.60:7878/install.sh | bash
```

This downloads the agent, writes its config (token + update URL), and registers it
to run on boot/login (Scheduled Task on Windows, systemd user service on Linux,
launchd on macOS). **No manual token handling** — it's baked in by the server.

### Auto-update
On **every start**, the agent asks `http://<sectool-host>:7878/version`; if SecTool
has a newer agent, it downloads it, replaces itself, and relaunches. So updating
all your devices is just updating `agent/sectool-agent.mjs` on the SecTool host.

It also runs a recurring **update-check heartbeat** (every 1h by default, see
`AGENT_UPDATE_CHECK_MIN`) so long-lived agents pick up new builds without waiting
for a restart. A *failed* check retries within ~5 minutes rather than waiting the
full interval. The last heartbeat's outcome is reported under `update` in
`GET /health` — `result` (`current`/`available`/`error`/…), `latestSeen`,
`upToDate`, `ageMs` since the last check, and `checks` performed — so the SecTool
dashboard can flag agents that are stale or failing their checks.

## Auto-push from discovery (no touching the device)

The Devices page's **LAN auto-discovery** flags every host that *supports* an
unattended install — one that exposes SSH and isn't already running the agent —
and lets you push the agent to it with one click (or **Push to all eligible** to
fan out across the whole subnet). SecTool simply SSHes in and runs the same
`install.sh` one-liner above, then polls the device's `/health` to confirm the
agent came up. Hosts without SSH (e.g. a stock Windows box) are listed as
*manual install* instead, since there's no unattended transport to use.

Push-deploy is **opt-in** because it installs software on other machines:

| Var | Default | Meaning |
|---|---|---|
| `DEPLOY_ENABLED` | `false` | Master switch for agent push-deploy. |
| `DEPLOY_SSH_USER` | `root` | SSH user to log in as on target devices. |
| `DEPLOY_SSH_PORT` | `22` | SSH port to connect to. |
| `DEPLOY_SSH_KEY` | *(SecTool's UDM key, else ssh-agent)* | Private key for non-interactive auth. |
| `DEPLOY_SERVER_IP` | *(auto, same-subnet)* | The LAN IP devices use to reach the dist server. |
| `DEPLOY_CONCURRENCY` | `4` | Max simultaneous installs during *Push to all*. |
| `DEPLOY_TIMEOUT_MS` | `120000` | Per-host install timeout. |

Auth is **key-based** by default (fully unattended) — re-using the SSH key SecTool
already set up for UDM pulls (`--setup-ssh`) when present, or your ssh-agent's
default keys. A password can be supplied per-request in the UI, but it only works
if `sshpass` is installed on the SecTool host; otherwise use key auth.
Requires `AGENT_ENABLED=true` (so the installer/updater server is running) and
`AGENT_TOKEN` set (so the deployed agent's API is authenticated).

## Manual run

```bash
# pick a strong shared secret and use the SAME value in SecTool's AGENT_TOKEN
AGENT_TOKEN=your-long-random-secret node sectool-agent.mjs
```

PowerShell (Windows):
```powershell
$env:AGENT_TOKEN="your-long-random-secret"; node sectool-agent.mjs
```

It listens on **0.0.0.0:7879** by default. SecTool (on `192.168.0.60`) reaches it
at `http://<device-LAN-IP>:7879`.

### Environment
| Var | Default | Meaning |
|---|---|---|
| `AGENT_TOKEN` | *(none)* | Shared bearer token. **Set it** — without it the API is unauthenticated. |
| `AGENT_PORT` | `7879` | Listen port (must match SecTool's `AGENT_PORT`). |
| `AGENT_HOST` | `0.0.0.0` | Bind address. |
| `AGENT_POLL_MS` | `4000` | How often to snapshot connections. |
| `AGENT_RETENTION_MIN` | `30` | How long to keep connection→process history. |
| `AGENT_UPDATE_CHECK_MIN` | `60` | Recurring update-check heartbeat interval (minutes). `0` disables it; values below `5` are clamped to 5. Failed checks retry within ~5 min. |
| `AGENT_UPDATE_URL` | *(from config)* | Update server base URL. Heartbeat is off unless this (or `updateUrl` in `agent.config.json`) is set. |
| `AGENT_NO_UPDATE` | *(unset)* | Set to any value to disable self-update + the heartbeat entirely. |
| `AGENT_ALLOW_KILL` | `false` | **Destructive.** Enables `POST /kill` (terminate/delete) and `POST /autoruns/remove`. Refused unless a token is set. |
| `AGENT_ALLOW_ISOLATE` | `false` | **Destructive.** Enables `POST /isolate` (network-quarantine the host). Refused unless a token is set. |
| `AGENT_PUSH` | `true`* | Push real-time host events (new external connection / new listener) to SecTool. *On when an update URL is known. |

## Keep it running

- **Windows (NSSM):**
  ```powershell
  nssm install SecToolAgent "C:\Program Files\nodejs\node.exe" "C:\path\to\sectool-agent.mjs"
  nssm set SecToolAgent AppEnvironmentExtra "AGENT_TOKEN=your-secret AGENT_ALLOW_KILL=true"
  nssm start SecToolAgent
  ```
  Or a Task Scheduler "At log on / At startup" task running the same command. To add `AGENT_ALLOW_KILL=true`, update the environment with:
  ```powershell
  nssm set SecToolAgent AppEnvironmentExtra "AGENT_TOKEN=your-secret AGENT_ALLOW_KILL=true"
  ```

- **Linux (systemd):** Create a service unit at `/etc/systemd/user/sectool-agent.service`:
  ```ini
  [Unit]
  Description=SecTool Agent
  After=network.target

  [Service]
  Type=simple
  ExecStart=/usr/bin/node /opt/sectool/sectool-agent.mjs
  Environment="AGENT_TOKEN=your-secret"
  Environment="AGENT_ALLOW_KILL=true"
  Restart=on-failure
  RestartSec=10

  [Install]
  WantedBy=default.target
  ```
  Then: `systemctl --user enable sectool-agent && systemctl --user start sectool-agent`

- **macOS (launchd):** Create a LaunchAgent plist at `~/Library/LaunchAgents/com.sectool.agent.plist`:
  ```xml
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
  <plist version="1.0">
  <dict>
    <key>Label</key>
    <string>com.sectool.agent</string>
    <key>ProgramArguments</key>
    <array>
      <string>/usr/local/bin/node</string>
      <string>/opt/sectool/sectool-agent.mjs</string>
    </array>
    <key>EnvironmentVariables</key>
    <dict>
      <key>AGENT_TOKEN</key>
      <string>your-secret</string>
      <key>AGENT_ALLOW_KILL</key>
      <string>true</string>
    </dict>
    <key>KeepAlive</key>
    <true/>
    <key>RunAtLoad</key>
    <true/>
  </dict>
  </plist>
  ```
  Then: `launchctl load ~/Library/LaunchAgents/com.sectool.agent.plist`

## API (token via `Authorization: Bearer <token>`)

- `GET /health` — host, platform, tracked connection count, and an `update`
  object summarising the update-check heartbeat (no auth needed).
- `GET /lookup?remoteIp=&remotePort=&localPort=&proto=` — connections matching the
  filter, each with `process`, `pid`, `path`, `state`, `firstSeen`/`lastSeen`.
- `GET /connections` — current connection→process snapshot. Each record includes
  `localAddr` (v1.0.2+), and (v1.3.0+) `sha256` of the binary (background-hashed,
  for reputation lookups), `cmdline`, `ppid`, and `parent` process name.
- **Audit trail (v1.7.0+):** every destructive action (kill, delete, service
  disable/enable, autorun removal, isolate/release) is appended to `audit.json` next
  to the agent — durable, survives restarts. `GET /audit` returns it; the Devices
  page has an **Audit** tab showing what was done on each host, including which
  services were disabled, with a **▶ re-enable** button (via `POST /service`,
  `{name, action:"enable"|"disable"}`) to restore a service you disabled by mistake.
- **Service neutralize (v1.6.1+):** when `deleteFile` is set, the agent first finds
  any Windows service backed by the target PID (or whose image is the target binary),
  **stops and disables** it, *then* kills + deletes — so a service watchdog can't
  respawn the process and re-lock the binary mid-delete. The disabled service(s) are
  reported back in each result's `services`. Plain kill (no delete) doesn't touch services.
- **Elevation (v1.6.0+):** deleting binaries under `C:\Program Files`, removing
  **HKLM** autoruns, and killing service/protected processes require the agent to
  run as **Administrator/SYSTEM**. The installer registers the Scheduled Task with
  **RunLevel Highest** — run the one-liner from an **elevated** PowerShell to enable
  it. `GET /health` reports `elevated`, and the Devices page shows **⬆ elevated** or
  **⚠ not elevated** per host. When elevated, `deleteFile` escalates past permission
  errors (take ownership + grant + hard delete, then schedule-on-reboot for locked
  files); when not, it returns a clear "agent not elevated" message.
- `GET /process?pid=N` (v1.5.0+) — full detail for one process: command line, parent
  chain, executable path, Authenticode signature + signer, SHA-256, owning user, and
  every socket it holds. Powers the Devices page's clickable process inspector
  (click a process under Connections or Listeners).
- `GET /autoruns` (v1.3.0+) — persistence enumeration: scheduled tasks, Run keys,
  auto-start services, startup-folder items (Windows; cron/systemd/autostart on Linux).
- `POST /autoruns/remove` (v1.3.0+, destructive, needs `AGENT_ALLOW_KILL`) — remove a
  persistence entry `{type,name,location,command}` (tasks / run keys / startup items).
- `POST /isolate` and `POST /release` (v1.3.0+, destructive, needs
  `AGENT_ALLOW_ISOLATE`) — network-quarantine the host (allow only SecTool + the
  agent port) / revert. The agent auto-allows the calling SecTool IP so you can't
  lock yourself out.
- **Push** (v1.3.0+): when enabled, the agent POSTs `new-external-connection` /
  `new-listener` events to the SecTool dist server's `/event` in real time.
- `GET /connections` records (v1.3.0+) carry `sha256` (background-hashed), `cmdline`,
  `ppid`, `parent`. SecTool checks the hash against VirusTotal (unknown-to-VT is
  surfaced as a hunting signal), clickable in the Connections table.
- `GET /dns` (v1.4.0+) — recently-resolved domains (host DNS cache) correlated with
  the processes doing DNS (port-53 sockets).
- `GET /triage` (v1.4.0+) — one-shot IR bundle: connections, autoruns, DNS, hosts
  file, and running binaries with Authenticode signature status + hashes. Downloadable
  from the Devices page (🧾 Triage).
- **Signed updates** (v1.4.0+): the agent pins an Ed25519 public key (installed from
  the dist server's `/pubkey`) and **refuses any self-update whose signature
  (`/agent.sig`) doesn't verify** — so a LAN MITM can't push a malicious update.
  Legacy installs with no pinned key still update (with a warning); re-run the
  installer to pin a key. Shows as 🔏 signed / 🔓 unsigned on the Devices page.
- **Fleet monitoring** (v1.4.0+): SecTool remembers every agent it has seen and
  alerts (Discord) when one goes dark, drifts below the latest version, or reports
  itself isolated. Offline agents are listed on the Devices page.
- `POST /kill` (v1.1.0+, **destructive, opt-in**) — terminate process(es), and
  optionally delete their executable. Body:
  `{ "pid": <n>, "process": "<name>", "signal": "SIGTERM"|"SIGKILL", "deleteFile": <bool> }`.
  Target **by `pid`** (single, name-verified) **or by `process` name** (kills every
  tracked process of that name). Returns a `results[]` with per-target
  `killed` / `deleted` / error fields.
  **Disabled unless `AGENT_ALLOW_KILL=true` AND a token is set.** Guards: rejects
  PIDs ≤ 4 and the agent's own PID; the target must be a process the agent
  currently tracks (has a live connection); a supplied `process` name must match the
  PID's real name (defeats PID reuse). `deleteFile` deletes only the **tracked
  binary path** of a killed process (never a caller-supplied path) and **refuses
  OS-critical locations** (`C:\Windows`, `/bin`, `/usr`, `/lib`, `/etc`, … and the
  node runtime itself). Surfaces as 🛑 **kill** and 🗑 **kill+delete** buttons on the
  Devices → **Connections**, **Listeners**, and **Egress** panels (Live ports and
  Traffic are gateway/NetFlow views with no process attribution, so no buttons).

### Enabling kill on a device
By default it's off. The easiest way is the **Devices page**: each host with a
token shows a **🛑 Kill: on/off** toggle. Clicking it calls `POST /config`, which
flips `allowKill` in memory **and persists it** to the host's `agent.config.json`
(so it survives a restart) — no need to touch files on the device. Requires
SecTool's own `AGENT_ALLOW_KILL=true` master switch.

Equivalent manual options (still supported):
- Add `"allowKill": true` to the host's `agent.config.json` (in
  `%LOCALAPPDATA%\SecToolAgent` on Windows, `~/.sectool-agent` on Linux/macOS).
- Set `AGENT_ALLOW_KILL=true` in its service environment.
  **Note:** When set, this env var *pins* the value—the dashboard toggle becomes locked (shown as 🔒), and `POST /config` requests to change it are refused with HTTP 409. The env var always takes precedence.

- `POST /config` (v1.1.1+, token-gated) — body `{ "allowKill": <bool> }`. Persists
  to `agent.config.json`. Refused (409) if `AGENT_ALLOW_KILL` env pins the value.

## Security

- The agent exposes process/connection info — **always set `AGENT_TOKEN`**, and
  only run it on a trusted LAN. Consider a host firewall rule limiting port 7879
  to SecTool's IP (`192.168.0.60`).
- It is **read-only**: it only reports connections; it never modifies the device.
- SecTool only ever queries **private/LAN IPs**, never arbitrary hosts.
