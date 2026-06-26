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

It also runs a recurring **update-check heartbeat** (every 6h by default, see
`AGENT_UPDATE_CHECK_MIN`) so long-lived agents pick up new builds without waiting
for a restart. The last heartbeat's outcome is reported under `update` in
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
| `AGENT_UPDATE_CHECK_MIN` | `360` | Recurring update-check heartbeat interval (minutes). `0` disables it; values below `5` are clamped to 5. |
| `AGENT_UPDATE_URL` | *(from config)* | Update server base URL. Heartbeat is off unless this (or `updateUrl` in `agent.config.json`) is set. |
| `AGENT_NO_UPDATE` | *(unset)* | Set to any value to disable self-update + the heartbeat entirely. |

## Keep it running

- **Windows (NSSM):**
  ```powershell
  nssm install SecToolAgent "C:\Program Files\nodejs\node.exe" "C:\path\to\sectool-agent.mjs"
  nssm set SecToolAgent AppEnvironmentExtra AGENT_TOKEN=your-secret
  nssm start SecToolAgent
  ```
  Or a Task Scheduler "At log on / At startup" task running the same command.
- **Linux (systemd):** a unit with `Environment=AGENT_TOKEN=...` and
  `ExecStart=/usr/bin/node /opt/sectool/sectool-agent.mjs`.
- **macOS (launchd):** a LaunchAgent plist with the env var + program args.

## API (token via `Authorization: Bearer <token>`)

- `GET /health` — host, platform, tracked connection count, and an `update`
  object summarising the update-check heartbeat (no auth needed).
- `GET /lookup?remoteIp=&remotePort=&localPort=&proto=` — connections matching the
  filter, each with `process`, `pid`, `path`, `state`, `firstSeen`/`lastSeen`.
- `GET /connections` — current connection→process snapshot. Each record includes
  `localAddr` (v1.0.2+) so SecTool can tell whether a listening port is bound to
  all interfaces or just localhost in the Devices page's **Listeners** audit.

## Security

- The agent exposes process/connection info — **always set `AGENT_TOKEN`**, and
  only run it on a trusted LAN. Consider a host firewall rule limiting port 7879
  to SecTool's IP (`192.168.0.60`).
- It is **read-only**: it only reports connections; it never modifies the device.
- SecTool only ever queries **private/LAN IPs**, never arbitrary hosts.
