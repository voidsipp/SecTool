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

- `GET /health` — host, platform, tracked connection count (no auth needed).
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
