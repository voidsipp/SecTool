# SecTool — UDM Pro alert summarizer → Discord

Ingests security alerts from a UniFi **UDM Pro** over syslog, gathers the
surrounding log context, summarizes each alert with **Claude** (using your
existing Claude Code OAuth subscription — no API key required), and posts a
clean, severity-colored embed to a **Discord webhook**.

```
UDM Pro ──syslog──▶ SecTool ──▶ detect ──▶ correlate ──▶ Claude ──▶ Discord
            (UDP/TCP)         (IDS/IPS)   (related logs)  (summary)  (webhook)
```

- **Zero runtime dependencies.** Pure Node.js (built-in `dgram`, `net`, `fetch`).
- **Real-time** UDP/TCP syslog listener with RFC 3164 / RFC 5424 parsing.
- **Smart detection** of Suricata IDS/IPS signatures, threat-management, and
  firewall events, with severity derived from Suricata priority + classification.
- **Log correlation** — every alert is enriched with recent buffered log lines
  that involve the same source/destination hosts.
- **Claude summaries** via your Claude Code OAuth token (auto-refreshed), with a
  deterministic offline fallback if Claude is unreachable.
- **De-duplication** so a re-firing signature doesn't spam your channel.
- **@-mentions** on `critical`/`high` alerts (optional).

---

## Requirements

- **Node.js ≥ 22.6** (uses native TypeScript execution; you have v24 ✓).
- A signed-in **Claude Code** install (`~/.claude/.credentials.json`) **or** an
  `ANTHROPIC_API_KEY`.
- A **Discord webhook** URL.
- A **UDM Pro** that can reach this machine on the LAN.

## Setup

```bash
npm install          # installs dev-only deps (typescript, @types/node)
cp .env.example .env # then edit .env
```

Fill in **`.env`** (see `.env.example` for all options). At minimum:

```ini
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/XXXX/YYYY
SYSLOG_UDP_PORT=5514
DRY_RUN=false
```

### Point the UDM Pro at SecTool

In the UniFi Network app:

1. **Settings → System → Logging** (older firmware: **Remote Logging / Syslog**).
2. Enable **Remote Syslog Server**.
3. **Server** = this machine's LAN IP, **Port** = `5514` (must match
   `SYSLOG_UDP_PORT`).
4. Enable the detailed/debug logging options so **IDS/IPS (Threat Management)**
   events are exported.
5. Make sure **Threat Management / IDS/IPS** is enabled
   (**Settings → Security**) so there are alerts to forward.

> Port `514` is privileged on most OSes. `5514` works without admin rights — just
> set the UDM to the same port. If you must use `514`, run SecTool elevated.

## Run

```bash
npm start            # start the service
npm run self-test    # inject a synthetic IPS alert end-to-end (posts to Discord)
npm run print-config # show the resolved config (secrets redacted)
npm run typecheck    # tsc --noEmit
```

**Validate it works** before relying on it:

```bash
npm run self-test
```

This feeds a realistic `ET MALWARE` Suricata line through the whole pipeline and
posts the result to your Discord channel.

## Backfilling past alerts (`--backfill`)

The live syslog service is **forward-only** — it summarizes alerts that arrive
after it starts. To process IDS/IPS detections the UDM already stored, run a
one-time backfill. It logs into the UDM controller API, pulls the events for the
window, correlates them against each other, summarizes each with Claude, and
posts one (deduped, rate-limited) Discord message per alert.

```bash
node src/index.ts --backfill 24    # last 24 hours
npm run backfill                   # shortcut for 24h
```

Requires UDM credentials in `.env` (the live service does **not** use these):

```ini
UNIFI_HOST=https://192.168.0.1
UNIFI_USERNAME=<local-admin-user>
UNIFI_PASSWORD=<local-admin-pass>
```

> Use a **local** UniFi admin account, not your Ubiquiti SSO email. Create one in
> **UniFi OS → Admins → Add Admin → "Restrict to local access only"**. The
> gateway's self-signed cert is accepted automatically (TLS verification is
> scoped-off only for UDM requests; Claude/Discord stay verified).

Safety: `BACKFILL_MAX` (default 200) caps how many alerts are posted, and
`BACKFILL_POST_DELAY_MS` (default 1200) spaces out Discord posts. Below-threshold
(`MIN_SEVERITY`) and duplicate events are filtered before posting.

### Recommended: automated SSH pull (`--pull`)

The easiest path. One command SSHes into the UDM, queries its MongoDB event
store, and ingests the results — no credentials stored in SecTool. The first run
walks you through a quick setup and configures **SSH key auth**, so you enter your
UDM password only once (while the key is installed); every pull after is
passwordless. Connection details are saved to `ssh-target.json` (gitignored).

```bash
node src/index.ts --setup-ssh     # one-time interactive setup (saves connection)
npm run pull                      # pull + ingest the last 24h
node src/index.ts --pull 48       # custom window
```

`--pull` auto-runs setup on first use. Prerequisite: enable **SSH** on the UDM
(UniFi OS console → Settings → SSH). Setup asks for host (default `192.168.0.1`),
port, user (`root`), and the Mongo collection (`ips_event`); if your firmware
runs the Network app in a container, answer **yes** to "wrap in `unifi-os shell`".
No password is ever written to disk — only the connection metadata and a
generated SSH key under `.ssh/`.

### Manual alternative: SSH export → `--ingest-file`

If you'd rather export by hand (or `--pull` can't set up keys on your firmware),
read the events straight from the UDM's MongoDB over SSH and ingest the file.

**1. Enable SSH** on the UDM: UniFi OS console → Settings → enable **SSH** and set
a root password.

**2. Export the last 24h** from the UDM's event store (run in PowerShell):

```powershell
ssh root@192.168.0.1 "mongo --quiet --port 27117 ace --eval 'JSON.stringify(db.ips_event.find({timestamp:{`$gte:Date.now()-86400000}}).sort({timestamp:1}).toArray())'" > C:\Users\conta\Desktop\SecTool\ips_events.json
```

> The backtick before `$gte` stops PowerShell expanding it; the `--eval` is in
> single quotes so the UDM's shell leaves `$gte` alone. If `mongo` isn't found,
> run `unifi-os shell` first (the Network app's Mongo lives in that container).
> If the file comes back `[]`, your firmware may store events in `db.alarm` —
> swap `db.ips_event` for `db.alarm`.

**3. Ingest the file** — same correlate → summarize → Discord pipeline:

```powershell
node src/index.ts --ingest-file ips_events.json
```

The ingester accepts a JSON array, an `{ data: [...] }` wrapper, or
newline-delimited JSON, and understands MongoDB extended JSON
(`$numberLong`, `$date`, `$oid`).

## Web dashboard (`--web`)

A local dashboard to view alerts and investigate them. It runs inside the service
automatically (or standalone via `node src/index.ts --web`) and is served at
**http://127.0.0.1:8787**.

- **Alert list** pulled live from the UDM, severity-colored, with AI/sent badges.
- **AI analysis** — shows the stored Claude summary, or generate one on demand.
- **Investigation tools** (run on the gateway over SSH):
  - **📡 Capture live traffic** — an 8s `tcpdump` of current traffic to/from the
    alert's hosts.
  - **🔗 Active connections** — `conntrack` sessions involving the host.
  - **🕑 Surrounding activity** — every logged event/flow within ±15 min of the
    event, plus a current connection snapshot.

> Bound to `127.0.0.1` by design — it can run privileged commands on your gateway,
> so don't expose it on the LAN without putting authentication in front of it.
> Requires the SSH connection from `--setup-ssh`.

## Active response: firewall blocking (`BLOCK_ENABLED`)

Block a malicious IP at the gateway from the dashboard (**🚫 Block this IP**) or
the API. SecTool maintains a `SECTOOL_BLOCK` ipset with DROP rules at the top of
the UDM's FORWARD/INPUT chains over SSH, **re-asserted every `BLOCK_REASSERT_SEC`**
(UniFi rebuilds its chains on provision). The **Blocked** page lists every block
with how long it's been active and a one-click unblock. Private/gateway IPs and
anything in `BLOCK_ALLOWLIST` are always refused. No auto-expiry — blocks persist
until you remove them.

## Auto-enrichment + smart escalation (`ENRICH_AUTO`)

Every live alert is enriched before it's posted: the external IP's geo/ASN/VT/
AbuseIPDB verdicts are folded into the Discord embed, and if VT
malicious+suspicious ≥ `ESCALATE_VT_MALICIOUS` or AbuseIPDB ≥ `ESCALATE_ABUSE_SCORE`,
the alert is escalated to **critical** (firing `DISCORD_MENTION`).

## Scheduled threat digest (`DIGEST_ENABLED`, `--digest`)

A Claude-written daily rollup posted to Discord: totals, severity breakdown, top
attackers (with country/ASN/VT), most-targeted hosts, and threat types. Runs
in-service daily at `DIGEST_HOUR`, or on demand:

```bash
node src/index.ts --digest 24    # or: npm run digest
```

## 🔍 Endpoint agent (process attribution)

Network data tells you *that* a host talked to an IP; the agent
([`agent/sectool-agent.mjs`](agent/sectool-agent.mjs)) on the device tells you
*which program* owned the socket. When `AGENT_ENABLED=true`, SecTool serves a
**one-line installer + auto-updater** on `:7878`:

```powershell
irm http://<sectool-host>:7878/install.ps1 | iex     # Windows
curl -fsSL http://<sectool-host>:7878/install.sh | bash   # Linux/macOS
```

The agent registers itself to run on boot, **self-updates on each start** (checks
`/version`), and exposes a token-protected lookup API. In the dashboard, the **🔍**
buttons (alert detail + war-map country breakdown) query the agent on the internal
host to name the owning **process / PID / path**. SecTool only ever queries LAN
IPs. See [agent/README.md](agent/README.md).

The **📟 Devices** page (`GET /api/agents`) discovers which internal hosts are
running an agent (probing hosts seen in flows), shows each one's version / platform
/ health, and lets you browse its **live connections → owning process**
(`GET /api/agents/connections?host=`) with a filter box.

### 🔍 LAN auto-discovery (`DISCOVERY_ENABLED`, `GET /api/discovery`)

The Devices page's **🔍 Scan LAN** button actively enumerates *every* device on
the local network — not just hosts running the agent or seen in flows. It runs a
TCP-connect ping sweep across the host's directly-connected private subnet(s) (an
open *or* refused port both prove liveness even when ICMP is firewalled), reads
the OS ARP cache to attach each device's **MAC address and vendor** (resolved from
the MAC's OUI prefix), best-effort reverse-DNS for a hostname, and folds in
NetFlow-seen hosts so quiet devices still appear with their last-seen time. Only
RFC1918 ranges are ever scanned and the candidate count is hard-capped
(`DISCOVERY_MAX_HOSTS`) so a wide netmask can't trigger a runaway sweep. Pass
`?subnet=192.168.1.0/24` (or set `DISCOVERY_SUBNETS`) to target a specific range.

### ⬇ Agent push-deploy (`DEPLOY_ENABLED`, `POST /api/discovery/deploy[-all]`)

Once devices are discovered, the **⬇ Push agent** bar installs the endpoint agent
on eligible hosts unattended — no need to touch each machine. SecTool flags every
LAN host that isn't already running the agent and exposes a transport it can drive,
then runs SecTool's own one-liner installer remotely (downloaded from the dist
server, with the agent token/port baked in). Two transports cover the LAN:

- **SSH** (`DEPLOY_SSH_*`) — Linux, macOS, and any host running an SSH server.
  Key auth by default (reuses the UDM key or `DEPLOY_SSH_KEY`); password auth only
  if `sshpass` is installed on the SecTool host.
- **WinRM** (`DEPLOY_WINRM_*`) — the fallback for **Windows hosts that don't run
  SSH**. SecTool's local PowerShell client opens a PSRemoting session (`:5985`, or
  `:5986` with `DEPLOY_WINRM_USE_SSL=true`) and runs the same `/install.ps1`
  one-liner. WinRM has no key auth, so enter a Windows admin password in the bar;
  the target needs PSRemoting enabled (`Enable-PSRemoting -Force`). The target IP
  is best-effort added to the client's `TrustedHosts` so IP + local-admin works.

A mixed LAN deploys in one pass — **⬇ Push to all eligible** routes each host over
its own transport. Pushing software onto other machines is sensitive, so the whole
feature is opt-in (`DEPLOY_ENABLED=false` by default) and only ever targets RFC1918
IPv4 hosts. Hosts with neither SSH nor WinRM are listed for the manual one-liner.

## 💬 Conversational analyst (dashboard "Ask", `POST /api/ask`)

Ask plain-English questions and Claude answers by **querying your real telemetry**
— it has read-only tools over collected flows, IDS/IPS alerts (Mongo), the DNS
log, IP reputation/feeds, host risk, and the blocklist. Examples: *"Who attacked
me most this week and are they dangerous?"*, *"Has any internal host talked to a
VPS abroad?"*, *"Show DNS lookups containing telemetry."* Needs no extra config —
uses your existing Claude auth. (A Discord bot can call the same endpoint.)

## 🍯 Deception / honeypots (`HONEYPOT_ENABLED`)

Opens decoy services on ports nothing legitimate should touch. **Any** connection
is a near-zero-false-positive alert — an external attacker, or (highest value) a
**compromised internal host scanning your LAN**. Internal hits are flagged as
likely compromise; external hits can optionally auto-block (`HONEYPOT_AUTOBLOCK`).
Ports already in use are skipped automatically.

## 📈 Behavioral baselining (`ANOMALY_ENABLED`)

Learns each internal host's normal outbound behavior, then flags **deviations**
signatures/feeds can't see: a **new outbound port**, an **outbound volume spike**,
or a **fan-out spike** (sudden scanning). Catches novel malware, exfil, and worm
behavior. Needs `ANOMALY_MIN_LEARN_HOURS` to learn first; anomalies appear on the
🖥️ Hosts page and (optionally) Discord.

## Threat-intel feeds (`INTEL_FEEDS_ENABLED`, `--feeds`)

Fetches public IP blocklists (abuse.ch Feodo/SSLBL, blocklist.de, FireHOL level1,
Spamhaus DROP), loads them into a `SECTOOL_FEED` ipset so known-bad IPs are
**dropped before they ever probe you**, and cross-references every enrichment
("on threat feeds: FireHOL level1"). A **highlighted changelog embed** is posted
to Discord every 24h with per-feed counts and deltas. Run on demand: `--feeds`.

## Autonomous response (`AUTORESPOND_*`)

Optionally auto-blocks IPs when an alert **escalates** (damning VT/AbuseIPDB/feed
verdict) or a source becomes a **repeat offender** (`AUTORESPOND_REPEAT_THRESHOLD`
hits in a window). Guarded by `AUTORESPOND_DAILY_CAP` and the block allowlist.
**Start with `AUTORESPOND_DRY_RUN=true`** — it logs "would block …" without acting,
so you can watch its decisions before letting it pull the trigger. The Blocked
page shows per-IP **dropped packet/byte counters** (block effectiveness).

## Internal host risk (Hosts page)

Flips the lens inward: ranks your internal devices by signs of compromise from
collected flows — **outbound to known-bad** (feed-listed) IPs, **beaconing**
(regular fixed-interval C2-style connections), and **fan-out** (talking to an
unusual number of externals). Open it from the **🖥️ Hosts** button. Forward-only
and 1:512-sampled, so bad-outbound is the highest-confidence signal.

## Attack campaigns (Campaigns page, `GET /api/campaigns`)

Clusters the stored alert history by the **external attacker IP** behind each
alert, so a single adversary's whole footprint reads as one incident instead of
dozens of scattered rows. Open it from the **🎯 Campaigns** button. Each campaign
rolls up its alert volume, worst severity, distinct signatures, every internal
host it touched, blocked-vs-detected counts, and its active time span — ranked by
a composite **threat score** (severity + volume + signature/target breadth, with
a bonus for short intense bursts and a discount when the gateway already blocked
everything). Attackers are tagged as already **blocked / watched / safe**, and
you can **block**, **watch**, or mark **safe** in one click. Optional geo
enrichment (`?geo=1`, on by default in the UI) labels each attacker with its
country/flag via ip-api. Pure in-memory math over `data/alerts.json` — no SSH
required, same data source as the Trends report.

## IP enrichment & per-IP activity (investigation panel)

- **🌍 Enrich IP** — looks up the alert's external IP against **ip-api.com**
  (geo, ASN, ISP/org, hosting/proxy/mobile flags, rDNS — no key needed),
  **VirusTotal** (`VT_API_KEY`: malicious/suspicious verdicts, reputation, link),
  and **AbuseIPDB** (`ABUSEIPDB_API_KEY`: abuse confidence score). Results are
  cached (6h) and private IPs are never sent to third parties.
- **📊 All activity for this IP** — every collected flow to/from the IP in an
  expandable window (±24h / 72h / 7d / 30d / all retained data), aggregated by
  peer with byte totals, plus logged events involving the IP. Shows the
  **data-availability range** so you know how far back collection goes (flows are
  persisted to `data/flows.json`, so history survives restarts).

## NetFlow/IPFIX flow collector (`NETFLOW_ENABLED`)

For true per-connection history in investigations, SecTool can act as a
NetFlow/IPFIX collector. The UDM keeps no local flow history (it exports IPFIX
and otherwise streams flows in real time), so SecTool collects them itself.

When `NETFLOW_ENABLED=true` and SSH is configured, on startup the collector:
1. Binds a UDP listener (`NETFLOW_PORT`, default 2055).
2. Points the UDM's IPFIX export at this host by setting the
   `net.netflow.destination` sysctl over SSH, and re-asserts it every 5 minutes
   (so it survives UDM reboots/provisions).
3. Decodes IPFIX (v10) / NetFlow v9 into a time-bounded in-memory flow store.

The **🌐 Collected flows** section of the investigation panel then shows flows
involving the alert's host in the time window (proto, ports, bytes, packets, and
a `BLOCKED` marker from IPFIX forwardingStatus).

Caveats:
- **Forward-only** — flows are collected from when the collector starts; it can't
  show flows from before that.
- **Sampled 1:512** (the UDM's setting) — low-volume hosts may not appear.
- For persistence across UDM reboots even when SecTool is down, also set the
  NetFlow **Collector Address** to this host in the UniFi UI (Settings →
  CyberSecure → Traffic Logging → NetFlow).

## How summarization is authenticated

`CLAUDE_AUTH_MODE` controls auth:

- `auto` (default) — use the Claude Code OAuth token if present, else the API key.
- `oauth` — force the OAuth token from `~/.claude/.credentials.json`. The access
  token is short-lived; SecTool refreshes it automatically using the stored
  refresh token and writes the rotated credentials back atomically (exactly as
  the `claude` CLI does). If refresh fails, re-run `claude` to sign in again.
- `apikey` — force `ANTHROPIC_API_KEY` (standard, billed per token).

> The OAuth path reuses your Claude subscription and shares the same credentials
> file as the `claude` CLI. Summarization counts against your subscription usage.

## Configuration reference

All keys live in `.env`; see **`.env.example`** for the annotated list. Highlights:

| Key | Default | Purpose |
| --- | --- | --- |
| `DISCORD_WEBHOOK_URL` | — | **Required.** Target webhook. |
| `DISCORD_MENTION` | — | e.g. `<@&ROLE_ID>`, pinged on critical/high. |
| `SYSLOG_UDP_PORT` | `5514` | Listener port (match the UDM). |
| `SYSLOG_PROTOCOL` | `udp` | `udp` \| `tcp` \| `both`. |
| `CLAUDE_MODEL` | `claude-sonnet-4-6` | Summarization model. |
| `SUMMARIZE_ENABLED` | `true` | `false` → raw alerts, no Claude. |
| `MIN_SEVERITY` | `low` | Only notify at/above this level. |
| `DEDUPE_WINDOW_SEC` | `300` | Suppress repeat alerts for N seconds. |
| `CORRELATION_WINDOW_SEC` | `180` | Time window for related-log gathering. |
| `ALERT_PATTERN` | — | Optional regex an event must match to be an alert. |
| `DISCOVERY_ENABLED` | `true` | Active LAN device sweep (Devices → 🔍 Scan LAN). |
| `DISCOVERY_MAX_HOSTS` | `1024` | Hard cap on hosts probed per sweep. |
| `DISCOVERY_SUBNETS` | — | Override auto-detected subnet(s), e.g. `192.168.1.0/24`. |
| `DEPLOY_ENABLED` | `false` | Agent push-deploy to discovered hosts (Devices → ⬇ Push). |
| `DEPLOY_SSH_USER` | `root` | SSH login for the SSH transport (Linux/macOS). |
| `DEPLOY_WINRM_ENABLED` | `true` | WinRM transport for SSH-less Windows hosts. |
| `DEPLOY_WINRM_USER` | `Administrator` | WinRM admin login (needs a password in the UI). |
| `DEPLOY_WINRM_USE_SSL` | `false` | Use HTTPS WinRM on `:5986` instead of `:5985`. |
| `DRY_RUN` | `false` | `true` → log instead of posting to Discord. |

## Running as a background service (Windows)

The simplest robust option is [NSSM](https://nssm.cc/):

```powershell
nssm install SecTool "C:\Program Files\nodejs\node.exe" "C:\Users\conta\Desktop\SecTool\src\index.ts"
nssm set SecTool AppDirectory "C:\Users\conta\Desktop\SecTool"
nssm start SecTool
```

Or use **Task Scheduler** with a "At startup" trigger running
`node C:\Users\conta\Desktop\SecTool\src\index.ts`. Allow the chosen syslog port
through **Windows Defender Firewall** (inbound UDP `5514`).

## Project layout

```
src/
  index.ts            entry point, lifecycle, self-test
  config.ts           env loading + validation
  logger.ts           leveled logger
  types.ts            shared domain types
  util/env.ts         tiny .env loader
  syslog/parser.ts    RFC 3164 / 5424 parsing + IP extraction
  syslog/server.ts    UDP/TCP listeners
  ingest/
    alertDetector.ts  classify + extract alert fields (Suricata/UniFi/JSON)
    logBuffer.ts      TTL ring buffer of recent events
  enrich/correlate.ts gather related logs for an alert
  summarize/
    oauth.ts          read + refresh Claude Code OAuth credentials
    claude.ts         Messages API client + fallback summary
    prompt.ts         analyst prompt construction
  notify/discord.ts   embed builder + webhook sender
  dedupe.ts           duplicate suppression
  pipeline.ts         orchestration
```

## Troubleshooting

- **No alerts arriving** — confirm the UDM is forwarding to the right IP/port,
  the firewall allows inbound UDP, and IDS/IPS is enabled. Set `LOG_LEVEL=debug`
  to see every received line, or temporarily set `MIN_SEVERITY=info`.
- **`EACCES` on bind** — use port `5514`, not `514`.
- **`OAuth token refresh failed`** — run `claude` once to re-authenticate, or set
  `CLAUDE_AUTH_MODE=apikey` with `ANTHROPIC_API_KEY`.
- **Discord 401/404** — the webhook URL is wrong or was deleted.
```
