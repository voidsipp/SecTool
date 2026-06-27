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
npm run metrics      # print the Prometheus/OpenMetrics exposition (also served at GET /metrics)
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

### 🔎 Search history (`GET /api/search`)

The live alert list needs SSH and only covers a recent window. The **🔎 Search**
tab instead queries the *persisted* alert history (up to 2000 stored alerts, with
their AI summaries and triage state) **entirely offline** — no SSH or UDM
round-trip. Free-text terms (space-separated, ANDed across signature / IP /
classification / category / raw) combine with structured filters: minimum
severity, action, triage status, time window, a `src OR dst` IP/CIDR match, and
`has-AI-summary` / `notified` / `include-dismissed` toggles, sortable by time or
severity. Selecting a result shows its stored Claude summary and full triage
controls (status + append-only notes). Export the whole match set to a
spreadsheet-friendly CSV (`GET /api/search.csv?…`, CSV-injection-safe) with the
**⬇ CSV** button.

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

## 📄 Offline incident report (`GET /api/report[.md]`)

The dashboard's **📄 Report** tab generates a shareable, SOC-style security
report for a chosen window (6h → 30d) straight from the **local** alert history —
**no SSH, no Claude, no live gateway query**, so it is safe to generate at any
time. It rolls up an auto-written executive summary and posture rating, key
metrics, the severity & disposition breakdown, triage workflow status, an ASCII
volume sparkline, top signatures / sources / destinations / categories,
watchlist activity, and the active suppression rules.

- `GET /api/report?hours=N` → the structured model **plus** the rendered Markdown.
- `GET /api/report.md?hours=N` → the same report as a downloadable `.md` file.

Use **⧉ Copy Markdown** to paste it into a ticket/chat, or **⬇ Download .md** to
keep a dated record. This complements the interactive **📊 Trends** view (not
exportable) and the Claude-written Discord **digest** (needs SSH + Claude).

## ⇆ Period comparison (`GET /api/compare[.md]`, `--compare`)

The Report tab's **⇆ Compare periods** toggle answers the orthogonal question to
the snapshot report: *what changed since last time?* It diffs the current window
against the immediately preceding window of equal length and surfaces the deltas
an analyst actually cares about — whether total volume and risk posture are
rising or falling (and by how much), which severities and dispositions moved,
which **signatures are brand new** this period, which existing signatures are
**surging**, which attacker **source IPs appeared for the first time**, and what
**went quiet**. Like the report, it is pure offline math over the local alert
history — **no SSH, no Claude, no live gateway query**.

- `GET /api/compare?hours=N` → the structured delta model **plus** rendered Markdown.
- `GET /api/compare.md?hours=N` → the same comparison as a downloadable `.md` file.
- `node src/index.ts --compare 24` (or `npm run compare`) → print the Markdown to stdout.

## 👤 Entity profile (`GET /api/profile[.md]`, `--profile`)

Where Trends aggregates *everything* and **🎯 Campaigns** clusters *all* attackers,
the entity profile answers the question you ask mid-investigation: *tell me
everything about **this one** address.* Given a single IP it rolls up — from the
local alert history — every alert that IP appears in (as source **or**
destination) and derives: whether it's an **internal host or external peer**,
first/last seen and active span, a volume **timeline sparkline**, severity /
disposition / triage breakdowns, the **signatures / categories** it triggered,
every **counterpart endpoint** it talked to (split internal/external), its
current **operator state** (blocked / watched / safe, with the watch note), the
most severe individual detections, and a composite **0-100 risk score** plus a
plain-language narrative. Like the report and comparison, it is pure offline math
over the local alert history — **no SSH, no Claude, no live gateway query**.

- `GET /api/profile?ip=<addr>&hours=N` → the structured model **plus** rendered Markdown (`hours` optional; omit for the entire stored history).
- `GET /api/profile.md?ip=<addr>&hours=N` → the same profile as a downloadable `.md` file.
- `node src/index.ts --profile <ip> [hours]` (or `npm run profile -- <ip>`) → print the Markdown to stdout.

This complements **🔎 Search** (lists the matching alert *rows* — no roll-up or
scoring), **🎯 Campaigns** (clusters *all* attackers, not one entity), and the
snapshot **Report** (a whole-window view, not scoped to one address).

## 🖥️ Asset exposure scoreboard (`GET /api/assets[.md]`, `--assets`)

The exact mirror of **🎯 Campaigns**: where Campaigns groups alerts by the
*external attacker* to answer *"who is attacking me?"*, the asset scoreboard
groups the **same** alert history by the **internal host** to answer the inverse —
*"which of **my** devices should I worry about?"* For every internal host it rolls
up its alert volume and worst severity, then makes the security-critical split
between **outbound** alerts (the host was the **source** — a strong *possible
compromise / beaconing* signal) and **inbound** alerts (the host was the
**destination** — it was scanned or targeted), the external peers it touched,
the signatures it tripped, blocked-vs-detected dispositions, open triage items,
and a composite **0-100 exposure risk score** that weights outbound activity
hardest. Each host gets a one-word **posture** — *compromise-suspected*,
*targeted*, *noisy*, or *calm* — and hosts showing severe outbound traffic float
to the top. Pure offline math over the local alert history — **no SSH, no Claude,
no live gateway query**.

- `GET /api/assets?hours=N` → the structured model **plus** rendered Markdown.
- `GET /api/assets.md?hours=N` → the same scoreboard as a downloadable `.md` file.
- `node src/index.ts --assets 24` (or `npm run assets`) → print the Markdown to stdout.

In the dashboard it lives under the **🖥️ Assets** tab, with one-click **Watch** /
**Safe** actions per host.

## 🔧 Signature tuning (`GET /api/tuning[.md]`, `--tuning`)

The reports above answer *"what happened?"*; this one answers the operational
follow-up that fights **alert fatigue**: *"what can I safely silence so the
signal stands out?"* For every distinct signature in the stored history it rolls
up volume + a normalized **alerts/day** rate, the **severity ceiling** it ever
reached, how many distinct hosts it touched, and the operator signals that prove
value or the lack of it — how many of its alerts were **dismissed**, marked
**false-positive**, left **open** in triage, or **resolved** as genuine
incidents. From that it computes a **0-100 noise score** (high volume + low
severity + dismissed/false-positive history push it up; medium+ severity, open
triage and resolved-real incidents pull it down) and emits a conservative
**recommendation** — `suppress` (safe to mute), `review` (probably noise, eyeball
it first), or `keep` (carries signal, leave it). Each actionable row carries a
**ready-to-apply suppression rule** whose `maxSeverity` is pinned to the observed
ceiling, so a future escalation **above** that level still pages you. Pure
offline math over the local alert history — **no SSH, no Claude, no live gateway
query**.

- `GET /api/tuning?hours=N` → the structured model **plus** rendered Markdown.
- `GET /api/tuning.md?hours=N` → the same report as a downloadable `.md` file.
- `node src/index.ts --tuning 168` (or `npm run tuning`) → print the Markdown to stdout.

In the dashboard it lives at the top of the **🔕 Suppressions** tab as a
**Tuning recommendations** panel — each suggested rule has a one-click **Create
rule** button that wires straight into the existing suppression engine.

## 👁️ Watchlist activity (`GET /api/watchlist-activity[.md]`, `--watchlist`)

The watchlist is your curated set of IPs / CIDR ranges to keep an eye on — a
known C2 block, a vendor pen-test, a noisy ASN. It takes no action and changes no
scoring; it is purely **observational**. This report answers the question the
watchlist exists to answer: *"of everything I'm watching, what has actually been
active — and what has gone quiet?"* It clusters the stored alert history around
each watchlist entry and, per entry, rolls up total **hits** + a normalized
**alerts/day** rate, the **direction split** (alerts where the watched address
reached toward us vs. where one of **our** hosts reached it), which concrete
addresses inside a **CIDR** entry actually lit up, the **internal hosts** it
touched, the signatures/categories it tripped, blocked-vs-detected dispositions,
and open triage items. Each entry is labelled **🔴 active**, **🟡 quiet**, or
**⚪ dormant** — and crucially it **also lists dormant entries** (a watched C2
going silent is itself a finding, invisible to every other report). Because the
watchlist is observational, **dismissed** alerts are kept: acknowledging an alert
as noise doesn't mean the target was inactive. Pure offline math over the local
alert history — **no SSH, no Claude, no live gateway query**.

- `GET /api/watchlist-activity?hours=N` → the structured model **plus** rendered Markdown.
- `GET /api/watchlist-activity.md?hours=N` → the same report as a downloadable `.md` file.
- `node src/index.ts --watchlist 24` (or `npm run watchlist`) → print the Markdown to stdout.

## 🕒 Activity rhythm (`GET /api/rhythm[.md]`, `--rhythm`)

Every other report slices the history by an *entity* (IP, host, attacker,
signature, watched target); this one slices it by the **clock**. It answers the
question a SOC asks when it plans coverage and hunts for automation: *when am I
actually under attack?* It folds the stored alert history onto two time axes —
**hour-of-day** (0–23) and **day-of-week** (Mon–Sun) — and crosses them into a
**7×24 ASCII heat-map** that reads at a glance. From that it derives the findings
an analyst acts on: the **peak hour** and **peak day**, how **concentrated**
activity is in that single hour (a tight clock concentration is a fingerprint of
an automated scanner or fixed-interval C2 **beacon** rather than organic
traffic), a **business-hours vs off-hours** split (Mon–Fri 09:00–17:00 by
default) — and crucially how many **medium-or-worse** detections fired
**off-hours**, when the console is least likely to be watched (an off-hours
critical is materially more dangerous than the same alert at 2 p.m.). Times are
bucketed in **UTC** by default to match every other report; pass a timezone
offset to read the rhythm in local time. Pure offline math over the local alert
history — **no SSH, no Claude, no live gateway query**.

- `GET /api/rhythm?hours=N&tz=M` → the structured model **plus** rendered Markdown (`tz` = UTC offset in minutes, e.g. `-300` for US Eastern Standard; omit for UTC).
- `GET /api/rhythm.md?hours=N&tz=M` → the same report as a downloadable `.md` file.
- `node src/index.ts --rhythm 168 [--tz -300]` (or `npm run rhythm`) → print the Markdown to stdout (defaults to a 7-day window so every weekday is represented).

## 📋 Triage SLA backlog (`GET /api/backlog[.md]`, `--backlog`)

Every other report is about the *threats*; this one is about the **response**.
It answers the question a SOC lead asks every morning: *of everything that fired,
what is still unhandled, how old is it, and have we blown our SLA on any of it?*
It joins the stored alert history with the per-alert **triage** workflow state
and the **dismissal** set to produce a service-level view of the queue: the
**open backlog** (status `open` or `investigating`, not dismissed) broken down by
severity and status; **SLA breaches** — unresolved alerts past the
time-to-resolve target for their severity (critical 1h, high 4h, medium 24h, low
72h, info 7d by default) — with the **worst offenders** listed most-overdue-first
so they can be actioned now; **untouched** alerts (still `open` with no triage
note — nobody has even looked); and **throughput** over resolved items (mean /
median time-to-resolve and the share closed inside SLA, so you can tell whether
the backlog is growing or shrinking). Dismissed alerts are excluded — the
operator explicitly chose to hide them. Pure offline math over the local stores —
**no SSH, no Claude, no live gateway query**.

- `GET /api/backlog?hours=N[&limit=25]` → the structured model **plus** rendered Markdown.
- `GET /api/backlog.md?hours=N` → the same report as a downloadable `.md` file.
- `node src/index.ts --backlog 720` (or `npm run backlog`) → print the Markdown to stdout (defaults to a wide 30-day window so genuinely stale, long-unhandled alerts still surface).

## 🎯 Threat-indicator export (`GET /api/iocs`, `--iocs`)

Every other report is a *human narrative*. This one closes the loop **after**
triage by emitting a clean, deduplicated, **confidence-ranked list of attacker
IPs** that other tools ingest directly — a firewall blocklist (`ipset` / pf
table / UniFi firewall group), a SIEM watch rule, or a shared threat-intel feed.
It folds the window's alerts onto each external (routable) source IP, scores how
confidently that IP belongs on a blocklist (severity, volume, how often the
gateway **already blocked** it, breadth of signatures/targets, and any watchlist
**confirmation**), and renders the result in four interchange formats: **plain**
(`#`-commented header + one IP per line, import-ready), **csv** (full context,
CSV-injection-safe), **markdown** (a human review table), and **json** (the
structured model). Trust rails make the output safe as a blocklist source:
**safelisted IPs are excluded by default** (and the omission is counted, never
silent), a **minimum-severity floor** (default `medium`) keeps info/low noise
out, and **dismissed alerts are ignored**. Pure offline math over the local
alert history — **no SSH, no Claude, no live gateway query**.

- `GET /api/iocs?hours=N&format=json|csv|plain|markdown&minSeverity=medium[&includeSafe=1]` → the export in the requested format (`json` returns the structured model inline; the others download as a file).
- `node src/index.ts --iocs 168 [--format plain] [--min-severity medium]` (or `npm run iocs`) → print the export to stdout (defaults to a 7-day window and the `plain` blocklist format, ideal for piping into `ipset restore`).

## 📈 Prometheus / OpenMetrics endpoint (`GET /metrics`, `--metrics`)

Every other surface answers a question **after the fact** — a Markdown report you
open, a dashboard panel you glance at, a digest you skim in the morning. This one
lets your **monitoring system** watch SecTool continuously, with no human in the
loop. It exposes SecTool's live state as a flat set of gauges in the Prometheus
text exposition format (v0.0.4, also valid OpenMetrics), so Grafana graphs it and
Alertmanager fires on it. The alarms it unlocks — none of which exist today:

- **Sensor / pipeline down.** `sectool_last_alert_age_seconds` climbing past a
  threshold means the syslog feed went quiet (collector outage, gateway reboot,
  dropped UDP stream) — a "no alerts" stretch that reads as "no *visibility*",
  the most dangerous silent failure. Alert on e.g. `sectool_last_alert_age_seconds > 3600`.
- **Severity spike.** `sectool_alerts_window{window="1h"}` and
  `sectool_alerts_window_by_severity{window="24h",severity="critical"}` page on a
  sudden surge the moment it happens, not at the next briefing.
- **Store truncation.** `sectool_alert_store_saturation_ratio` nearing `1.0` warns
  the bounded history is evicting the past, so every windowed report is quietly
  understating it.
- **Control-plane drift.** `sectool_blocklist_size`, `sectool_watchlist_size` and
  `sectool_triage{status="open"}` turn "is the queue growing unboundedly?" into a
  graph and an alert.

Cardinality is bounded by design — no raw IP or signature is ever a label;
severity, disposition, triage status and window are fixed enumerations, and the
only data-driven family (`category`) is capped to the top 12 with the tail folded
into `other`. Everything is an **instantaneous gauge** (the store is capped and
rotated, so a fake monotonic `_total` counter would silently reset and break
`rate()`). Pure offline math over the local stores — **no SSH, no Claude, no live
gateway query** — so a scrape is microseconds and safe to hit every 15s.

- `GET /metrics` (the path Prometheus probes by default) or `GET /api/metrics` → the exposition as `text/plain; version=0.0.4`.
- `node src/index.ts --metrics` (or `npm run metrics`) → print the same exposition to stdout for a quick eyeball.

Example scrape config:

```yaml
scrape_configs:
  - job_name: sectool
    static_configs:
      - targets: ["localhost:8787"]   # SecTool's WEB_PORT
```

## ⛓️ Kill-chain / attack-stage report (`GET /api/killchain[.md]`, `--killchain`)

Every other report slices the history by an *entity* (IP, host, attacker,
signature, watched target) or by the *clock* (rhythm). This one slices it by
**attack lifecycle stage**, answering the question that decides whether scattered
alerts are background noise or one unfolding intrusion: *how far along the kill
chain is what I'm seeing — and is any single internal host progressing through
it in sequence?* A lone port-scan is routine internet weather; that same
scanner's target later showing **exploitation** then **command-and-control**
traffic is a breach in motion — a story no per-entity report tells.

It maps every stored alert to one ordered stage using a heuristic over its
Suricata **classification / category / signature** text, then produces two
complementary views:

- **Stage coverage** — Reconnaissance → Delivery/Access → Exploitation →
  Command & Control → Actions on Objectives — each with alert volume, distinct
  attackers and internal hosts touched, severity ceiling, blocked-vs-detected
  disposition, and the defining signatures, plus an at-a-glance ASCII funnel.
- **Per-host progression** — for every internal host, the *set* of stages it
  appears in and the **furthest** it reached. A host seen across several
  successive stages — especially one acting as the **source** of C2 or
  exfiltration traffic — is flagged **🔴 compromise-suspected**; stage depth is a
  far sharper compromise signal than raw alert volume.

Unmappable alerts land in an honest **off-chain** bucket (counted, never
silently dropped), and the output is explicit that stage assignment is a triage
heuristic — a shared endpoint across stages is a lead to investigate, not proof
of a completed intrusion. Pure offline math over the local alert history — **no
SSH, no Claude, no live gateway query**.

- `GET /api/killchain?hours=N[&limit=25]` → the structured model **plus** rendered Markdown.
- `GET /api/killchain.md?hours=N` → the same report as a downloadable `.md` file.
- `node src/index.ts --killchain 168` (or `npm run killchain`) → print the Markdown to stdout (defaults to a 7-day window so multi-stage progression has room to surface).

## 📡 Beaconing / periodicity report (`GET /api/beacon[.md]`, `--beacon`)

Command-and-control malware almost never streams traffic — it *checks in* on a
fixed cadence (every 60s, every 5m, every hour) and goes quiet between beats.
That regular, low-jitter heartbeat is one of the most reliable behavioural tells
in network defence: humans and legitimate apps are bursty, while a beacon ticks
like a metronome. No other report surfaces it — [`rhythm`](#) folds history onto
*hour-of-day* axes (a 5-minute beacon just looks like steady all-day activity),
and volume-ranked reports bury a low-and-slow beacon under noisy scanners.

This report groups the windowed history into **src→dst conversations**, computes
the inter-arrival intervals for each, and scores how *regular* they are. A pair
is flagged **📡 beacon-like** when it repeats enough times, has a sane period
(~10s–24h), and its intervals cluster tightly around their median. For each
candidate it reports the estimated **period** (median interval), the **jitter**
(0% = a perfect metronome), a **0–100 regularity score** that blends low jitter
with having enough samples to trust it, the worst severity, and the dominant
signature for context.

Honest about its limits: cadence is measured from stored **IPS-alert**
timestamps (second-resolution), not every packet — so the true beacon rate may
be faster than shown, very fast beacons (<~10s) can't be distinguished, and thin
candidates are discounted rather than crying "C2" on three lucky hits. Pure
offline math over the local alert history — **no SSH, no Claude, no live gateway
query**.

- `GET /api/beacon?hours=N[&limit=25][&minHits=4]` → the structured model **plus** rendered Markdown.
- `GET /api/beacon.md?hours=N` → the same report as a downloadable `.md` file.
- `node src/index.ts --beacon 168 [--limit 25] [--min-hits 4]` (or `npm run beacon`) → print the Markdown to stdout (defaults to a 7-day window so a low-and-slow beacon has room to repeat many times).

## 🕸️ Spread / fan-out report (`GET /api/spread[.md]`, `--spread`)

Most malicious network shapes are defined not by *what* an endpoint says but by
*how many* other endpoints it says it to. This report surfaces the two topology
anomalies that dominate real incidents — and that no other report captures:

- **🛰️ Fan-out (a sweeping source).** One source IP reaching *many distinct
  destinations* — the signature of horizontal scanning, network recon, a worm
  spreading, or an owned host doing lateral movement. A pure sweep touches each
  peer once and moves on, so its **hits/peer** ratio sits near 1.
- **🎯 Fan-in (a sprayed destination).** One destination contacted by *many
  distinct sources* — the signature of a distributed brute-force, a credential
  spray, a DDoS, or simply an exposed service everyone is poking.

[`beacon`](#-beaconing--periodicity-report-get-apibeaconmd---beacon) scores a
*single* src→dst pair for timing and is blind to a source that hits a hundred
destinations once each; [`watchlist`](#) / [`profile`](#) pivot on an IP you
*already* named, while this report surfaces the spreaders you didn't know to
name. Each endpoint is classified **internal vs. external** (RFC1918 / loopback /
link-local) and its external-peer count is reported, because an internal host
fanning out to *internal* peers (`int→int`, lateral movement) and one fanning out
to the *internet* (`int→internet`, exfil / C2 discovery) are very different
fires — both called out ahead of ordinary external scanners.

Honest about its limits: it reads stored **IPS-alert** topology, not full flow
data — a peer only counts if the conversation tripped a signature, so the true
fan-out/fan-in is a lower bound. Breadth ranks attention; it does not by itself
prove malice (resolvers, update servers and gateways legitimately talk to many
peers). Pure offline math over the local alert history — **no SSH, no Claude, no
live gateway query**.

- `GET /api/spread?hours=N[&limit=25][&minPeers=8]` → the structured model **plus** rendered Markdown (two ranked tables: fan-out sources and fan-in destinations).
- `GET /api/spread.md?hours=N` → the same report as a downloadable `.md` file.
- `node src/index.ts --spread 168 [--limit 25] [--min-peers 8]` (or `npm run spread`) → print the Markdown to stdout (defaults to a 7-day window so a low-and-slow sweep has room to touch many peers).

## 🧬 Threat-classification breakdown (`GET /api/classify[.md]`, `--classify`)

Every other report pivots on an *entity* (attacker IP, internal host, src→dst
pair) or a *time shape* (beacon, surge, rhythm). This one answers the first
question a SOC lead asks at a glance — **"what is the threat *mix*?"** — by
folding the window over Suricata's own threat taxonomy (the `classification` /
classtype: *"Attempted Administrator Privilege Gain"*, *"A Network Trojan was
Detected"*, *"Detection of a Network Scan"*, policy chatter, and so on). The
Trends view ranks top *categories* (`IDS/IPS`, `Firewall`) — a coarse
source-of-event label — but the fine-grained classification mix has never been
surfaced offline until now.

For each threat class the report rolls up its alert volume and **share** of the
window, its **severity profile** (worst severity, medium-or-worse count, critical
count), its **enforcement posture** (actively blocked vs only detected, and the
resulting block rate), its **breadth** (distinct attacker sources → distinct
internal targets), the dominant signature, and a **recent-vs-older split** so a
class that is *accelerating* (most of its volume in the recent half of the
window) is flagged with a ▲ trend glyph.

Classes are ranked by a **severity-weighted score**, not raw volume — so a small
but dangerous class (a handful of trojan detections) outranks benign chatter
(thousands of policy hits), instead of being buried under it. The sharpest rows
are the **control gaps** (🚩): medium-or-worse classes that were mostly *detected,
not blocked* — exactly where to verify enforcement first.

Honest about its limits: `classification` is optional (firewall blocks carry
none), so those alerts fall back to the event **category** and are marked `~`
rather than dropped; and a low block rate reflects detection-mode sensing as much
as a real enforcement gap. Pure offline math over the local alert history — **no
SSH, no Claude, no live gateway query**.

- `GET /api/classify?hours=N[&limit=25]` → the structured model **plus** rendered Markdown (one table of threat classes, ranked by severity-weighted attention).
- `GET /api/classify.md?hours=N` → the same report as a downloadable `.md` file.
- `node src/index.ts --classify 168 [--limit 25]` (or `npm run classify`) → print the Markdown to stdout (defaults to a 7-day window so the mix reflects more than one shift's chatter).

## 📊 Threat-focus / concentration report (`GET /api/focus[.md]`, `--focus`)

Every other report answers **"*which* ones?"** — it ranks the worst sources,
hosts, pairs, signatures or threat classes. None of them answer the question a
responder asks *before* picking a strategy: **"what is the *shape* of the
distribution?"** A "top 20 sources" table looks identical whether those 20 IPs
are 95% of all traffic (block them, done) or 4% of it (whack-a-mole against a
5,000-host botnet) — and that distinction changes the entire response plan. The
numbers that tell the two apart live *between* the rows, never in them.

This report measures **concentration** across four independent axes — **source
IPs**, **destination IPs**, **signatures** and **threat classes** — from the
stored alert history. For each it computes the share held by the top 1 / 5 / 10
values, the **Pareto point** (the fewest values that cover ≥80% of the volume,
and that count as a fraction of all distinct values), the **Gini coefficient**
(0 = perfectly even … →1 = one value holds everything) and a 0-100 concentration
index, then renders a categorical verdict — `▰ concentrated`, `░ diffuse`,
`▱ moderate` or `● single` — with the raw numbers always shown so you can
overrule the heuristic.

The payoff is an action, not just a description. **Concentrated sources** →
*"block these N IPs to cut 80% of the noise"* (a high-leverage quick win, with a
note on how many are already blocked). **Diffuse sources** → blocking won't
scale; tune rules and rate-limit. **Concentrated destinations** → the attacker
has picked favourites; harden those assets. **A single dominant signature** →
the classic false-positive / tuning tell.

Honest about its limits: concentration describes *where the noise lives*, not how
dangerous it is — pair it with the severity-ranked reports before triaging; and
"diffuse" means diffuse among *alerting* actors only, since a source that never
trips a rule is invisible here. Pure offline math over the local alert history —
**no SSH, no Claude, no live gateway query**.

- `GET /api/focus?hours=N[&limit=8]` → the structured per-axis model **plus** rendered Markdown (a concentration-at-a-glance table plus a top-values table per axis).
- `GET /api/focus.md?hours=N` → the same report as a downloadable `.md` file.
- `node src/index.ts --focus 168 [--limit 8]` (or `npm run focus`) → print the Markdown to stdout (defaults to a 7-day window so the shape reflects more than one shift).

## 🧱 Source-netblock / infrastructure report (`GET /api/netblocks[.md]`, `--netblocks`)

Every other source report ranks or scores *individual* IPs, *pairs* of IPs, or
the *shape* of the IP distribution. None of them looks at the structure one level
*above* the address: the network block it lives in. That gap is exactly where the
most common evasion against per-IP defence hides — **rotation**: a botnet, a
compromised hosting range or a cloud subnet sprays from dozens of neighbouring
addresses, each tripping just a few alerts so none clears a per-IP threshold,
while the *block as a whole* is hammering the perimeter. To a per-IP ranking the
campaign is invisible; rolled up into its `/24` it's a single, obvious, high-leverage row.

This report folds every **external IPv4** source into two CIDR groupings — **`/24`**
(the tight grouping; almost always one operator / one piece of infrastructure) and
**`/16`** (the wide grouping, for spotting a broadly hostile provider / region) —
and ranks the resulting blocks by alert volume. For each block it reports the
total alerts, the **distinct source IPs** (the rotation/coordination signal),
distinct targets and signatures, the block's share of external volume, first/last
seen, a **`⚑ coordinated`** flag (≥3 distinct IPs), and how many of the block's
IPs are *already* `⛔` blocked / `👁` watched / `✅` safelisted — so the "still on
the table" quick win is explicit. Coordinated `/24`s also get a member-IP detail
table so the rotation is visible directly.

The payoff is an action: a coordinated `/24` is a candidate for a **single CIDR
rule in place of N per-IP blocks** that also pre-empts the next address in the
range — **unless** the block carries a `✅` safelisted IP, in which case the report
explicitly warns you to block its IPs individually instead.

Honest about its limits: a `/24` is octet math, not a real allocation boundary
(which follows BGP/whois) — "coordinated" is a strong hint to *look*, not an
automatic block, especially for shared-hosting / CDN ranges. Only external IPv4
sources are aggregated; IPv6 and internal sources are excluded (IPv6 is counted
and reported separately). Pure offline math over the local alert history — **no
SSH, no Claude, no live gateway query**.

- `GET /api/netblocks?hours=N[&limit=20]` → the structured model **plus** rendered Markdown (ranked `/24` and `/16` tables plus member-IP detail for coordinated blocks).
- `GET /api/netblocks.md?hours=N` → the same report as a downloadable `.md` file.
- `node src/index.ts --netblocks 168 [--limit 20]` (or `npm run netblocks`) → print the Markdown to stdout (defaults to a 7-day window so adjacent-IP rotation across days is visible).

## 🩺 Data-coverage / quality report (`GET /api/coverage[.md]`, `--coverage`)

Every other offline report *analyses* the stored alert history and ends with the
same honest disclaimer — the answer is only as good as the data, which is
window-bounded, store-capped, and only as complete as the collector that fed it.
None of them actually **measures** that foundation. This one does. It is a
meta-report that audits the dataset itself rather than the threats in it, and
answers the question you should ask *before* acting on any other report: **"is
this history complete enough that the conclusions hold?"**

It surfaces the three failure modes that silently corrupt every downstream
report and are invisible from the reports themselves:

- **Truncation** — the store keeps at most a fixed number of alerts and evicts
  the oldest once full, so a long look-back reads a *clipped* history and
  "first-seen" / "novelty" / "persistence" quietly understate the past. The
  report flags when the store is at (or near) capacity and when the requested
  window reaches back further than the oldest retained alert.
- **Missing fields** — a report can only rank what was recorded. It measures the
  **completeness** of every field other reports depend on (source/destination IP,
  signature, severity, classification, action), with IP fields' *invalid*
  (present-but-malformed) count broken out, so a hole is named rather than
  inferred from a suspiciously short table.
- **Blind spots** — a collector outage or syslog drop makes the history go quiet,
  and "no alerts" reads as "no activity" when it may be "no *visibility*". The
  report finds the largest **time gaps** between consecutive alerts and flags any
  far longer than the typical inter-arrival as a candidate outage.

It also reports the distinct `severity` / `action` label vocabularies (an empty
or unexpected label is usually a parser regression), Claude-summary and
notification coverage, and rolls everything into a **0-100 health score** and a
categorical grade (`🟢 excellent` / `🟡 good` / `🟠 fair` / `🔴 poor`) — with the
raw numbers always shown so you can overrule the heuristic.

Honest about its own limits: **completeness ≠ correctness** (a present value can
still be mis-parsed), **gaps ≠ outages** (a genuinely quiet network also goes
silent — a flagged gap is a prompt to check the collector, not proof it failed),
and the audit reads the same capped store it audits, so it can see *that* the
store is full but not what was evicted before it looked. Pure offline math over
the local alert history — **no SSH, no Claude, no live gateway query**.

- `GET /api/coverage?hours=N[&limit=6]` → the structured model **plus** rendered Markdown (retention/time-coverage table, per-field completeness, blind-spot gaps, value vocabularies and enrichment coverage).
- `GET /api/coverage.md?hours=N` → the same report as a downloadable `.md` file.
- `node src/index.ts --coverage 168 [--limit 6]` (or `npm run coverage`) → print the Markdown to stdout (defaults to a 7-day window so retention and blind-spot signals reflect more than one shift).

## 🧭 Traffic-direction / exposure report (`GET /api/direction[.md]`, `--direction`)

Every other offline report treats an alert's two endpoints symmetrically — it
ranks the worst *source*, the worst *destination*, or the worst source→dest
*pair*. None of them asks the one question that flips an internal host from
**victim** to **suspect**: *is that host the **target** of the alert, or the
**source** of it?* That distinction is the sharpest compromise signal the data
holds. An external IP tripping a rule against your server is the expected,
all-day perimeter background; one of **your** hosts tripping a rule while
reaching **out** to the internet — or pivoting **sideways** into another internal
host — is the texture of a live compromise (C2 beaconing, exfil, east-west
movement). A symmetric ranking buries those few alerts inside thousands of
inbound ones; a directional split surfaces them as their own bucket with the
responsible internal host named.

Each stored alert is bucketed by the RFC1918 / loopback / link-local status of
its two endpoints into one of five directions, in descending operational
concern:

- **outbound** (internal → external) — the highest-concern bucket: an internal
  host is the one tripping the rule, reaching outward. Candidate C2 / exfil /
  compromised-host beaconing.
- **lateral** (internal → internal) — east-west movement; a foothold probing or
  pivoting to neighbours. Rare in a healthy network, loud when real.
- **inbound** (external → internal) — classic perimeter attacks; the normal,
  high-volume background of an internet-facing gateway. Expected, not benign.
- **external** (external → external) — neither endpoint is yours: spoofed
  sources, transit, or mis-parsed lines. Usually noise, called out as such.
- **unknown** — one or both endpoints missing / unparseable; excluded from the
  verdict so it never inflates a concern bucket.

Per bucket it shows volume and share, distinct sources and destinations, the
blocked-vs-passed disposition split (reusing the efficacy report's classifier)
and pass rate, the severe (≥ medium) count and the loudest signature. A high
pass rate on the **outbound** bucket is the alarm worth the most: the gateway
watched an internal host reach out and *let it through*. It then ranks the
**internal hosts that are sourcing** outbound / lateral alerts — the nearest
thing this dataset has to a "which of my machines is compromised?" list — by
unmitigated outbound volume, with external-destination breadth, lateral-target
count, peak severity, top signature and blocklist / watchlist / safelist flags.

Honest about its limits: **direction is inferred, not observed** — it rests on
RFC1918 classification, so NAT, VPN tunnels, asymmetric routing or carrier-grade
NAT can mislabel a flow; a surprising outbound / lateral hit is a *lead to
verify* (pull the host's egress in the live investigator), not a conviction.
These are IPS **detections**, not full flows — a host beaconing over a channel
that never trips a rule is invisible here. Pure offline math over the local
alert history — **no SSH, no Claude, no live gateway query**.

- `GET /api/direction?hours=N[&limit=15]` → the structured model **plus** rendered Markdown (per-direction table, internal-source candidate-compromise ranking).
- `GET /api/direction.md?hours=N` → the same report as a downloadable `.md` file.
- `node src/index.ts --direction 168 [--limit 15]` (or `npm run direction`) → print the Markdown to stdout (defaults to a 7-day window so outbound/lateral signals reflect more than one shift).

## 🫀 Signature lifecycle / chronic-vs-acute report (`GET /api/lifecycle[.md]`, `--lifecycle`)

Every other report measures a signature by **how much** it fires (tuning,
trends, focus), **who** fires it (persistence, netblock, edges), or **when it was
first seen** (novelty). None measures the **temporal shape** of a signature — how
its alerts are *distributed across the window* — even though that shape is the
best discriminator between two operationally opposite things that look identical
in a volume ranking. A signature firing 500 times spread evenly over a week and
one firing 500 times inside ten minutes have the same volume and the same
top-signature rank, but the first is **background noise to tune out** and the
second is a **discrete event to investigate**. This report tells them apart.

Each signature's alerts are bucketed into equal time slices, and from the
per-bucket counts it computes two orthogonal measures — **coverage** (the share
of slices the signature fired in; high = ever-present) and **burstiness** (a
0..1 normalized dispersion of the counts; 0 = perfectly even, 1 = all in one
slice) — then assigns one of four shapes, in descending investigate-priority:

- **acute** — alerts concentrated into a short burst; a discrete event. Investigate.
- **one-shot** — fired in a single slice only; an isolated blip. Triage.
- **intermittent** — on-and-off, neither steady nor a single spike. Watch.
- **chronic** — steady, broad coverage, low dispersion; background noise. Tune / suppress.

Each row carries the context to act: total volume and per-day rate, peak-slice
share and when it landed, distinct sources / destinations, severity ceiling,
lifespan, and a **💤 dormant** flag for a recurring rule that went silent
mid-window (fixed, rotated away, or a sensor gap). The summary quantifies the
**noise floor** — how much of the firehose is chronic background and therefore
suppressible — and pulls out the loudest acute bursts as the morning's
investigate-first list.

Honest about its limits: **shape is window-relative** (a rule that looks acute
in a 24h window can look chronic in a 7-day one) and depends on the bucket
granularity, which is printed for reproducibility. A "chronic" shape means a rule
fires steadily, **not** that it is benign — cross-check the tuning report's
operator-value evidence before suppressing. Pure offline math over the local
alert history — **no SSH, no Claude, no live gateway query**.

- `GET /api/lifecycle?hours=N[&limit=25][&buckets=N]` → the structured model **plus** rendered Markdown (per-shape roll-up table, per-signature lifecycle ranking).
- `GET /api/lifecycle.md?hours=N` → the same report as a downloadable `.md` file.
- `node src/index.ts --lifecycle 168 [--limit 25] [--buckets N]` (or `npm run lifecycle`) → print the Markdown to stdout (defaults to a 7-day window so chronic vs acute shape reflects more than one shift).

## 🧠 AI analyst-insight digest (`GET /api/insight[.md]`, `--insight`)

Every other offline report mines the **raw IPS telemetry**. This one mines the one
field SecTool spends real money to produce: the **Claude summary** stored on each
processed alert (`StoredAlert.summary`). Until now that analysis evaporated into the
dashboard one alert at a time and was never rolled up. The digest audits the AI
analysis layer in aggregate and answers three questions the raw reports cannot:

1. **Is the AI actually covering the stream?** It splits the window into *AI-backed*
   summaries, non-AI *heuristic fallback* summaries (taken when Claude is
   unreachable / rate-limited / disabled), and *un-analysed* alerts. A high fallback
   or un-analysed share means the dashboard's "AI analysis" is mostly heuristics —
   worth knowing before you trust the verdicts below it.
2. **Where does Claude disagree with the rule?** For every AI-backed alert it
   compares the rule's severity against Claude's re-assessed severity and buckets it
   as **downgraded** (a false-positive / over-noisy-rule signal), **agreed**, or
   **upgraded** (an under-graded rule worth escalating). It then ranks the signatures
   Claude most often downgrades (your *tuning backlog*) and most often upgrades (your
   *escalation backlog*) — the sharpest, most actionable thing the AI layer produces,
   previously invisible.
3. **What is Claude telling you to do?** It normalises and tallies every
   `recommendedActions` entry across the window, so the most-repeated remediation
   rises to the top with the count of distinct alerts and signatures it was advised
   for — a ready-made, frequency-ranked work list. Summaries are also attributed to
   the **model** that produced them, so a silent model swap or a flood of fallbacks
   is visible.

Honest caveats are baked into the output: it audits Claude's *opinions*, not ground
truth (a downgrade is a lead to review, not proof a rule over-fired); re-grading is
computed over AI-backed summaries only (heuristic fallbacks copy the rule severity
and would always read as "agreed"); and alerts processed before summarisation was
enabled show as un-analysed and are excluded from the divergence math. Pure offline
math over the local alert history — **no SSH, no Claude call, no live gateway query**.

- `GET /api/insight?hours=N[&limit=15]` → the structured model **plus** rendered Markdown (coverage · re-grading · FP/escalation candidates · action roll-up · model attribution).
- `GET /api/insight.md?hours=N` → the same digest as a downloadable `.md` file.
- `node src/index.ts --insight 168 [--limit 15]` (or `npm run insight`) → print the Markdown to stdout (defaults to a 7-day window so coverage and re-grading reflect more than one shift).

## 📈 Surge / burst report (`GET /api/surge[.md]`, `--surge`)

Steady background noise is one thing; a sudden **storm** of alerts is another — and
the storms are exactly the events worth a human's attention: a horizontal scan
lighting up a signature hundreds of times in a couple of minutes, a brute-force
hammering a service, a worm or compromised host suddenly going loud, or a misfiring
rule flooding the console. This report compresses a long, flat timeline into the
few *moments that were not normal* and names the driver of each, so the morning
question changes from "scroll 2,000 alerts" to "three storms happened overnight;
here is what drove each."

The method is deliberately robust:

1. Slice the window into fixed-width **buckets** (default 15 min, auto-widened so a
   long window never produces an unbounded number of bins).
2. Establish a **baseline** as the *median* bucket count — median, not mean,
   because the very spikes being hunted would inflate a mean and hide themselves. A
   bucket is a surge only when it clears both an absolute floor (`minCount`, so a
   near-empty window can't manufacture a "spike" out of two alerts) and a relative
   bar (`factor` × baseline).
3. **Merge adjacent surge buckets into episodes** — a storm spanning four
   consecutive buckets is one incident, not four — and attribute each episode to
   its dominant **signature**, **source**, **category**, peak **severity** and
   **block share**, with a *shape* hint (`single src` scanner / `spray` distributed
   brute-force / `internal` lateral-movement).

Unlike [`trends`](#) (a flat histogram that never flags a spike or computes a
baseline), [`rhythm`](#-activity-rhythm-report) (which folds the timeline onto
hour-of-day aggregates, destroying the absolute timeline a burst lives on), and
[`beacon`](#-beaconing--periodicity-report-get-apibeaconmd---beacon) (which scores
*regular* cadence — the opposite of a one-off burst), this report is the only one
that detects **volume-over-time spikes** and explains them. A compact unicode
sparkline of the whole window's volume tops the output. Pure offline math over the
local alert history — **no SSH, no Claude, no live gateway query**.

- `GET /api/surge?hours=N[&limit=25][&bucketMinutes=15][&factor=3][&minCount=5]` → the structured model **plus** rendered Markdown (sparkline + ranked episode table).
- `GET /api/surge.md?hours=N` → the same report as a downloadable `.md` file.
- `node src/index.ts --surge 168 [--limit 25] [--bucket-minutes 15] [--factor 3] [--min-count 5]` (or `npm run surge`) → print the Markdown to stdout (defaults to a 7-day window so a quiet baseline is visible and overnight storms surface).

## 🔌 Service / port-exposure report (`GET /api/ports[.md]`, `--ports`)

Every other offline report pivots on an *entity* (source IP, destination host,
source→dest pair, netblock), a *signature*, a *time axis*, a *direction*, a
*severity magnitude*, or the *enforcement* split. None of them ask the question a
firewall administrator asks first: *which destination **port / service** is being
attacked — and which of my hosts is exposing it?* That is the most directly
**actionable** axis the data holds. Knowing a single IP is loud tells you who to
block; knowing that **port 3389 (RDP)** is your busiest attacked service, exposed
by one internal host and mostly *let through*, tells you what to **close** — a far
more durable fix than chasing scanners, who rotate IPs by the thousand while the
service they hunt for stays put.

The destination port and protocol aren't stored as first-class columns, so the
report **re-parses** them from each alert's raw line using the same flow-tuple /
JSON shapes the live detector understands (`{TCP} 1.2.3.4:51000 -> 10.0.0.5:3389`
or a Suricata JSON `dest_port`). Alerts whose raw line carries no recoverable port
are counted as *unparsed* and never silently dropped. Per attacked port it shows
volume and share, a well-known-port → **service name** mapping (22→SSH, 3389→RDP,
445→SMB, 3306→MySQL …), the dominant protocol, a **⚠️ remote-admin / data-store
exposure flag** for ports that should almost never face the internet, distinct
external attackers and distinct internal hosts exposing it, the blocked-vs-passed
disposition split (reusing the efficacy report's classifier) and pass rate, a
severe (≥ medium) count, and a **severity-weighted score** (reusing the risk
report's weights) used for ranking so a few critical hits outrank a flood of
scans. It then rolls the data up by **internal host**, ranking the hosts that
expose the widest set of attacked ports — your largest attack surface — with
blocklist / watchlist / safelist flags.

Honest about its limits: ports are **re-parsed, not stored** (the *unparsed* count
is shown so low coverage is visible, not mistaken for "few ports attacked"); a
destination port is the *attacked service* only when the destination is one of
your hosts, so the exposing-host roll-up counts internal destinations only; these
are IPS **detections**, not full flows — a port scanned without tripping a rule is
invisible. Pure offline math over the local alert history (plus blocklist /
watchlist / safelist membership) — **no SSH, no Claude, no live gateway query**.

- `GET /api/ports?hours=N[&limit=20]` → the structured model **plus** rendered Markdown (per-port table with service names / risk flags, internal-host attack-surface ranking).
- `GET /api/ports.md?hours=N` → the same report as a downloadable `.md` file.
- `node src/index.ts --ports 168 [--limit 20]` (or `npm run ports`) → print the Markdown to stdout (defaults to a 7-day window so the attacked-service mix reflects more than one shift).

## 🛰️ Scan-shape / reconnaissance-pattern report (`GET /api/scan[.md]`, `--scan`)

The fan-out report ranks a source by how many *hosts* it touches but is blind to
ports; the port-exposure report ranks the *service* under fire but pivots on the
port, not the attacker. Neither answers the question that decides your response:
***how* is each attacker probing — sweeping one service across the whole network,
or enumerating one host end-to-end?* The shape of a probe is one of the most
diagnostic things the IPS stream holds, because each classic recon pattern demands
a different fix:

- **↔ Horizontal** — *few ports, many hosts*: hunting one service everywhere
  (SMB/445 across the subnet). Fix at the **edge for the whole subnet**, not the
  one host that alerted.
- **↕ Vertical** — *many ports, few hosts*: enumerating one **target's** whole
  surface. That box is being singled out — harden and watch it.
- **▦ Sweep** — *many of both*: full-spectrum reconnaissance (a mass scanner /
  toolkit cataloguing the network). The broadest and noisiest.
- **• Targeted** — *narrow*: exploitation against a known service, or noise — not
  recon-shaped, never ranked above genuine scanning.

For every source it folds the windowed alerts and computes **host breadth**
(distinct `dstIp`) × **port breadth** (distinct destination ports, re-parsed from
the raw line via the same parser the port-exposure report uses), classifies the
shape against tunable thresholds (`≥3` hosts / `≥3` ports = "many" by default),
and ranks by total breadth — for a *recon* report reach is the signal, so a loud
info-level sweep ranks above a quiet exploit. It flags **internal** sources that
are themselves scanning (a lateral-movement / compromise tell, not an inbound
attacker), the blocked-vs-passed split (recon that is *let through* is succeeding),
high-risk admin/data-store ports, and blocklist / watchlist / safelist membership.
A companion **most-hunted services** roll-up ranks ports by how many *distinct
sources* converge on them — the single service most attackers are after.

Honest about its limits: probe **shape is a heuristic** over the host/port
thresholds (the raw counts are always shown so the call can be second-guessed);
ports are **re-parsed, not stored**, so port breadth is a lower bound when alerts
omit the flow tuple (host breadth is unaffected); these are IPS **detections**,
not full flows, so a surgical scanner can read as "targeted". Pure offline math
over the local alert history (plus blocklist / watchlist / safelist membership) —
**no SSH, no Claude, no live gateway query**.

- `GET /api/scan?hours=N[&limit=20][&minHosts=3][&minPorts=3]` → the structured model **plus** rendered Markdown (per-source shape table, most-hunted-services ranking).
- `GET /api/scan.md?hours=N` → the same report as a downloadable `.md` file.
- `node src/index.ts --scan 168 [--limit 20] [--min-hosts 3] [--min-ports 3]` (or `npm run scan`) → print the Markdown to stdout (defaults to a 7-day window so a low-and-slow scanner has time to show breadth).

## 🔎 Port-signature scanner-fingerprint report (`GET /api/portsig[.md]`, `--portsig`)

The scan-shape report classifies a probe by the *counts* of distinct hosts and
ports; the port-exposure report ranks the single port under fire. Neither names
the **intent** behind a port combination — yet a database raid
(`3306·5432·1433·6379·27017`) and a web-stack scan (`80·443·8080·8443·8000`) look
identical to a count. The *set* of destination ports a source touches is one of the
most diagnostic things the IPS stream holds, because attacker toolkits have
characteristic port signatures, and knowing *which* toolkit is probing changes the
response:

- **🧨 SMB/RDP lateral movement** — `445·139·135·3389·WinRM`: ransomware foothold / east-west movement.
- **🗄️ Exposed-database raid** — `3306·5432·1433·6379·27017·9200·11211`: pull these off the edge **now**.
- **🤖 IoT-botnet recruitment** — `23·2323·7547·ADB`: Mirai-class device sweep.
- **🌐 Web-application recon**, **✉️ mail / relay probing**, **📞 VoIP toll-fraud**, **☁️ container / cloud-API probing**, **🕳️ open-proxy hunting**, **🔒 VPN/tunnel discovery**, **📡 UDP amplification vectors**, and more.

For every source it recovers the set of distinct destination ports it probed (the
same parser the port-exposure / scan-shape reports use) and matches it against a
curated library of toolkit signatures, attributing the source to the toolkit it
**best** matches (most signature ports hit, ties broken toward the tighter
signature). A source that probed several ports matching no known toolkit is
surfaced as a **novel combination** (possible new tooling); a single-port source is
set aside as not fingerprintable. It flags **internal** hosts wearing an attacker
fingerprint (a lateral-movement / compromise tell, not an inbound scan), the
blocked-vs-passed split (a dangerous toolkit *let through* is the headline), and
blocklist / watchlist / safelist membership. A companion **active-toolkits**
roll-up ranks each toolkit by how many distinct sources are running it against you —
the campaign view the per-source table can't give.

Honest about its limits: attribution is a **heuristic** over port-sets that
deliberately overlap (port 22 is in both lateral-movement and remote-admin) — a
source is filed under its *best* match and the matched ports are always shown so the
call can be second-guessed; ports are **re-parsed, not stored**, so a source's
port-set is a lower bound; these are IPS **detections**, not full flows, so a
surgical single-service tool can read as not-fingerprintable. Pure offline math over
the local alert history (plus blocklist / watchlist / safelist membership) — **no
SSH, no Claude, no live gateway query**.

- `GET /api/portsig?hours=N[&limit=20][&minMatch=2]` → the structured model **plus** rendered Markdown (active-toolkits roll-up, per-source fingerprint table, novel-combination table).
- `GET /api/portsig.md?hours=N` → the same report as a downloadable `.md` file.
- `node src/index.ts --portsig 168 [--limit 20] [--min-match 2]` (or `npm run portsig`) → print the Markdown to stdout (defaults to a 7-day window so a slow toolkit has time to reveal its full port-set).

## 🔌 Source-port fingerprint / tooling-artifact report (`GET /api/srcports[.md]`, `--srcports`)

Every other report pivots on the *destination* side of the flow — which host,
which service, which port is under fire. None of them look at the **source port**
the attacker dialled *from*, yet that field carries a signal nothing else captures:
*is this a real client stack or a packet-crafting tool — and do several unrelated
IPs share the same fixed source port (one toolkit, many hands)?*

- A healthy client OS picks a fresh, effectively-random **ephemeral** source port
  (Linux 32768–60999, Windows 49152–65535) per connection, so hundreds of alerts
  show hundreds of distinct high-numbered ports — **high entropy**.
- A **mass-scanning tool** (zmap, masscan, many bespoke scanners) commonly pins a
  *single fixed* source port for its whole run for speed and stateless
  reply-matching. A source firing 400 alerts all from `:61000` is not a browser —
  it is a tool, and that port value is a **fingerprint**.
- A **privileged** source port (`< 1024`) on inbound attack traffic is abnormal for
  a real client (those need root/raw sockets) and hints at **spoofing, reflection,
  or hand-rolled tooling**.

For every source it recovers each alert's source port from the raw line (the same
flow-tuple / JSON parser the port-exposure report uses, here reading the *source*
side) and computes the **distinct source ports**, the **normalised Shannon entropy**
of their distribution (0 = one fixed port, 1 = uniform spread), the **dominant
port and its share**, and the **privileged / ephemeral** shares. Each source is
classified **🔧 fixed** (one dominant port — classic tool artifact), **🎯 clustered**
(a small reused set — semi-automated or a NAT pool), or **🎲 varied** (broad
ephemeral spread — normal stack), and sources rank most-tool-like first. A
companion **shared-fingerprint** roll-up surfaces source ports that are the
dominant dial-out port for *more than one* distinct IP — a cross-source artifact
that points at the same tool / launch script (often the same operator) behind
otherwise-unrelated addresses, which no destination-pivoted report can see.

Honest about its limits: source ports are **re-parsed, not stored**, so every
figure is a lower bound drawn from alerts that still carried a flow tuple or
`src_port` field; **low volume is not a fingerprint** (a 4-alert floor keeps
coincidence out of the "tool" verdict, and raw counts are always shown); **NAT**
can make many hosts share a source port over time, so attribution is to the
address SecTool saw; these are IPS **detections**, not full flows. Pure offline
math over the local alert history (plus blocklist / watchlist / safelist
membership) — **no SSH, no Claude, no live gateway query**.

- `GET /api/srcports?hours=N[&limit=20][&minAlerts=4]` → the structured model **plus** rendered Markdown (per-source fingerprint table, shared-fingerprint roll-up).
- `GET /api/srcports.md?hours=N` → the same report as a downloadable `.md` file.
- `node src/index.ts --srcports 168 [--limit 20] [--min-alerts 4]` (or `npm run srcports`) → print the Markdown to stdout (defaults to a 7-day window so a slow tool has time to reveal its fixed-port habit).

## 🎯 Attack-surface-by-service-class report (`GET /api/services[.md]`, `--services`)

The port-exposure report ranks *individual* destination ports (3389, 445, 3306 …)
and the asset report ranks *individual* internal hosts. Both are one level too low
for the question a defender actually briefs upward: **what *kind* of service is
under attack, and which crown-jewel classes are still being let through?** "Port
3389 is hot" means nothing to a risk owner; "**remote-access services are the #1
attacked surface and 18% of that traffic was allowed through**" is a decision.

This report rolls the raw destination ports up into curated **service classes** —
🖥️ Remote Access, 🌐 Web, 🗄️ Database, 📁 File Sharing, ✉️ Mail, 🔐 Directory/Auth,
🔒 VPN, 📡 Network/Infra, 🏭 ICS/IoT/Camera, 🕳️ Proxy/Anonymiser, and a
💣 Known-Bad/Exploit bucket — so `22+23+3389+5900` collapse into one **Remote
Access** row. Two things this altitude captures that no per-port report can:

- **ICMP / layer-3 traffic.** Every other destination report keys off a destination
  *port* and therefore silently drops ICMP entirely — yet a flood of ICMP
  echo/redirect is classic host-discovery recon. Here **ICMP is a first-class
  service class**, so that reconnaissance is finally visible.
- **"Should-never-be-exposed" exposure.** Six classes (remote-access, database,
  file-share, directory, ICS/IoT, exploit) should never be internet-facing. The
  report flags every such class whose alerts the gateway **let through** (passed,
  not blocked) and lifts the specific exposed endpoints into a second,
  **close-these-first worklist**.

For each class it computes the **alert volume and share**, a **severity-weighted
score**, **distinct attacking sources** and **internal targets**, the
**blocked/passed/unknown** split and resulting **pass rate**, the **busiest concrete
ports** inside the class, and the **top signature**. Classes rank most-dangerous
first. Honest about its limits: ports are **re-parsed, not stored** (figures are a
lower bound from alerts that still carried a flow tuple or `dest_port` field);
**class membership is heuristic** (the per-class top-ports column lets the mapping
be sanity-checked); a **passed** alert marks *exposure*, not a successful breach;
these are IPS **detections**, not full flows. Pure offline math over the local
alert history — **no SSH, no Claude, no live gateway query**.

- `GET /api/services?hours=N[&limit=20]` → the structured model **plus** rendered Markdown (service-class table + exposed-endpoint worklist).
- `GET /api/services.md?hours=N` → the same report as a downloadable `.md` file.
- `node src/index.ts --services 168 [--limit 20]` (or `npm run services`) → print the Markdown to stdout (defaults to a 7-day window so the full service-class mix has time to accumulate).

## 📡 Signature-audience / spray-vs-snipe report (`GET /api/audience[.md]`, `--audience`)

The threat-classification report tells you the threat *mix*, the tuning report
ranks the noisiest *rules* by volume, and the concentration report measures the
*shape of the whole distribution*. None of them answer the single sharpest triage
question the IPS stream holds about each rule that fired: ***who* is behind it —
is this signature being *sprayed* at me by a diffuse crowd of unrelated sources
(internet background radiation I can down-prioritise) or *sniped* by one or two
actors at a handful of my hosts (a focused, real signal that raw volume buries)?***
A rule firing 10 000 times from a single IP and one firing 10 000 times from
8 000 IPs are indistinguishable to a volume ranking, yet the first is one attacker
and the second is the whole internet.

For every signature it folds the windowed alerts and computes its **source
breadth** (distinct `srcIp`), a diversity-weighted **effective source count**
(inverse-Simpson `1 / Σ shareᵢ²`, which discounts a long tail of one-shot sources
so a crowd dominated by one actor reads as "few"), the **dominant source's share**,
and its **target breadth** (distinct `dstIp`). It then classifies each signature
from the two diffusion axes against tunable thresholds (`≥5` effective sources /
`≥5` targets = "many" by default):

- **🌐 Spray** — *many sources × many targets*: internet background radiation.
  Loud, ubiquitous, low-signal — collapse / down-prioritise / suppression-tune.
- **🐝 Swarm** — *many sources × few targets*: a crowd converging on one box (a
  popular target, or a botnet tasked specifically at you).
- **🛰 Scan** — *few sources × many targets*: a small number of actors sweeping
  wide (cross-reference the scan-shape report).
- **🎯 Targeted** — *few sources × few targets*: a focused, hands-on signal — the
  alert most likely to be a real intrusion, and the one volume ranking buries.

The primary table ranks signatures by **alert volume** (what fills the console)
but annotates each with its quadrant and effective-source count, so a loud row
reads at a glance as "spray → tune it away" or "targeted → investigate". Two
companion roll-ups then pull the extremes the volume ranking hides: **sharpest
targeted signatures** (the buried, low-volume snipes, ranked by severity) and
**top spray / tuning candidates** (the loudest background radiation). It flags
signatures fired *by internal sources* (a compromise / lateral-movement tell) and
the blocklist / watchlist / safelist status of each dominant source.

Honest about its limits: the diffusion **shape is a heuristic** over the
source/target thresholds (raw counts and the effective-source number are always
shown so the call can be second-guessed); **effective sources ≠ distinct sources**
(a crowd dominated by one actor is correctly read as concentrated, with the
dominant share shown alongside); these are IPS **detections**, not full flows, so
every source count is a lower bound. Pure offline math over the local alert history
(plus blocklist / watchlist / safelist membership) — **no SSH, no Claude, no live
gateway query**.

- `GET /api/audience?hours=N[&limit=25][&minSources=5][&minTargets=5]` → the structured model **plus** rendered Markdown (per-signature audience table, sharpest-targeted and top-spray roll-ups).
- `GET /api/audience.md?hours=N` → the same report as a downloadable `.md` file.
- `node src/index.ts --audience 168 [--limit 25] [--min-sources 5] [--min-targets 5]` (or `npm run audience`) → print the Markdown to stdout (defaults to a 7-day window so a diffuse, low-and-slow spray has time to show breadth).

## 🚫 Block-effectiveness / post-block recidivism audit (`GET /api/recidivism[.md]`, `--recidivism`)

Every IP SecTool (or you) blocks at the firewall is stamped with a *block time*.
No other report reads that timestamp — yet it answers the one question that proves
an enforcement action worked: **after I blocked this IP, did the traffic actually
stop?** The efficacy report scores the gateway's per-alert disposition across the
whole stream but has no notion of *when* a source was blocked; the persistence /
recurrence reports rank repeat offenders but treat a source we've *already
contained* identically to a fresh enforcement gap.

This audit takes every IP on the blocklist, folds the windowed alerts whose source
is that IP, and splits them on the block timestamp — `time < at` is the pre-block
activity that *led to* the block, `time >= at` is the **recidivism** signal. The
post-block alerts are then split by the gateway's own disposition into a three-way
verdict:

- **🟢 clean** — no alerts since the block: it held (or the attacker moved on).
- **🟡 stubborn** — re-tripping rules but *every* post-block hit was dropped:
  enforcement is working, the attacker just won't quit. Noise, not exposure.
- **🔴 leaking** — at least one post-block alert was *let through*: the block
  exists in the list but traffic is still reaching you. The headline finding — the
  ipset/iptables DROP may not have applied, the rule may be detection-only, or the
  block was never pushed. Re-apply it and confirm enforcement.

A separate **cleanup roll-up** flags *stale* blocks — IPs silent for the entire
window despite predating it — as safe candidates to retire so the active blocklist
(and the ipset behind it) stays lean. Contradictory controls (an IP that is both
blocked and marked *safe*) are surfaced too.

Honest about its limits: alerts are matched to a block by **source address**
(blocks target attacker sources); these are IPS **detections**, not full flows, so
an *effective* firewall block produces no detections and correctly reads as
**clean** ("clean" = "no detections since the block"). The block timestamp is not
windowed (every current block is audited regardless of age), but post-block
*activity* older than the look-back can be missed. Pure offline math over the local
alert + block history (plus watchlist / safelist membership) — **no SSH, no Claude,
no live gateway query**.

- `GET /api/recidivism?hours=N[&limit=30]` → the structured model **plus** rendered Markdown (per-block recidivism table + stale-block cleanup roll-up).
- `GET /api/recidivism.md?hours=N` → the same report as a downloadable `.md` file.
- `node src/index.ts --recidivism 168 [--limit 30]` (or `npm run recidivism`) → print the Markdown to stdout (defaults to a 7-day window so a slow re-offender has time to show post-block activity).

## ⏱️ Detection-to-mitigation latency / Mean-Time-To-Block (`GET /api/mttb[.md]`, `--mttb`)

The recidivism audit reads each block's timestamp to ask the *post*-block question
("did the traffic stop?"). This report reads the very same timestamp to ask the
opposite, *pre*-block one that nothing else answers: **once an attacker first
showed up in my logs, how long did it take me to actually block them — and how
much got through during that gap?** Detection-to-mitigation latency is to blocking
what MTTR is to incident response: two SOCs can block the exact same attackers and
have wildly different real-world exposure depending on how fast each block landed.

For every IP whose block was applied inside the window it scans the **entire**
stored history for that source (reaching back past the window to find the *first*
sighting the latency is measured from), then grades the gap **latency = block time
− first alert**:

- **🟢 fast** — latency ≤ the fast threshold (default 5 min): containment was
  effectively immediate; little or nothing landed.
- **🟡 moderate** — latency ≤ the slow threshold (default 60 min).
- **🔴 slow** — latency above the slow threshold: the source attacked for a
  meaningful stretch before being contained — and if anything *passed* in that
  window, that exposure was real, not theoretical.
- **⚪ no-lead-up** — no pre-block alert in the store: a proactive (manual /
  threat-intel / first-packet reactive) block, or a source whose early history has
  aged out of the capped store. Reported separately and **excluded from the MTTB**
  so they don't flatter it as "instant".

Sources are ranked **slowest-latency first** — for a responsiveness report the
biggest gaps are the finding. A headline stat block reports mean/median/fastest/
slowest MTTB and the total lead-up alerts the gateway **let through before any
block existed** (real exposure during the gap).

Honest about its limits: latency is a **lower bound** (the rotating store can drop
an old source's earliest alerts, so the true gap may be larger); these are IPS
**detections**, so "first seen" is first *detected* activity, not first contact;
alerts are matched to a block by **source address**; and the number is only as
accurate as the recorded block timestamp. Pure offline math over the local alert +
block history (plus watchlist / safelist membership) — **no SSH, no Claude, no live
gateway query**.

- `GET /api/mttb?hours=N[&limit=50][&fastMins=5][&slowMins=60]` → the structured model **plus** rendered Markdown (latency stat block + per-block latency table).
- `GET /api/mttb.md?hours=N` → the same report as a downloadable `.md` file.
- `node src/index.ts --mttb 168 [--limit 50] [--fast-mins 5] [--slow-mins 60]` (or `npm run mttb`) → print the Markdown to stdout (defaults to a 7-day window so recent enforcement actions are graded with their lead-up).

## 🔍 Safelist / allowlist risk audit (`GET /api/safelist-audit[.md]`, `--safelist`)

Every other audit in SecTool points at the **deny side** of the controls —
recidivism and hygiene at the blocklist, suppaudit at the suppression rules, noise
at de-dup candidates. Nothing audits the **allow side**. The safelist (see
`store/safelist.ts`) is your set of external IPs vetted as benign — a vendor CDN, a
monitoring service, a sanctioned scanner. Marking an IP safe **removes it from
host-risk scoring and shields it from any auto-blocking**: a silent, powerful trust
grant. A safelisted address that later turns hostile is invisible to every
risk-ranked report (its score is suppressed) and immune to reactive blocking — yet
the IPS keeps *detecting* its traffic, because the safelist changes scoring, not
ingestion. That detection stream is exactly the evidence this audit reads.

For every safelist entry it folds the windowed alerts on that IP and — the axis no
other report reads — splits them on the entry's **vetting timestamp** (`at`):
`time < at` is **pre-safelist** context (often the noise the entry was created to
silence), `time >= at` is the **post-safelist** signal that drives a verdict:

- **🔴 dangerous** — post-safelist alerts at high/critical (or sustained medium):
  the trust decision is demonstrably wrong. A vetted-benign IP is attacking you
  while excused from scoring and shielded from blocking — the headline finding.
- **🟠 suspect** — post-safelist alerts at medium, or a notable low/info volume:
  the safelist is silencing something worth a glance.
- **🟢 benign** — little or no post-safelist activity: the vetting still holds.
- **· dormant** — no activity this window: a stale prune candidate.

A **conflict** flag marks any IP that is *both* safelisted and blocklisted (a
contradictory allow+deny curation), and the report tallies the medium-or-worse
alerts the safelist hid from risk scoring — the blind spot the allowlist creates.

Honest about its limits: the safelist suppresses *scoring*, not *ingestion*, so a
"dangerous" verdict is a prompt to *look* (a real vendor can still trip a noisy
rule), not an automatic un-safelist; matching is **exact-IP** (no CIDR); and the
vetting time is not windowed, but post-vetting activity older than the look-back can
be missed. Pure offline math over the local alert + safe / block / watch / triage
stores — **no SSH, no Claude, no live gateway query**.

- `GET /api/safelist-audit?hours=N[&limit=100]` → the structured model **plus** rendered Markdown (verdict-ranked entry table + dormant prune roll-up).
- `GET /api/safelist-audit.md?hours=N` → the same report as a downloadable `.md` file.
- `node src/index.ts --safelist 168 [--limit 100]` (or `npm run safelist`) → print the Markdown to stdout (defaults to a 7-day window so a slow-turning vendor IP has time to reveal post-vetting activity).

## ⛔ Block-recommendation / candidate-blocklist worklist (`GET /api/blockplan[.md]`, `--blockplan`)

Every enforcement report in SecTool points at a control that already **exists** —
efficacy at per-*signature* gaps, recidivism at whether a **blocklist** entry held,
hygiene at which existing blocks to *prune*, safelist at the **allow** side. None
produces the single most operational artefact a defender wants from an alert
stream: a **ranked, copy-pasteable list of new IPs to block**, with an honest
estimate of what each block buys. A threat leaderboard (risk / focus) ranks danger
but happily re-lists addresses you have already blocked, already vetted safe, or
your own internal hosts — none of which belongs on a "block these next" worklist.
This is the **add** side of the blocklist lifecycle, the mirror of hygiene.

For every **external, routable** source that is **not already blocklisted and not
safelisted**, it folds the windowed alerts into a severity-weighted **impact
score** (info=1 · low=3 · medium=9 · high=27 · critical=81), counts the distinct
internal hosts it reaches (hitting your assets outranks banging on a closed port),
and assigns a one-word recommendation:

- **⛔ block** — high/critical reaching an internal host, sustained severe (≥ medium)
  volume, or a high impact score. The clear-cut worklist.
- **🤔 consider** — medium severity, a notable score, or broad host reach (a scanner).
  Worth a human glance before an edge block.
- **👁 monitor** — low/info noise only; never recommended (a watchlist candidate instead).

The crucial honesty axis is **preventability**: a source-level block drops
*everything* at the edge, but the IPS may already drop some of it at the signature
level. So the report separates the **let-through** alerts a block would *newly*
prevent from the traffic already being dropped, and the headline sums only the
genuine gain. **Already-blocklisted**, **safelisted**, and **internal** sources are
deliberately excluded (the action is taken, vetted benign, or a compromise to
isolate respectively) — each count is surfaced, never silently dropped — and a
block-tier source already on the **watchlist** is flagged as the cleanest possible
promotion. It is a **recommendation engine, not an actuator**: it never blocks
anything (reactive/auto blocking lives in `respond/*`). Pure offline math over the
local alert + block / safe / watch / triage stores — **no SSH, no Claude, no live
gateway query**.

- `GET /api/blockplan?hours=N[&limit=30&minAlerts=2]` → the structured model **plus** rendered Markdown (copy-paste worklist + impact-ranked candidate table + per-source detail).
- `GET /api/blockplan.md?hours=N` → the same report as a downloadable `.md` file.
- `node src/index.ts --blockplan 168 [--limit 30]` (or `npm run blockplan`) → print the Markdown to stdout (defaults to a 7-day window so a low-and-slow attacker accrues enough impact to rank).

## 🚧 Auto-block threshold simulator / preventable-volume curve (`GET /api/autoblock[.md]`, `--autoblock`)

`blockplan` answers *which IPs* to block; this answers the question one level up —
**at what volume should an auto-block fire at all?** A threshold of 1 blocks every
source the instant it trips a rule (maximal prevention, an exploding firewall table
full of one-shot scanners and a real false-positive risk); a threshold of 50 only
ever stops the relentless hammerers (tiny blast radius, but a mountain of mid-volume
noise gets through). The right answer is **deployment-specific** — it depends on the
actual shape of your source-volume distribution, which only your stored history
knows.

This report draws that curve. Over the candidate population — every **external,
routable, non-safelisted** source in the window — it sweeps a ladder of thresholds
`N` (default `1,2,3,4,5,7,10,15,20,30,50,100`) and, for each: **sources blocked**
(the cost — every one is a firewall entry and a potential false positive),
**alerts prevented** = Σ `max(0, alerts − N)` (the noise a block removes, since it
fires *on* the N-th alert and everything after is dropped at the edge), **prevented
%**, **leverage** (prevention per block — efficiency), and how many blocked sources
ever sent medium-or-worse traffic. It then recommends the **knee** of the curve —
the threshold nearest the ideal corner of *(0 blocks, 100% prevented)* — and lists
exactly which sources that policy would block, flagged with their current control
state (a source it would block that you have **already** blocklisted is confirmation
the threshold is calibrated; a brand-new one is a candidate; a **watchlisted** one
is the cleanest possible promotion).

It is a **counterfactual on fixed arrivals**: it replays the alerts that landed and
assumes the attacker keeps the same source IP — a rotator defeats any volume
threshold, so prevention is an upper bound for rotators and an honest estimate for
the commodity scanners that dominate the volume. **One-shot sources** (seen once)
are structurally unreachable by any threshold ≥ 2 and their count is surfaced;
**safelisted and internal** sources are excluded from candidacy (you never
auto-block a vetted-benign IP or one of your own hosts). Pure offline math over the
local alert + block / safe / watch stores — **no SSH, no Claude, no live gateway
query**.

- `GET /api/autoblock?hours=N[&limit=20&thresholds=1,2,5,10]` → the structured model **plus** rendered Markdown (swept threshold curve + would-be-blocked source table).
- `GET /api/autoblock.md?hours=N` → the same report as a downloadable `.md` file.
- `node src/index.ts --autoblock 168 [--limit 20] [--thresholds 1,2,5,10]` (or `npm run autoblock`) → print the Markdown to stdout (defaults to a 7-day window so the source-volume distribution has time to take shape).

## 🎚️ Priority-inversion / IDS-urgency-vs-enforcement audit (`GET /api/priority[.md]`, `--priority`)

Suricata stamps every alert with a numeric **priority** (`[Priority: 1]` …, where
**1 is the most urgent** and the number climbs as urgency falls) — the engine's own
verdict on how serious a detection is, set by the rule author and the classtype map.
That field is upstream of, and finer-grained than, the single five-rung `severity`
ladder SecTool derives from it. Every *other* enforcement report (the IPS
enforcement-gap, block-worklist, recidivism and MTTB reports) reasons in terms of
that derived **severity**; none reads the raw Suricata **priority**, and none asks
the first question a tuning engineer asks about enforcement quality: *is the
gateway's block decision actually correlated with the engine's urgency?*

In a healthy posture **block rate falls as the priority number climbs** — the
most-urgent band (P1) is blocked hardest, routine policy chatter (P3/P4) is mostly
just logged. **Priority inversion** is the dangerous opposite: urgent P1/P2 traffic
*passed* while low-priority noise is *blocked* — the classic shape of an IPS that
drops chatty low-value signatures inline while the scariest categories sit in
alert-only mode. Volume- and severity-pivoted reports hide it, because the *count*
of blocks can look healthy while the *worst* events are the ones escaping.

For every alert it **re-parses the Suricata priority from the raw line** (the same
`[Priority: N]` bracket / JSON `priority` shapes the detector reads — the value is
*not* a stored column, so this mirrors how the port reports recover ports) and
crosses it against the gateway disposition (**blocked** / **passed** / **unknown**,
using the shared `classifyDisposition`). It then produces three layers: a
**priority × enforcement matrix** (one row per band with its block rate and reach),
the **inversion headline** — urgent-band block rate vs routine-band block rate and
an **Inversion Index** ∈ `[-1, 1]` (`urgentBlockRate − routineBlockRate`; positive
is healthy, **negative is true inversion**, near-zero is a flat posture that ignores
urgency) — and the **worklist**: the top **sources** and top **signatures** behind
urgent-but-passed alerts, with urgent traffic that reached an *internal* asset
flagged hardest.

Honest about its limits: priority is **re-parsed, not stored** (every figure is
drawn from alerts that still carried a `[Priority: N]` bracket or JSON `priority`
field, and the priority-bearing count is always shown); **"passed" means "not
enforced inline"**, which is a gap only when a block was expected — a detection in
IDS/alert mode is *meant* to be logged, not dropped, so the report surfaces the
shape without assuming intent; unknown-action alerts are counted but **never inflate
a block rate**; these are IPS **detections**, not full flows. Pure offline math over
the local alert history (plus blocklist / watchlist / safelist membership) — **no
SSH, no Claude, no live gateway query**.

- `GET /api/priority?hours=N[&limit=20][&urgentMax=2]` → the structured model **plus** rendered Markdown (priority × enforcement matrix + source/signature worklists).
- `GET /api/priority.md?hours=N` → the same report as a downloadable `.md` file.
- `node src/index.ts --priority 168 [--limit 20] [--urgent-max 2]` (or `npm run priority`) → print the Markdown to stdout (defaults to a 7-day window so a representative urgency-vs-enforcement mix accumulates).

## 📋 Morning security briefing / SITREP (`GET /api/briefing[.md]`, `--briefing`)

SecTool has grown a deep catalogue of sharp, single-purpose reports, but none of
them **composes**: an operator returning in the morning has to know which reports
to run, run several, and stitch the headlines together in their head. This is the
capstone that does it for them — the daily **SITREP** every SOC opens first,
answering, in order, *what changed, how bad is it, and what do I do first* — then
carrying the supporting detail underneath. It is deliberately **not** another
analytic lens; it is a **consolidator**, and it works in three layers:

- **Executive KPIs (self-computed).** A compact scorecard — total alerts, severe
  (medium+) alerts, gateway **block rate**, **unblocked high/critical** exposure,
  active sources, an unmitigated **risk weight** (Σ severity-weight × disposition-
  factor, the same weighting `risk.ts` uses), and **new sources**. Every KPI is
  paired with the **same KPI over the immediately preceding window of equal
  length**, yielding a trend arrow and a percent change — because *is today worse
  than yesterday?* matters more than any absolute.
- **Prioritised action items (self-synthesised).** A deduplicated, severity-ranked
  to-do list so the briefing is opinionated, not just descriptive: **🔴 URGENT** —
  a *safelisted* (vetted-benign) IP firing severe alerts (a trusted address
  behaving badly is the worst surprise); **🟠 HIGH** — sources landing **unblocked
  high/critical** alerts (active threats reaching your hosts unblocked); **🟡
  MEDIUM** — loud, persistent, un-blocked, un-safelisted repeat offenders. Each
  item names the IP, cites the evidence, and surfaces block/watch/safe membership
  so an already-handled IP isn't re-flagged.
- **Bundled detail (composed).** The full Markdown of the "morning essential"
  reports (risk → efficacy → blockplan → escalation → novelty → backlog by
  default, selectable via `sections`) appended under a table of contents, each
  guarded so one failing builder degrades to a noted stub instead of breaking the
  whole briefing.

Unlike the AI digest (`digest` / `insight`, which call Claude and a Discord
webhook), the briefing is **pure, deterministic, offline** — no model, no network
— so it runs identically anywhere, including a cron or an air-gapped review. Pure
in-memory math over the local alert + block / watch / safe stores and the existing
offline builders — **no SSH, no Claude, no live gateway query**.

- `GET /api/briefing?hours=N[&limit=15&sections=risk,efficacy,...]` → the structured model (KPIs + trend + action items + bundled sections) **plus** rendered Markdown.
- `GET /api/briefing.md?hours=N` → the same briefing as a downloadable `.md` file.
- `node src/index.ts --briefing 24 [--limit 15] [--sections risk,blockplan]` (or `npm run briefing`) → print the Markdown to stdout (defaults to a 24-hour window — the SITREP you open in the morning).

## 🔑 Credential-attack / brute-force report (`GET /api/bruteforce[.md]`, `--bruteforce`)

Every other report treats the alert stream *generically* — it ranks a source by
breadth, a signature by noise, a window by shape, the gateway by enforcement. The
classification report rolls the whole taxonomy into a *mix*, but a percentage
("12% credential access") never tells you ***which* login surface is under fire,
how hard, from how many sources, and whether the guesses are reaching the
service.** This report drills into the single attack class that matters most to
almost every threat model — *someone trying to authenticate as someone they are
not* — because the response is so cheap and so specific (MFA, lockout,
rate-limit, restrict the source), and the **shape** of the attack tells you which
to reach for:

- **🔨 Brute-force / stuffing** — *many attempts concentrated on one (or few)
  hosts*: a dictionary / credential-stuffing run against a single login. **Lock
  the host down and rate-limit it.**
- **💦 Password spray** — *a few attempts each, fanned across many hosts*: trading
  depth for breadth to stay under per-account lockout. Per-host lockout never
  trips; the tell is the **fan-out** and the fix is **org-wide** (MFA, disable
  legacy auth, alert on the pattern).
- **🕸 Distributed** — *one target, many sources*: a botnet sharing the guess work
  to dodge IP blocks. The tell is the **source count** on a single victim —
  **rate-limit the service**, not just the addresses.
- **• Probe** — *low volume*: opportunistic noise, surfaced for completeness,
  never ranked above a real run.

Credential-bearing alerts are identified two complementary ways (and which fired
is shown, for honesty about the heuristic): by **signature semantics** (the
signature / classification / raw line matches a curated credential vocabulary —
brute-force, login, auth, password, kerberos, hydra, "privilege gain", …, which
also catches app-layer logins like a WordPress flood on an odd port) **or** by
**target service** (the destination port — re-parsed from the raw line via the
same parser the port-exposure report uses — is a known authentication service:
SSH/22, RDP/3389, SMB/445, FTP/21, the database and mail-auth ports, …). The
qualifying alerts are folded per **target login surface** (`dstIp` × service:
where the guessing lands, how hard, from how many sources, and how much is *let
through*) and per **attacking source** (classified into the four shapes above). A
**passed-through** credential attempt is the headline — the gateway *detected* the
login and let the packet reach the service, so the only thing between the attacker
and the account is the password itself.

Honest about its limits: these are IPS **detections, not authentication outcomes**
— an attempt means a login tripped a rule, never that a password was *correct*, so
the report measures pressure and exposure, not breach; identification is a
**keyword / port heuristic** (the signature-confirmed vs. port-only split is always
shown so a port-inflated set is visible); ports are **re-parsed, not stored**, with
a text-inferred or "unknown" service fallback. Pure offline math over the local
alert history (plus blocklist / watchlist / safelist membership) — **no SSH, no
Claude, no live gateway query**.

- `GET /api/bruteforce?hours=N[&limit=20][&minAttempts=3]` → the structured model **plus** rendered Markdown (login-surface table + attacking-source shape table).
- `GET /api/bruteforce.md?hours=N` → the same report as a downloadable `.md` file.
- `node src/index.ts --bruteforce 168 [--limit 20] [--min-attempts 3]` (or `npm run bruteforce`) → print the Markdown to stdout (defaults to a 7-day window so a low-and-slow guesser has time to reveal a run).

## 🧬 Burstiness / temporal-texture report (`GET /api/burstiness[.md]`, `--burstiness`)

Every attacker leaves a *timing texture*, and which one a source wears says more
about *what it is* than its raw alert count does. A "1,000 alert" source that
fired them all in one 8-second burst is one push of a button; the same 1,000
spread evenly over a week is a persistent presence. This report measures that
texture per source with two well-established network-science statistics computed
over its inter-arrival gaps (the time between its consecutive alerts):

- **Burstiness `B = (σ − μ) / (σ + μ)`** (Goh & Barabási, 2008) — bounded to
  [−1, +1] and *scale-free* (independent of how *often* the source fires).
  **`B → +1`** = extremely **bursty**: tight clusters separated by long silences —
  the signature of scripted scanners / exploit tooling emptying a magazine.
  **`B ≈ 0`** = **random / Poisson**: a memoryless drizzle (CV ≈ 1), i.e.
  background internet weather. **`B → −1`** = perfectly **regular**: evenly spaced,
  the metronome / beacon / cron shape.
- **Memory coefficient `M`** — the lag-1 autocorrelation of the gap sequence: do
  *long gaps follow long gaps*? `M > 0` means the cadence has momentum (slow and
  fast phases cluster), the tell of an on/off **duty cycle** — a tool run
  repeatedly on a loose schedule rather than one continuous run.

Together `(B, M)` place every active source in a behavioural plane no other
SecTool report draws. It is deliberately *not* the beaconing report: `beacon`
flags a single src→dst *pair* at the `B → −1` corner (low jitter, C2 cadence);
this scores *every* source across its whole footprint and is mostly interested in
the opposite corner (`B → +1`), where automation lives. It is not `surge` (spikes
in the *aggregate* stream), nor `dwell` (idle-gap *sessions*), nor
`rhythm`/`patterns` (which fold onto hour-of-day axes, destroying the fine
inter-arrival structure `B` measures). For each scored source it also reports the
**tightest burst** — the most alerts seen inside any sliding window
(`--burst-window`, default 60s) — turning the abstract `B` into a concrete
"37 hits in 60s", plus the longest silence, distinct targets/signatures, peak
severity and block share. Two tables: **burstiest first** (automation hunting),
and **most regular** (beacon-adjacent, cross-checkable with `--beacon`).

Honest about its limits: these are IPS **detections, not packets**, so the
texture is the texture of *detections* — a burst can be a real machine-gun scan
or a chatty rule firing many times on one flow (it ranks and classifies, it does
not convict); syslog timestamps are **second-resolution**, so sub-second
structure collapses to zero-length gaps (treated, correctly, as maximal
burstiness); and `B` (and especially `M`) are unstable on a handful of gaps, so a
source needs a minimum number of alerts (`--min-events`, default 6) to be scored.
Pure offline math over the local alert history — **no SSH, no Claude, no live
gateway query**.

- `GET /api/burstiness?hours=N[&limit=20][&minEvents=6][&burstWindow=60]` → the structured model **plus** rendered Markdown (population-texture table + burstiest-sources table + most-regular-sources table).
- `GET /api/burstiness.md?hours=N` → the same report as a downloadable `.md` file.
- `node src/index.ts --burstiness 168 [--limit 20] [--min-events 6] [--burst-window 60]` (or `npm run burstiness`) → print the Markdown to stdout (defaults to a 7-day window so an on/off duty cycle has several burst-then-sleep rounds to emerge).

## 🤝 Convergence / coordinated-strike report (`GET /api/convergence[.md]`, `--convergence`)

The single most reliable tell of *coordination* is **simultaneity**: many
unrelated source IPs converging on one target in the same handful of seconds. No
human types from forty addresses at once — a tasked botnet, a stresser service,
or a distributed password-spray does exactly that. The members of such a crowd
are deliberately diverse (scattered across different netblocks, sometimes firing
*different* signatures), so the only thing that binds them is the **clock** —
precisely the axis the other reports throw away. This report localises the crowd
in time: for every target it slides a `--window` (default 120s) across that
target's alert timeline and records the **peak number of distinct sources** seen
inside any single window, with the member IPs present at that peak. A target
whose peak clears `--min-sources` (default 5) is a **convergence event** — a
coordinated strike, not background drizzle. The same statistic is then computed
per **signature** (many distinct sources firing one rule in one window — the
mass-exploitation / single-CVE-campaign shape).

This is *not* the toolkit-cluster report (`--clusters`), which groups sources by
shared *signature set* and ignores timing; nor the netblock report
(`--netblocks`), which groups by /24 CIDR; nor `surge`, which flags spikes in the
*aggregate* stream without asking how many *distinct* sources made the storm; nor
the single-source timeline reports (`burstiness`/`beacon`/`dwell`). It is the
orthogonal question — *many sources, one instant*. Each convergence reports the
peak distinct-source count and the seconds it spanned, a sample of the member
IPs, the **convergence ratio** (peak-window distinct sources ÷ the target's total
distinct sources — `100%` means every attacker landed in one window, a tightly
synchronized strike), the external-source share, direction
(ext→int / int→int / int→ext / ext→ext), peak severity and block share.

Honest about its limits: these are IPS **detections, not packets**, at syslog
**second-resolution**, so a true volumetric flood is under-counted (read counts
as a floor) and sub-second ordering is lost; source addresses can be **spoofed**
in volumetric attacks (it flags the crowd to investigate, it does not attribute);
and on a very busy target unrelated sources can coincide by chance — the
`--min-sources` floor and the convergence ratio separate a synchronized strike
from background coincidence. Cross-check flagged crowds against `--clusters` and
`--netblocks` for the *who*. Pure offline math over the local alert history —
**no SSH, no Claude, no live gateway query**.

- `GET /api/convergence?hours=N[&limit=20][&minSources=5][&window=120]` → the structured model **plus** rendered Markdown (coordinated-strikes-by-target table + coordinated-strikes-by-signature table).
- `GET /api/convergence.md?hours=N` → the same report as a downloadable `.md` file.
- `node src/index.ts --convergence 168 [--limit 20] [--min-sources 5] [--window 120]` (or `npm run convergence`) → print the Markdown to stdout (defaults to a 7-day window so coordinated bursts have room to recur and stand out).

## 🧠 Attacker repertoire / sophistication report (`GET /api/repertoire[.md]`, `--repertoire`)

Almost every attacker-centric report ranks a source by *how much* it does:
persistence and footprint reward longevity and volume, fan-out and scan-shape
reward *reach across targets*, escalation rewards a rising *severity*. None of
them rank a source by *how many different things it does*. Yet that breadth is
the sharpest sophistication tell the IPS stream holds: a source that trips one
classtype five hundred times is automated background noise, while a source that
walks **reconnaissance → delivery → exploitation → command-and-control**,
tripping a dozen distinct signatures across several threat classes, is a
hands-on operator running a *toolkit* — far more dangerous at a fraction of the
volume, and exactly what raw-count rankings bury.

For every source it folds the windowed alerts and measures three orthogonal
breadth axes: **stage breadth** (distinct kill-chain stages reached, mapped with
the very same heuristic that powers the kill-chain report, plus the furthest
stage), **class breadth** (distinct Suricata classifications, resolved exactly as
the threat-mix report resolves them), and **technique breadth** (distinct
signatures). From those it computes a 0–100 **sophistication score** — stage
breadth weighted heaviest, then class & technique breadth, chain depth and worst
severity, with **volume deliberately excluded** so a quiet many-method operator
outranks a loud flood — and assigns a one-word tier:

- **🎯 operator** — reaches **≥3 kill-chain stages**: a multi-stage intrusion in
  motion, the highest-priority thing to act on.
- **🧰 toolkit** — spans **2 stages** or **≥3 threat classes**: a varied attacker
  worth a closer look.
- **🔧 specialist** — one stage but **many signatures / classes**: one thing done
  many ways (a dedicated brute-forcer, a vuln-specific exploiter).
- **• probe** — minimal breadth: the long tail of one-trick scanners and noise.

Each row carries a compact **stage strip** (①②③④⑤ lit for the stages reached),
the blocked-vs-passed split (a sophisticated source whose traffic is *let
through* is the worst case), worst severity, the top class / signature, and
blocklist / watchlist / safelist membership. **Internal** sources with a wide
repertoire are flagged — an internal box reaching multiple attack stages is a
lateral-movement / compromise tell, not an inbound probe.

Honest about its limits: **tier and stage are heuristics** (regex over
classification + category + signature text; the raw distinct counts are always
shown so the call can be second-guessed); breadth needs labels, so a source under
unhelpful rule names can under-read as a "probe" (labelling coverage is
reported); these are IPS **detections**, not full flows, so repertoire breadth is
a lower bound. Pure offline math over the local alert history (plus blocklist /
watchlist / safelist membership) — **no SSH, no Claude, no live gateway query**.

- `GET /api/repertoire?hours=N[&limit=20][&minAlerts=2]` → the structured model **plus** rendered Markdown (per-source sophistication table with stage strips).
- `GET /api/repertoire.md?hours=N` → the same report as a downloadable `.md` file.
- `node src/index.ts --repertoire 168 [--limit 20] [--min-alerts 2]` (or `npm run repertoire`) → print the Markdown to stdout (defaults to a 7-day window so a low-and-slow operator has time to reveal breadth).

## 📜 Detection-rule (SID) inventory & ruleset-provenance report (`GET /api/ruleset[.md]`, `--ruleset`)

Every signature-centric report in SecTool keys off the human-readable **signature
text** (`tuning`, `lifecycle`, `audience`, `noise` all group and de-dup by the
`msg` string). But that string is **mutable** — Emerging Threats rewrites a rule's
`msg` across revisions, so group-by-text silently splits one rule across its
wording changes and conflates near-duplicates. This report keys off the one field
that is a **stable, globally-unique identity** for the rule that actually fired:
the Suricata `gid:sid:rev` stamp (`[1:2024897:4]`) that leads every fast.log line,
re-parsed straight from each stored alert's raw payload (using the same bracket the
ingest detector keys on, plus the JSON `signature_id`/`gid`/`rev` fields for
eve-format alerts).

That numeric identity carries information the text cannot:

- **Provenance** — Suricata/Snort allocate SID ranges by *source feed*: `< 1,000,000`
  is Snort/Talos (the GPL + registered VRT ruleset), `1,000,000–1,999,999` is the
  range reserved for an operator's **own local rules**, and `2,000,000+` is
  **Emerging Threats** (ET OPEN / ETPRO). The report rolls hits up by feed, so you
  see the ruleset's centre of gravity — and can confirm at a glance that your local
  rules are loaded and firing (or that they have gone silent, a coverage blind spot).
- **Revision drift** — the same SID firing under **two revisions inside one window**
  is a fingerprint that your ruleset was **updated mid-window**; any trend or
  period comparison that straddles the update is comparing different detection
  logic. A dedicated drift table surfaces every such rule, newest rev highlighted.
- **Family / category** — the ET `msg`'s own family + category prefix (`ET MALWARE`,
  `ET SCAN`, `GPL ICMP`, `ETPRO …`) is rolled up as a coarser, source-native
  grouping, distinct from Suricata's `Classification` taxonomy.

The per-rule inventory ranks by severity-weighted volume and carries each rule's
rev(s), feed, signature text, hits, peak severity, block-rate and distinct
source/target counts — so the first tuning candidate is named by its **stable SID**,
not by wording that will change under you. Alerts whose raw line carries no
recoverable rule id (firewall / threat-management events, or alerts whose raw was
lost) are counted as *un-attributable* and excluded from the rule tables (never
silently folded into a rule); the parse-coverage fraction is reported so a thin
attribution rate is visible, not hidden. Pure in-memory math over the stored alert
history — **no SSH, no Claude, no live gateway query**.

- `GET /api/ruleset?hours=N[&limit=25][&minHits=1]` → the structured model **plus** rendered Markdown (provenance rollup, family rollup, per-rule inventory and revision-drift watch).
- `GET /api/ruleset.md?hours=N` → the same report as a downloadable `.md` file.
- `node src/index.ts --ruleset 168 [--limit 25] [--min-hits 1]` (or `npm run ruleset`) → print the Markdown to stdout (defaults to a 7-day window so slow-firing rules and revision drift have time to show). Provenance is a documented range heuristic (the raw SID is always shown); only Suricata IDS/IPS alerts carry a SID, so firewall events are un-attributable.

## 🚀 Attack-momentum / rate-trend report (`GET /api/momentum[.md]`, `--momentum`)

Every source-centric report measures a *static* property of an attacker — how
much, how varied, how clustered — but not the one thing morning triage most
needs: **direction**. A source that fired 200 alerts is interesting; a source
that fired 10 yesterday and 190 in the last hour is an *incident in progress*,
and a flat "top sources by count" ranking buries it. The neighbouring temporal
reports each look elsewhere: the surge report flags **global** volume spikes (not
a single source's own slope), the escalation report tracks rising **severity**
(not volume), and the burstiness report measures **clumpiness** (scale-free, by
construction blind to whether the clumps are growing). None of them fit a *trend
line to each source's own volume-over-time*.

This report does. It slices the window into equal time bins (default 12, anchored
to the absolute window so "recent" means the same for every source), counts each
source's alerts per bin, and fits an ordinary **least-squares line** to those
counts. The slope is normalised into a scale-free **trend** in roughly [−1, +1]
(so it is comparable across sources of wildly different volume) and turned into a
0–100 **momentum score** (50 = flat) — **volume is deliberately excluded**, so a
small fast riser outranks a steady flood. A one-word **direction** is assigned:

- **🚀 surging** (trend ≥ +0.6) — heavily back-loaded, rate climbing fast.
- **📈 rising** (≥ +0.2) — clearly trending up.
- **➡️ steady** (|trend| < 0.2) — roughly constant rate.
- **📉 fading** (≤ −0.2) — winding down.
- **💤 spent** (≤ −0.6) — front-loaded, effectively gone quiet.
- **⚡ spike** — all activity in a *single* bin: a one-off burst with no trend.

Each row carries a unicode **sparkline** (▁▂▃▄▅▆▇█ over the bins, oldest left) so
a low-confidence fit is never hidden behind its label, the fit **R²** (trend
confidence), recency (share of the source's alerts in the back half), worst
severity, the blocked-vs-passed split (a *surging* source whose traffic is *let
through* is the worst case), the top signature, and blocklist / watchlist /
safelist membership. **Internal** sources trending **up** are flagged — a rising
rate from one of your own boxes is a beaconing / exfil / worm ramp, not an
inbound probe.

Honest about its limits: **a trend is a description, not a forecast** (a surging
source may stop the moment you read this; use momentum as a triage *order*); a
noisy, humped or U-shaped timeline can wear a weak slope label, so R² and the
sparkline are always shown; the result is bin-width sensitive (tune with
`--buckets`); these are IPS **detections**, not flows, and a long look-back can
hit the store's history cap and clip the early bins, flattering the trend upward.
Pure offline math over the local alert history (plus blocklist / watchlist /
safelist membership) — **no SSH, no Claude, no live gateway query**.

- `GET /api/momentum?hours=N[&limit=20][&minAlerts=3][&buckets=12]` → the structured model **plus** rendered Markdown (per-source momentum table with sparklines).
- `GET /api/momentum.md?hours=N` → the same report as a downloadable `.md` file.
- `node src/index.ts --momentum 168 [--limit 20] [--min-alerts 3] [--buckets 12]` (or `npm run momentum`) → print the Markdown to stdout (defaults to a 7-day window so a slow ramp has room to reveal its slope).

## 🕒 Source dwell-time & engagement-session report (`GET /api/dwell[.md]`, `--dwell`)

Every *temporal* report already exists — the [rhythm report](#-temporal-activity-rhythm-report)
folds the whole network into an hour-of-day heatmap, the surge report finds volume
spikes, the [beacon report](#-beacon--periodicity-report) hunts metronomic
fixed-interval C2 pings, and the [persistence report](#-persistence--repeat-offender-report)
counts the distinct *days* a source reappears. None of them segment a **single
source's timeline into sessions** and answer the responder's first triage
question about an active actor: *is this one sustained sitting (camped, hands-on,
working a target right now) or a thin scatter of drive-by touches across the
week?* Two sources with the **same alert count and the same first/last
timestamps** can be a solid three-hour intrusion or twelve one-second pokes spread
over six days — opposite threats that every count- and span-based report renders
identically. The difference lives in the **gaps**, which nothing else measures.

For every source it sorts the alert timestamps and **sessionises** them — a new
sitting begins whenever the idle gap exceeds a threshold (default **30 min**,
`--gap`/`?gap=`) — then derives the **dwell span** (first→last), the **number of
sittings**, the **longest / mean sitting**, the **active time & duty cycle** (Σ
sitting durations as a fraction of the span: how *present* the source was), and
the **longest idle gap**. From those it assigns a one-word engagement pattern:

- **🔥 sustained** — one long continuous sitting, or many covering ≥50% of a
  non-trivial span: camped on you *now*, the highest-priority thing to look at.
- **🔁 intermittent** — three or more separated sittings: a returner that keeps
  coming back (low-and-slow, or a scheduled job / beacon too ragged for the
  beacon report).
- **• sporadic** — a couple of touches spread thin across a wide span.
- **⚡ transient** — a single short burst then gone (a one-off scan / probe).

Sources are ranked by a 0–100 **engagement score** (dwell span as a fraction of
the window, duty cycle, return count, worst severity) so the source most
*entrenched in time* floats up — deliberately a different axis from the volume-,
reach- and breadth-ranked reports, surfacing the quiet long camp a top-by-count
table buries. Each row carries the first-seen age, dwell, sittings, longest
sitting, duty cycle, max idle gap, worst severity, and blocklist / watchlist /
safelist membership; **internal** hosts with sustained/intermittent engagement are
flagged as a beaconing / data-staging tell.

Honest about its limits: these are IPS **detections**, not presence — a gap is a
gap in *alerting*, not proof of absence, so dwell span is a lower bound and the
duty cycle an under-estimate (a careful operator can read as "sporadic"); the
sitting threshold is a heuristic (the raw span and count are always shown); and a
long look-back can hit the alert store's history cap and clip the earliest
sittings. Pure offline math over the local alert history (plus blocklist /
watchlist / safelist membership) — **no SSH, no Claude, no live gateway query**.

- `GET /api/dwell?hours=N[&limit=20][&minAlerts=2][&gap=30]` → the structured model **plus** rendered Markdown (per-source dwell table).
- `GET /api/dwell.md?hours=N` → the same report as a downloadable `.md` file.
- `node src/index.ts --dwell 168 [--limit 20] [--min-alerts 2] [--gap 30]` (or `npm run dwell`) → print the Markdown to stdout (defaults to a 7-day window so a low-and-slow returner has time to reveal its sittings).

## ⚔️ MITRE ATT&CK coverage report (`GET /api/mitre[.md]`, `--mitre`)

Every other report describes the threat in *SecTool's own* vocabulary — sources,
hosts, signatures, kill-chain stages. This one re-expresses the same alert
history in the framework your SOC, your SIEM, and your compliance auditor already
speak: **MITRE ATT&CK**. The closest neighbour is the
[kill-chain report](#-kill-chain--attack-stage-report-get-apikillchainmd---killchain),
but the two are complementary, not redundant — the kill chain maps each alert to
one of **five ordered Lockheed-Martin stages** and watches a single host *progress*
through them; this report maps each alert to one of the **fourteen ATT&CK
Enterprise tactics** and a specific **technique ID** (T-code), producing the
industry-standard, ATT&CK-Navigator-shaped **coverage matrix** that drops straight
into a threat-coverage review or a detection-gap assessment. ATT&CK's tactic set
is far finer than the kill chain's (it separates Credential Access, Discovery,
Lateral Movement, Defense Evasion, Impact … each of which the kill chain lumps
into a single bucket).

Each stored alert is mapped to **one** ATT&CK technique by a first-match-wins
heuristic over its `classification` / `signature` / `category` text, then rolled
up two ways:

- **Tactic coverage** — per ATT&CK tactic (in canonical order, observed cells
  only): distinct techniques fired, alert volume and share, distinct attacker
  sources and internal hosts, severity ceiling, blocked-vs-detected split, the
  busiest technique, and an ASCII coverage bar.
- **Per-technique detail** — every observed technique ranked by a
  severity-weighted score (so a small but dangerous technique outranks a flood of
  low-severity noise): ID + name + parent tactic, volume, distinct sources and
  targets, severity ceiling, disposition split, the dominant signature, a **🏠
  internal-source** flag (an inside host *sourcing* a technique is a
  compromise / lateral-movement tell), and a **🚩 control-gap** flag for
  medium-or-worse techniques mostly *detected, not blocked* — the ATT&CK cells to
  verify enforcement on first.

Honest about its limits: ATT&CK mapping is a **heuristic** over free-text Suricata
fields, not a curated rule→technique table — a strong triage hint, not an authored
mapping. To keep the coverage math clean each alert is attributed to a **single**
best-match technique (a real ATT&CK mapping is often many-to-one), and everything
that matches no rule lands in an honest **unmapped** bucket (counted, never
silently dropped). These are IPS **detections**, not full telemetry — a technique
used without tripping a signature is invisible, so coverage is a lower bound and an
empty tactic means "not *alerted* on", not "did not happen". Pure offline math over
the local alert history — **no SSH, no Claude, no live gateway query**.

- `GET /api/mitre?hours=N[&limit=30]` → the structured model **plus** rendered Markdown (tactic-coverage table + per-technique ranking).
- `GET /api/mitre.md?hours=N` → the same report as a downloadable `.md` file.
- `node src/index.ts --mitre 168 [--limit 30]` (or `npm run mitre`) → print the Markdown to stdout (defaults to a 7-day window so the technique mix reflects more than one shift).

## 📊 Threat-concentration / Pareto-Gini report (`GET /api/concentration[.md]`, `--concentration`)

Every other attacker report hands you a *leaderboard* — the worst source, the
noisiest signature, the most-hammered host. This one steps back and measures the
**shape of the whole distribution**: the strategic number that decides *how* to
respond before you touch any single entity. Ten thousand alerts from **three** IPs
and ten thousand from **eight thousand** IPs read identically on every count- and
rank-based report, yet they demand opposite playbooks — a tight blocklist that
wins the day versus a botnet storm where no single block moves the needle and the
answer is tuning, rate-limiting or geo/ASN policy. That difference lives in how
*evenly* the volume is spread, which a leaderboard hides.

The report measures concentration across **three orthogonal dimensions** —
**sources** (attacker IPs), **signatures** (which rules fire) and **targets**
(destination hosts) — and for each computes:

- **Gini coefficient (0–1)** — the classic inequality measure. 0 = perfectly even
  (every entity contributes the same volume); → 1 = one entity owns everything.
- **Pareto top-shares** — what the top 1% / 5% / 10% / 20% of entities account for.
- **Coverage breakpoints** — the inverse: how *few* entities cover 50% / 80% / 90%
  / 95% of the volume (the directly actionable "9 sources = 80% of alerts").
- A one-word **shape** — **🎯 concentrated** (block-and-win), **▥ mixed**, or
  **🌫 diffuse** (tune / rate-limit / geo-policy, not blocklists).

Because a shape verdict is only useful if you can act on it, the source dimension
carries a **blocklist quick-wins** view: the heaviest *unblocked, external,
non-safelisted* sources and the exact fraction of source-attributed alerts that
blocking those few would remove — alongside how much the blocklist already absorbs.
Internal hosts that surface as *source* heavy hitters are flagged (a compromise /
misconfiguration tell, not an inbound attacker).

Honest about its limits: concentration is measured on alert **counts**, not
severity — a diffuse tail can still hide one concentrated critical actor, so the
*shape* guides strategy, not triage. These are IPS **detections**: NAT / shared
egress can collapse many real actors into one IP (over-stating concentration) and a
rotating botnet can inflate the source count (under-stating it). A long look-back
can hit the store's history cap and clip the tail. Pure offline math over the local
alert history — **no SSH, no Claude, no live gateway query**.

- `GET /api/concentration?hours=N[&limit=15][&quickWins=10]` → the structured model **plus** rendered Markdown (the at-a-glance matrix, per-dimension Pareto/coverage detail and the quick-wins table).
- `GET /api/concentration.md?hours=N` → the same report as a downloadable `.md` file.
- `node src/index.ts --concentration 168 [--limit 15] [--quick-wins 10]` (or `npm run concentration`) → print the Markdown to stdout (defaults to a 7-day window so the distribution shape reflects more than one shift).

## 🔁 Attacker cohort-retention / churn report (`GET /api/cohort[.md]`, `--cohort`)

This is **product-style retention analytics applied to attackers.** A growth team
never asks only "how many users this week"; it asks how many are *new*, how many
*stayed*, how many *came back*, how many *churned out*, and tracks each cohort's
retention curve. That same decomposition is exactly what a defender wants for the
attacker population — and **no other report computes it**. `--persist` ranks the
single most entrenched IPs (a leaderboard), `--novelty` surfaces first-seen leads
(but never follows them forward), `--compare` diffs two windows as aggregate
totals, and `--lifecycle` measures a *signature's* shape — none build a cohort
triangle or a population retention curve.

The distinction is strategic. Two networks with identical alert volume can have
opposite threat surfaces: a **🌀 churny** revolving door where almost every source
appears once and never returns (internet background radiation — blocklisting
individuals buys nothing durable; reach for category / geo / ASN policy), or a
**🪨 sticky** committed base where attackers come back day after day (someone has
*chosen* you — the persistent core is a small, concrete, blockable set worth
escalating). The retention *curve* is the single number that separates those
worlds, and it is invisible in every volume- or leaderboard-shaped report.

For each equal-width **time bucket** (default one UTC day) the report decomposes the
external source population into:

- **new** — first appearance in the window here.
- **retained** — active here *and* the immediately previous bucket (stayed).
- **resurrected** — back after a quiet bucket (returned after a gap).
- **churned** — active the previous bucket, absent here (left).

It then groups each bucket's first-timers into a **cohort**, builds the cohort
retention triangle and the population-average **retention curve** (lag-1 = the
probability an active attacker returns the next bucket), profiles **stickiness**
(how many buckets each source spans), surfaces the **sticky core** (persistent
returners, flagged ⛔ blocked / 👁 watched / ✅ safelisted / 🆕 new — so the
unblocked rows are your durable blocklist targets), and splits the window's
attackers into brand-new-to-history vs. returning-from-before faces.

Honest about its limits: cohorts are built from source IPs **as the IPS logged
them** — NAT / shared egress collapses many real attackers into one address
(over-stating stickiness) and a rotating botnet inflates the newcomer count
(over-stating churn); retention reflects **address** reuse, not human intent.
"New to history" is bounded by the rolling alert store, so a long look-back that
hits the store cap clips the oldest buckets. Pure offline math over the local alert
history (plus blocklist / watchlist / safelist flags) — **no SSH, no Claude, no
live gateway query**.

- `GET /api/cohort?hours=N[&limit=15][&bucket=24]` → the structured model **plus** rendered Markdown (the population scoreboard, per-bucket flow, retention curve, cohort triangle, stickiness histogram and the sticky-core table).
- `GET /api/cohort.md?hours=N` → the same report as a downloadable `.md` file.
- `node src/index.ts --cohort 168 [--limit 15] [--bucket 24]` (or `npm run cohort`) → print the Markdown to stdout (defaults to a 7-day window with daily buckets, so the retention curve has seven points to work with).

## 🔕 Suppression-rule audit report (`GET /api/suppaudit[.md]`, `--suppaudit`)

SecTool lets you silence noisy detections with **suppression rules** (match on
signature / category / src / dst / max-severity; matched alerts are still recorded
but skip summarization + the Discord page). Over time a rule set rots in three
quiet, dangerous ways, and **no other report looks at the rules themselves** —
`--tuning` does the opposite job (it *proposes new* suppressions), and the snapshot
report only prints a rule count. This report audits the silences you already have:

- **Dead weight** — a rule whose signature/scanner is long gone. It matches nothing
  but still sits in the evaluation path and clutters the config.
- **Shadowing** — two rules overlap, so one silently covers everything the other
  does. The shadowed rule is redundant and lies about why alerts are quiet.
- **Over-broad silence** — the worst failure mode. A rule written to mute `info`
  scan chatter is loose enough (e.g. `cat=IDS/IPS` with no severity ceiling) to now
  swallow **medium / high / critical** detections too. You think you're quiet
  because nothing is wrong; in fact the page was muted. A suppression that hides a
  real incident costs far more than the noise it was meant to remove.

For every rule it replays the stored alert history through the *same match
predicate the live engine uses* and reports the rule's **standalone** reach, its
**first-match-effective** credit (non-double-counted, mirroring the live
first-match-wins evaluation), the **worst severity** it silences, and its **live
hit counters** (so a rule that worked *before* the store's retention window is not
mislabelled dead). Each rule earns a one-word **verdict** and a recommended action:
🚨 **risky** (silences medium+ signal — review) · 🔁 **shadowed** (redundant) ·
🌐 **broad** (no signature/IP anchor) · 💀 **dead** (no matches, no live hits —
prune) · 🌙 **quiet** (dormant but proven) · 🌱 **untested** (too new) · ✅
**effective** (muting noise cleanly). The summary headlines the overall
noise-reduction the rule set delivers and the count of medium+ detections it is
silencing — the number you most want to be zero.

Honest about its limits: standalone/effective counts only see alerts still in the
rolling store (the verdict weighs live hit counters to avoid a false "dead");
"risky" means a rule *can* silence a medium+ **detection**, not that it was a true
positive — but a silence broad enough to swallow high/critical signal deserves a
human look. Pure offline math over the local alert history + suppression store —
**no SSH, no Claude, no live gateway query**.

- `GET /api/suppaudit?hours=N[&limit=100][&grace=24]` → the structured per-rule model **plus** rendered Markdown (the scoreboard and the verdict-ranked rule table).
- `GET /api/suppaudit.md?hours=N` → the same report as a downloadable `.md` file.
- `node src/index.ts --suppaudit 168 [--limit 100] [--grace 24]` (or `npm run suppaudit`) → print the Markdown to stdout (defaults to a 7-day window so dormant-but-proven rules are judged on more than one shift).

## 🔁 Alert-noise / stream-redundancy report (`GET /api/noise[.md]`, `--noise`)

The single biggest driver of analyst fatigue is **the same event firing over and
over** — and **no other report measures it**. `dedupe.ts` only de-bounces duplicate
*deliveries* in the live pipeline (each distinct event is still stored and still
counts); `--concentration` measures volume inequality across *one* entity dimension
at a time; `--tuning` ranks *noisy rules* heuristically. None of them fold the
stream onto the **event tuple** — `source IP · destination IP · signature` (signature
falling back to the event `category`) — to ask "how much of this is repetition, and
exactly which combinations should I collapse?".

For the window it computes the **redundancy ratio** (`1 − distinct/total` — the share
of volume that is repeats of an event already represented), the **compression
factor** (`total/distinct` — "your 5 000 alerts compress to 320 lines, 15.6×"), and
the **collapsible alert count** (rows that would simply vanish if every repeat folded
to one line, with zero loss of distinct information). It bands the repetition
histogram, ranks the loudest **noise drivers**, and — crucially — separates two kinds
of repeat so you never suppress the wrong thing:

- 🧹 **Collapsible noise** — a tuple repeating ≥ the threshold whose worst severity is
  only info/low. Textbook fatigue: aggregate it into one line or write a suppression
  rule (see `--suppaudit`); you lose nothing.
- 🚨 **Sustained pressure** — a tuple repeating just as often but reaching
  high/critical severity. This is *not* noise — it is the same serious attack landing
  again and again, so each repeat is flagged and must never be folded away.

A one-word **verdict** (🔁 high ≥60% · ▥ moderate · 🟢 low <30% redundancy) headlines
how repetitive the stream is. Honest about its limits: redundancy is measured over
source IPs **as the IPS logged them** — NAT / shared egress over-states it, a rotating
botnet hitting one rule from many IPs under-states it; signature-less firewall events
are keyed on their coarser `category`; repetition older than the rolling store's cap is
invisible, so every metric is a lower bound. Pure offline math over the local alert
history (plus blocklist / watchlist / safelist flags) — **no SSH, no Claude, no live
gateway query**.

- `GET /api/noise?hours=N[&limit=20][&repeat=5]` → the structured model **plus** rendered Markdown (the at-a-glance scoreboard, repetition distribution, noise-driver table and the action list).
- `GET /api/noise.md?hours=N` → the same report as a downloadable `.md` file.
- `node src/index.ts --noise 168 [--limit 20] [--repeat 5]` (or `npm run noise`) → print the Markdown to stdout (defaults to a 7-day window so repetition is measured over more than one shift).

## 🔀 Attack-sequence / signature-transition (playbook) report (`GET /api/sequence[.md]`, `--sequence`)

Several reports look at *which* signatures a source uses, but every one of them
throws away **order** — the most operationally useful dimension. `--cooccur` pairs
signatures that fire *together* (symmetric, unordered — it can't say A comes *before*
B); `--killchain` buckets each alert into a *fixed* stage taxonomy; `--repertoire`
counts the *breadth* of a source's signature set. None of them learn the directed
edge **A → B**: "this source fired A and then, soon after, fired a different
signature B".

This report orders each source's alerts by time, collapses runs of the same
signature (`A,A,A,B` is one `A→B` step), and emits an ordered transition on each
signature change — **unless** the gap exceeds the session bound (default 6h), in
which case the chain is cut so a day-old A is never chained onto B. Folding every
source's transitions together yields a directed weighted graph of attacker behaviour:

- 🚨 **Early-warning edges** — escalating transitions whose *destination* reaches
  high/critical and whose conditional probability `P(B | A)` is high with real
  support. The actionable gold: *"when you see A, the serious step B usually follows
  within ~M — alert or auto-block on A."* The **median lead time** is the warning
  window you have.
- 🛤️ **Most-walked transitions** — the busiest A→B edges, with how many *distinct
  sources* repeat each (an edge many independent attackers walk is a real playbook,
  not one noisy host).
- 🎯 **Predictable pivots** — per source-signature, the next-step distribution and its
  Shannon entropy. Low entropy + high `P(top)` = a deterministic fork worth a rule.
- 📖 **Recurring 3-step playbooks** — the most common ordered `A→B→C` sequences, the
  closest thing to a reusable attack script.

A one-word **verdict** (🤖 playbook-driven ≥50% · ▥ mixed · 🎲 opportunistic <25%)
headlines the share of transition volume flowing along *dominant* (`P≥0.5`) edges —
high means attackers behave like scripts and are easy to pre-empt; low means ad-hoc
probing. Honest about its limits: sequences are built over source IPs **as the IPS
logged them** (NAT chains unrelated actors; a rotating botnet splits one playbook
across many IPs), `A→B` is correlation not causation, and steps only chain within the
session gap, so every count is a lower bound. Pure offline math over the local alert
history (plus blocklist / watchlist flags) — **no SSH, no Claude, no live gateway
query**.

- `GET /api/sequence?hours=N[&limit=20][&gap=6][&support=3]` → the structured model **plus** rendered Markdown (the at-a-glance scoreboard, early-warning edges, most-walked transitions, predictable pivots and recurring playbooks).
- `GET /api/sequence.md?hours=N` → the same report as a downloadable `.md` file.
- `node src/index.ts --sequence 168 [--limit 20] [--gap 6] [--support 3]` (or `npm run sequence`) → print the Markdown to stdout (defaults to a 7-day window so ordered transitions have enough events to chain).

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

**Conversational memory.** Both Ask and Act keep the **last few turns** of each
chat session, so follow-ups stay in context (*"…and block that IP"*, *"now suppress
it"*) instead of starting cold every request. Pass a stable `sessionId` with each
request (the dashboard generates one per tab); the server retains a rolling window
of recent messages — in-process only, never written to disk — and forgets a session
after it goes idle. The dashboard's **↺ New chat** button clears it (`POST
/api/chat/reset`). Tune with `CONVO_MEMORY_ENABLED`, `CONVO_MEMORY_MAX` (default 10
messages) and `CONVO_MEMORY_TTL_MIN`.

## 🤖 Automation agent (dashboard "Act", `POST /api/agent/act`)

The same chat surface has an **🤖 Act** mode backed by an *action-capable* agent
(`src/analyst/agent.ts`). Where Ask only reads, Act can **operate every
operator-facing feature** from a plain-English instruction: create/remove
**suppression** rules, manage the **safelist** and **watchlist**, **block**/
**unblock** IPs at the firewall, and drive per-alert **triage** (status, notes,
dismiss/restore). Examples: *"Suppress the noisy SSH-scan signature from 10.0.0.5
for 24h"*, *"Add 185.220.101.0/24 to my watchlist as a Tor range"*, *"Block the IP
that attacked me most this week — check its reputation first."*

Every mutating call is returned as an **audit list** of exactly what changed, and a
default-on **Preview (dry-run)** toggle lets you see the planned changes without
applying anything. Firewall blocks still pass the same `blockGuard` allowlist that
protects private/internal/gateway/safelisted IPs. Send `{"instruction": "...",
"dryRun": true|false}` to the endpoint.

To close the LLM **"said it would act but never called a tool"** gap, the agent
self-checks its draft answer: if it claims or promises a change yet ran no action
tool (empty audit list), it is re-prompted once to either actually invoke the
tool(s) or honestly state that nothing was changed — so the reply can never
describe an action that didn't happen. The response includes a `nudged` flag when
this self-correction fired.

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

NetFlow is packet-sampled (`NETFLOW_SAMPLING_RATE`, 1:512 on the UDM Pro), so
volume detection scales the observed bytes back up by that rate to an estimated
true volume — a real ~50 MB/h exfil trips the threshold instead of looking 512×
too small. Distinct-port and fan-out counts can't be scaled linearly, so they're
judged relative to each host's own baseline (they remain conservative lower
bounds). Set `NETFLOW_SAMPLING_RATE=1` if your exporter doesn't sample.

## Threat-intel feeds (`INTEL_FEEDS_ENABLED`, `--feeds`)

Fetches public IP blocklists (abuse.ch Feodo/SSLBL, blocklist.de, FireHOL level1,
Spamhaus DROP), loads them into a `SECTOOL_FEED` ipset so known-bad IPs are
**dropped before they ever probe you**, and cross-references every enrichment
("on threat feeds: FireHOL level1"). A **highlighted changelog embed** is posted
to Discord every 24h with per-feed counts and deltas. Run on demand: `--feeds`.

### 🛡️ Intel page (feed exposure)

The blocklists hold millions of indicators — the **🛡️ Intel** dashboard tab
answers the question that actually matters: *which of those known-bad IPs are
touching **my** network right now?* It cross-references the loaded feeds against
your stored alert history **and** collected NetFlow, then ranks every flagged IP
by worst severity and activity volume. Each row shows the **direction**
(inbound = a flagged host reached in; outbound = an internal device contacted a
flagged host — often the more urgent signal), alert/flow hit counts, bytes, how
many distinct internal hosts were involved, and the listing feeds — with
one-click **👁 Watch** / **🚫 Block**. A header **🔎 Check IP** box looks up any
arbitrary address against the live feeds. Pure in-memory math over local data —
no SSH required (`GET /api/intel?hours=N`, `GET /api/intel/check?ip=`).

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
| `SKIP_GATEWAY_BLOCKED` | `true` | Don't notify when the gateway already blocked the detection (still recorded to history). |
| `CORRELATION_WINDOW_SEC` | `180` | Time window for related-log gathering. |
| `ALERT_PATTERN` | — | Optional regex an event must match to be an alert. |
| `DISCOVERY_ENABLED` | `true` | Active LAN device sweep (Devices → 🔍 Scan LAN). |
| `CONVO_MEMORY_ENABLED` | `true` | Ask/Act remember recent chat turns; `false` → cold every request. |
| `CONVO_MEMORY_MAX` | `10` | Messages (user+assistant turns) retained per chat session. |
| `CONVO_MEMORY_TTL_MIN` | `120` | Forget an idle chat session after this many minutes. |
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
