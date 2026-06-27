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
