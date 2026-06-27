/**
 * Report catalog / discovery report — "**what can SecTool actually tell me, and
 * how do I ask for it?**"
 *
 * SecTool has grown more than fifty self-contained offline reports, each with its
 * own CLI flag, `npm run` script, and `GET /api/<x>` + `/api/<x>.md` route. That
 * breadth is the product's strength and, paradoxically, its biggest usability
 * problem: there is no single place that answers *"which report do I want, and
 * what do I type to get it?"* The flag, the npm script, and the API route do not
 * even always share a name — `--watchlist` serves `/api/watchlist-activity`,
 * `--safelist` serves `/api/safelist-audit`, `--cooccur` serves `/api/cooccur` —
 * so guessing the route from the flag fails exactly when you need it most.
 *
 * This module is the missing index. Unlike every other report it does **not**
 * touch the alert history at all — it analyses *SecTool itself*. It exposes a
 * single curated registry ({@link REPORT_CATALOG}) of every report the tool
 * ships, grouped into the handful of questions an operator actually starts from
 * ("who is attacking me?", "what's hit?", "are my controls working?"), and
 * renders it two ways:
 *
 *   - a **structured model** ({@link CatalogReport}) whose entries carry the
 *     flag, npm script, JSON route, Markdown availability, default look-back
 *     window and a one-line purpose — machine-readable so a future dashboard can
 *     render a reports menu straight from `GET /api/catalog` instead of
 *     hard-coding links; and
 *   - a ready-to-paste **Markdown directory**, one table per category, that
 *     doubles as living documentation.
 *
 * It is intentionally a *curated* index, not an auto-derived one: parsing the
 * router and the arg-handler to discover routes would be brittle, and a short,
 * hand-tended list reads better and lets each report carry a human one-liner the
 * code can't generate. The trade-off is that a newly added report must also be
 * registered here — the `count` in the header is the honest tell when it drifts.
 *
 * Pure in-memory data with zero dependencies — no alert store, no SSH, no Claude,
 * no network. Mirrors the model + Markdown shape of report.ts, scan.ts and the
 * other offline reports so it plugs into the same CLI and HTTP plumbing.
 */

/** The coarse question-buckets an operator starts a report search from. */
export type ReportCategory =
  | "Daily driver"
  | "Attacker / source"
  | "Target / exposure"
  | "Threat type / signature"
  | "Temporal"
  | "Detection coverage"
  | "Controls / enforcement"
  | "Quality / AI / ops";

/** Canonical display order for the categories (drives the Markdown sections). */
export const CATEGORY_ORDER: readonly ReportCategory[] = [
  "Daily driver",
  "Attacker / source",
  "Target / exposure",
  "Threat type / signature",
  "Temporal",
  "Detection coverage",
  "Controls / enforcement",
  "Quality / AI / ops",
] as const;

/** One report's discovery metadata. */
export interface CatalogEntry {
  /** Stable identity / `npm run <key>` script name (e.g. "scan"). */
  key: string;
  /** CLI flag including the leading dashes (e.g. "--scan"), or null if API-only. */
  flag: string | null;
  /** JSON API route (e.g. "/api/scan"), or null if there is no HTTP endpoint. */
  api: string | null;
  /** True when a downloadable Markdown twin exists at `<api>.md`. */
  markdown: boolean;
  /** Default look-back window in hours, or null for non-windowed reports. */
  defaultHours: number | null;
  /** The question-bucket this report belongs to. */
  category: ReportCategory;
  /** Short human title. */
  title: string;
  /** One-line description of what the report tells you. */
  description: string;
}

/** A category and the reports filed under it. */
export interface CatalogGroup {
  category: ReportCategory;
  count: number;
  entries: CatalogEntry[];
}

export interface CatalogReport {
  /** ms epoch the catalog was rendered (for the header stamp only). */
  generatedMs: number;
  /** Total reports in the (optionally filtered) catalog. */
  totalReports: number;
  /** Total reports before any filter was applied. */
  catalogSize: number;
  /** The free-text query applied, if any. */
  query?: string;
  /** The category filter applied, if any. */
  categoryFilter?: ReportCategory;
  /** Reports grouped by category, in {@link CATEGORY_ORDER}. */
  groups: CatalogGroup[];
  /** Flat list of the (filtered) entries, in catalog order. */
  entries: CatalogEntry[];
  /** The finished Markdown directory. */
  markdown: string;
}

export interface CatalogOptions {
  /** Case-insensitive substring filter over key/title/description/flag/api. */
  query?: string;
  /** Restrict to a single category. */
  category?: ReportCategory;
  /** Pins the generated stamp for deterministic tests; defaults to now. */
  nowMs?: number;
}

// ----- the registry ---------------------------------------------------------

/**
 * Compact constructor so the registry below stays readable. Positional args:
 * category, key, flag, api, defaultHours, title, description. `markdown` is true
 * for every entry that has an `api` unless overridden — every offline report
 * ships a `<api>.md` twin; the handful of plain-text endpoints pass `false`.
 */
function entry(
  category: ReportCategory,
  key: string,
  flag: string | null,
  api: string | null,
  defaultHours: number | null,
  title: string,
  description: string,
  markdown = api !== null,
): CatalogEntry {
  return { category, key, flag, api, markdown, defaultHours, title, description };
}

/**
 * The curated index of every report SecTool ships. Keep this in sync when adding
 * a report — the catalog is the one place that is meant to know about all of
 * them. Order within a category is roughly "reach for this first" → "niche".
 */
export const REPORT_CATALOG: readonly CatalogEntry[] = [
  // --- Daily driver ---------------------------------------------------------
  entry("Daily driver", "briefing", "--briefing", "/api/briefing", 24,
    "Morning SITREP", "Consolidated security briefing: KPIs, trend, action items and bundled detail reports."),
  entry("Daily driver", "compare", "--compare", "/api/compare", 24,
    "Period comparison", "Period-over-period: this window versus the previous one, what rose and what fell."),
  entry("Daily driver", "report", null, "/api/report", null,
    "Period overview", "At-a-glance period report that powers the dashboard overview (API-only)."),
  entry("Daily driver", "catalog", "--catalog", "/api/catalog", null,
    "Report catalog", "This directory — every report, its flag, API route, window and purpose."),

  // --- Attacker / source ----------------------------------------------------
  entry("Attacker / source", "profile", "--profile", "/api/profile", null,
    "Single-IP dossier", "Deep profile of one address: every alert, target, signature and timeline (needs an IP)."),
  entry("Attacker / source", "persist", "--persist", "/api/persist", 168,
    "Repeat-offender longevity", "Which sources keep coming back, and for how long, across the window."),
  entry("Attacker / source", "recurrence", "--recurrence", "/api/recurrence", 168,
    "Return forecast", "When each repeat attacker is statistically due back."),
  entry("Attacker / source", "cohort", "--cohort", "/api/cohort", 168,
    "Cohort retention / churn", "Attacker retention: revolving-door newcomers vs a committed returning base."),
  entry("Attacker / source", "repertoire", "--repertoire", "/api/repertoire", 168,
    "Attacker sophistication", "Signature breadth per source: toolkit operator vs one-trick probe."),
  entry("Attacker / source", "dwell", "--dwell", "/api/dwell", 168,
    "Dwell time / sessions", "Engagement sessions per source: sustained camp vs transient drive-by."),
  entry("Attacker / source", "momentum", "--momentum", "/api/momentum", 168,
    "Attack-rate trend", "Who is ramping up right now versus who is spent (per-source rate trend)."),
  entry("Attacker / source", "netblocks", "--netblocks", "/api/netblocks", 168,
    "Source netblocks (CIDR)", "Rolls sources up into the infrastructure ranges behind the noise."),
  entry("Attacker / source", "clusters", "--clusters", "/api/clusters", 168,
    "Toolkit clusters", "Coordinated-infrastructure / botnet correlation across sources."),
  entry("Attacker / source", "spread", "--spread", "/api/spread", 168,
    "Fan-out / spread", "Scanning sources and sprayed targets ranked by distinct-destination reach."),
  entry("Attacker / source", "srcports", "--srcports", "/api/srcports", 168,
    "Source-port fingerprint", "Fixed-port tooling vs ephemeral stack; shared-port botnet correlation."),
  entry("Attacker / source", "portsig", "--portsig", "/api/portsig", 168,
    "Port-signature toolkit fingerprint", "Which attacker toolkit each source's destination-port set betrays — IoT-botnet, SMB/RDP lateral, database raid, web recon…"),
  entry("Attacker / source", "rarity", "--rarity", "/api/rarity", 168,
    "Rarity / signal-surprise", "TF-IDF lens: which source fires signatures nobody else does — the bespoke needle vs the commodity-scan noise."),
  entry("Attacker / source", "bogon", "--bogon", "/api/bogon", 168,
    "Bogon / spoofed-source audit", "Classifies each source IP against the IANA special-use registry (RFC6890) — flags martian/bogon sources that cannot legitimately exist (a spoofing tell and edge-filter gap), separates internal/lateral sources from real public attackers, distinct from netblocks (CIDR rollup) and geo."),
  entry("Attacker / source", "cloud", "--cloud", "/api/cloud", 168,
    "Cloud / hosting-origin attribution", "Matches each public source IP (longest-prefix, offline) to the cloud/VPS/CDN provider that hosts it — AWS, GCP, Azure, Oracle, Alibaba, Tencent, DigitalOcean, Linode, Vultr, OVH, Hetzner, Scaleway, Cloudflare — separating rented hyperscaler/VPS scan infra (with per-provider abuse-desk contacts to report) from unclassified residential/ISP space; complements netblocks (CIDR rollup) and bogon (validity)."),

  // --- Target / exposure ----------------------------------------------------
  entry("Target / exposure", "assets", "--assets", "/api/assets", 24,
    "Internal-asset exposure", "Scoreboard of which of your own hosts is hit hardest."),
  entry("Target / exposure", "targets", "--targets", "/api/targets", 168,
    "Victim exposure", "Which assets attract the most — and the worst — traffic."),
  entry("Target / exposure", "ports", "--ports", "/api/ports", 168,
    "Service / port exposure", "Which destination service/port is attacked, and which host exposes it."),
  entry("Target / exposure", "services", "--services", "/api/services", 168,
    "Attack surface by service class", "Remote-access / database / file-share / ICS-IoT crown-jewel surface."),
  entry("Target / exposure", "scan", "--scan", "/api/scan", 168,
    "Reconnaissance shape", "Per-source probe shape: horizontal vs vertical vs sweep vs targeted."),
  entry("Target / exposure", "cotarget", "--cotarget", "/api/cotarget", 168,
    "Co-targeting affinity", "Which of your hosts share the same adversaries — shared-fate / blast-radius clusters."),
  entry("Target / exposure", "direction", "--direction", "/api/direction", 168,
    "Traffic direction", "Inbound vs outbound vs lateral exposure split."),
  entry("Target / exposure", "edges", "--edges", "/api/edges", 168,
    "Attack-edge graph", "Source→target edges and lateral-movement topology between hosts."),
  entry("Target / exposure", "graph", "--graph", "/api/graph", 168,
    "Attack-graph visualization", "Renders the source→target topology as a ready-to-paste GraphViz DOT diagram, a Mermaid flowchart and a JSON node/edge model (--format dot|mermaid|md|json) — the visual twin of the edges report for incident bridges, tickets and post-mortems."),
  entry("Target / exposure", "traffic", "--traffic", "/api/traffic", 168,
    "Traffic / top-talkers", "Volumetric NetFlow view (not the alert stream): heaviest hosts, top conversations, outbound fan-out / exfil tell and the destination-service mix."),

  // --- Threat type / signature ----------------------------------------------
  entry("Threat type / signature", "classify", "--classify", "/api/classify", 168,
    "Threat-class mix", "How volume divides across Suricata's own taxonomy (recon vs trojan vs policy…)."),
  entry("Threat type / signature", "tuning", "--tuning", "/api/tuning", 168,
    "Signature tuning", "Which rules are loud, low-value chatter worth suppressing or re-tuning."),
  entry("Threat type / signature", "ruleset", "--ruleset", "/api/ruleset", 168,
    "Rule (SID) inventory & provenance", "Which Suricata rules fire, keyed by the stable gid:sid: source feed (Snort/Talos vs your local rules vs Emerging Threats) and mid-window revision drift."),
  entry("Threat type / signature", "protocols", "--protocols", "/api/protocols", 168,
    "Protocol mix (transport & L7)", "How traffic divides across transport (TCP/UDP/ICMP/…) and application (http/dns/tls/…) protocol — the port-independent axis that surfaces ICMP recon, UDP amplification and GRE/ESP tunnelling at the edge."),
  entry("Threat type / signature", "lifecycle", "--lifecycle", "/api/lifecycle", 168,
    "Signature lifecycle", "Chronic background signatures vs acute, newly spiking ones."),
  entry("Threat type / signature", "audience", "--audience", "/api/audience", 168,
    "Signature audience", "Background-radiation spray vs targeted snipe, per signature."),
  entry("Threat type / signature", "noise", "--noise", "/api/noise", 168,
    "Stream redundancy", "De-dup / suppression candidates in the alert firehose."),
  entry("Threat type / signature", "cve", "--cve", "/api/cve", 168,
    "CVE exposure", "Exploited-vulnerability patch worklist mapped from signatures."),
  entry("Threat type / signature", "artifacts", "--artifacts", "/api/artifacts", 168,
    "Payload artifacts / IOCs", "Domains, URLs, file hashes, CVEs and tool user-agents mined from raw payloads."),
  entry("Threat type / signature", "mitre", "--mitre", "/api/mitre", 168,
    "MITRE ATT&CK coverage", "Tactic/technique coverage mapped from the firing signatures."),
  entry("Threat type / signature", "cwe", "--cwe", "/api/cwe", 168,
    "CWE weakness-class coverage", "Which classes of software weakness (SQLi, traversal, overflow, broken auth…) the traffic targets — the AppSec/hardening view, orthogonal to cve (specific bugs) and mitre (adversary behaviour)."),
  entry("Threat type / signature", "owasp", "--owasp", "/api/owasp", 168,
    "OWASP Top 10 (2021) coverage", "Maps the alert stream onto the ten industry-standard web risk categories (A01 Broken Access Control … A10 SSRF) using the official 2021 CWE→category groupings — the compliance/AppSec-reporting language a board slide, SOC2/PCI narrative or dev ticket is written in, with per-category enforcement gap; the third taxonomy alongside cwe (weakness classes) and mitre (adversary behaviour)."),
  entry("Threat type / signature", "killchain", "--killchain", "/api/killchain", 168,
    "Kill-chain stages", "Distribution of activity across attack stages."),
  entry("Threat type / signature", "cooccur", "--cooccur", "/api/cooccur", 168,
    "Signature co-occurrence", "Which signatures fire together — attack-chain pairs."),
  entry("Threat type / signature", "sequence", "--sequence", "/api/sequence", 168,
    "Attack sequences / playbooks", "Ordered A→B signature transitions, escalation early-warning edges and recurring 3-step playbooks."),

  // --- Temporal -------------------------------------------------------------
  entry("Temporal", "rhythm", "--rhythm", "/api/rhythm", 168,
    "Activity rhythm", "When you're under attack: hour-of-day × day-of-week heat-map."),
  entry("Temporal", "surge", "--surge", "/api/surge", 168,
    "Volume surges", "Where the alert volume spiked in time, and what drove each storm."),
  entry("Temporal", "beacon", "--beacon", "/api/beacon", 168,
    "Beaconing / C2 cadence", "Periodic, clock-like callbacks that betray automation or C2."),
  entry("Temporal", "burstiness", "--burstiness", "/api/burstiness", 168,
    "Temporal texture", "Bursty tooling vs Poisson drizzle vs metronome cadence."),
  entry("Temporal", "convergence", "--convergence", "/api/convergence", 168,
    "Coordinated strikes", "Temporal convergence: botnet / DDoS / distributed-spray flash-crowds."),
  entry("Temporal", "patterns", "--patterns", "/api/patterns", 168,
    "Patterns of life", "Operating hours and timezone attribution: bot vs human shift."),
  entry("Temporal", "offhours", "--offhours", "/api/offhours", 168,
    "Off-hours coverage gap", "How much attack pressure — and serious detect-only exposure — lands while no one is on shift."),

  // --- Detection coverage ---------------------------------------------------
  entry("Detection coverage", "bruteforce", "--bruteforce", "/api/bruteforce", 168,
    "Credential attacks", "Password spray vs brute-force vs distributed login attempts."),
  entry("Detection coverage", "novelty", "--novelty", "/api/novelty", 168,
    "First-seen / novelty", "Brand-new sources, signatures and targets in the window."),
  entry("Detection coverage", "escalation", "--escalation", "/api/escalation", 168,
    "Severity trajectory", "Which threats are escalating versus de-escalating."),
  entry("Detection coverage", "risk", "--risk", "/api/risk", 168,
    "Risk index / posture", "Severity-weighted risk index and overall threat posture."),
  entry("Detection coverage", "focus", "--focus", "/api/focus", 168,
    "Threat focus", "Pareto concentration: where to spend defensive effort first."),
  entry("Detection coverage", "concentration", "--concentration", "/api/concentration", 168,
    "Concentration (Gini)", "Distribution shape: block-a-handful-and-win vs diffuse storm."),
  entry("Detection coverage", "drift", "--drift", "/api/drift", 168,
    "Severity-mix drift", "Is the *average* alert getting nastier over time, independent of volume? Per-slice mean-severity trend (front-half vs back-half delta + least-squares slope) that surfaces the \"volume flat but the mix is escalating\" recon→exploitation signal a raw count hides — the temporal twin of risk (magnitude) and escalation (per-source)."),

  // --- Controls / enforcement -----------------------------------------------
  entry("Controls / enforcement", "efficacy", "--efficacy", "/api/efficacy", 168,
    "IPS enforcement gap", "Serious traffic that was detected but never actually blocked."),
  entry("Controls / enforcement", "priority", "--priority", "/api/priority", 168,
    "Priority inversion", "Did the gateway block the IDS engine's most-urgent verdicts, or pass them while blocking noise?"),
  entry("Controls / enforcement", "blockplan", "--blockplan", "/api/blockplan", 168,
    "Block worklist", "Which sources to block next, ranked by preventable impact."),
  entry("Controls / enforcement", "autoblock", "--autoblock", "/api/autoblock", 168,
    "Auto-block threshold simulator", "Sweep \"block a source after N alerts\": preventable-volume vs blocks-issued knee curve to tune the auto-block trigger."),
  entry("Controls / enforcement", "recidivism", "--recidivism", "/api/recidivism", 168,
    "Post-block recidivism", "Did the block actually stop the traffic, or is it still coming?"),
  entry("Controls / enforcement", "mttb", "--mttb", "/api/mttb", 168,
    "Mean-Time-To-Block", "Detection-to-mitigation latency — how fast each attacker was contained."),
  entry("Controls / enforcement", "safelist", "--safelist", "/api/safelist-audit", 168,
    "Safelist risk audit", "Is a vetted-benign / allow-listed IP still attacking you?"),
  entry("Controls / enforcement", "hygiene", "--hygiene", "/api/hygiene", 720,
    "Blocklist hygiene", "Stale IOCs: which blocks to keep versus prune."),
  entry("Controls / enforcement", "fwrules", "--fwrules", "/api/fwrules", null,
    "Firewall-rule export", "Renders the enforced blocklist into ready-to-apply config for 10 firewall dialects (ipset/iptables/nftables/UFW/pf/Cisco/MikroTik/EdgeRouter-VyOS-UniFi/Windows/plain CIDR); safelisted IPs excluded by default, advisory CIDR-rollup hints. The codegen step after the iocs IP list."),
  entry("Controls / enforcement", "suppaudit", "--suppaudit", "/api/suppaudit", 168,
    "Suppression audit", "Are your alert-suppression rules effective — and are they hiding anything live?"),
  entry("Controls / enforcement", "watchlist", "--watchlist", "/api/watchlist-activity", 24,
    "Watchlist activity", "What your watched entities have been doing in the window."),

  // --- Quality / AI / ops ---------------------------------------------------
  entry("Quality / AI / ops", "coverage", "--coverage", "/api/coverage", 168,
    "Data coverage / integrity", "Can you trust the other reports? Truncation, gaps and parse health."),
  entry("Quality / AI / ops", "insight", "--insight", "/api/insight", 168,
    "AI analyst digest", "Summary coverage, severity re-grading and the recommended-action rollup."),
  entry("Quality / AI / ops", "notify", "--notify", "/api/notify", 168,
    "Notification audit", "Alert-fatigue check: what was pushed to Discord and how noisy it was."),
  entry("Quality / AI / ops", "backlog", "--backlog", "/api/backlog", 720,
    "Triage SLA backlog", "Unactioned alerts aging past their triage target."),
  entry("Quality / AI / ops", "iocs", "--iocs", "/api/iocs", 168,
    "IOC export", "Threat-indicator export in firewall-ready formats (plain / json / csv).", false),
  entry("Quality / AI / ops", "stix", "--stix", "/api/stix", 168,
    "STIX 2.1 intel export", "OASIS STIX 2.1 bundle (Indicator + Identity SDOs with patterns, confidence and validity windows) for sharing into MISP / OpenCTI / a TAXII collection / any STIX-aware SIEM; deterministic UUIDv5 IDs keep re-published feeds idempotent. The interop sibling of iocs (SecTool-shaped) and fwrules (enforcement codegen)."),
  entry("Quality / AI / ops", "sigma", "--sigma", "/api/sigma", 168,
    "Sigma detection-rule export", "Vendor-neutral Sigma detection rules (per-indicator, or --consolidated single list rule) for any Sigma-aware SIEM — convert with pySigma to Splunk / Elastic / Sentinel / QRadar / Loki / Chronicle. Each rule matches the attacker IP as either endpoint (src or dst) with severity-mapped level and deterministic UUIDv5 ids for clean recurring-export diffs. The detection-content sibling of stix (intel interchange) and fwrules (perimeter codegen)."),
  entry("Quality / AI / ops", "cef", "--cef", "/api/cef", 168,
    "CEF / LEEF event export", "Per-alert SIEM event-forwarding lines in CEF (ArcSight/Splunk/Sentinel) or LEEF (QRadar) — one normalized line per alert with mapped severity and re-parsed ports/protocol (--format cef|leef|json|md). The event-stream sibling of iocs (indicators), stix (intel) and sigma (detection rules).", false),
  entry("Quality / AI / ops", "metrics", "--metrics", "/api/metrics", null,
    "Prometheus metrics", "OpenMetrics exposition of live state (also served at GET /metrics).", false),
];

// ----- helpers --------------------------------------------------------------

function fmtTime(ms: number): string {
  return new Date(ms).toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
}

function cell(v: unknown): string {
  return String(v ?? "").replace(/\|/g, "\\|").replace(/\n/g, " ");
}

function mdTable(headers: string[], rows: string[][]): string {
  if (!rows.length) return "_None._";
  const head = `| ${headers.join(" | ")} |`;
  const sep = `| ${headers.map(() => "---").join(" | ")} |`;
  const body = rows.map((r) => `| ${r.join(" | ")} |`).join("\n");
  return `${head}\n${sep}\n${body}`;
}

/** "168h" or "—" for non-windowed reports. */
function windowLabel(hours: number | null): string {
  return hours === null ? "—" : `${hours}h`;
}

/** Inline-code the JSON route plus a hint that a `.md` twin exists. */
function apiLabel(e: CatalogEntry): string {
  if (!e.api) return "—";
  return e.markdown ? `\`${e.api}\` (+\`.md\`)` : `\`${e.api}\``;
}

function matchesQuery(e: CatalogEntry, q: string): boolean {
  const hay = `${e.key} ${e.title} ${e.description} ${e.flag ?? ""} ${e.api ?? ""}`.toLowerCase();
  return hay.includes(q);
}

// ----- markdown -------------------------------------------------------------

function categoryTable(entries: CatalogEntry[]): string {
  return mdTable(
    ["Report", "CLI flag", "npm run", "API route", "Window", "What it tells you"],
    entries.map((e) => [
      cell(e.title),
      e.flag ? `\`${e.flag}\`` : "—",
      `\`${e.key}\``,
      apiLabel(e),
      windowLabel(e.defaultHours),
      cell(e.description),
    ]),
  );
}

function renderMarkdown(m: CatalogReport): string {
  const lines: string[] = [];
  lines.push(`# 📚 SecTool Report Catalog`);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(m.generatedMs)}`);
  if (m.query || m.categoryFilter) {
    const bits: string[] = [];
    if (m.categoryFilter) bits.push(`category **${m.categoryFilter}**`);
    if (m.query) bits.push(`query **\`${m.query}\`**`);
    lines.push(`**Filter:** ${bits.join(" · ")} — **${m.totalReports}** of ${m.catalogSize} report(s).`);
  } else {
    lines.push(`**Reports:** ${m.totalReports} across ${m.groups.length} categor${m.groups.length === 1 ? "y" : "ies"}.`);
  }
  lines.push("");
  lines.push(
    `Every offline report runs purely over stored history — the IPS alert store, or for \`traffic\` the NetFlow flow ` +
      `store — with no live gateway query, no Claude and no network. ` +
      `Most accept a look-back window: on the CLI as the value after the flag (\`--scan 24\`), over HTTP as \`?hours=N\`. ` +
      `The **Window** column is each report's default. Reports with an API route also serve a downloadable Markdown ` +
      `twin at the same path with a \`.md\` suffix (shown as \`(+.md)\`).`,
  );
  lines.push("");

  if (!m.entries.length) {
    lines.push(`_No report matched the filter._`);
    lines.push("");
    lines.push("---");
    lines.push(`_Self-describing catalog generated offline by SecTool. No alert data was read._`);
    lines.push("");
    return lines.join("\n");
  }

  // A tiny table-of-contents so a long catalog is navigable.
  lines.push(`## Categories`);
  lines.push("");
  for (const g of m.groups) {
    lines.push(`- **${g.category}** — ${g.count} report(s)`);
  }
  lines.push("");

  for (const g of m.groups) {
    lines.push(`## ${g.category}`);
    lines.push("");
    lines.push(categoryTable(g.entries));
    lines.push("");
  }

  lines.push("---");
  lines.push(
    `**Usage:** CLI \`node src/index.ts <flag> [hours]\` or the matching \`npm run <name>\`; HTTP \`GET <route>?hours=N\` ` +
      `for JSON or \`<route>.md?hours=N\` for a downloadable report. Note a few flags and routes differ by name ` +
      `(\`--watchlist\` → \`/api/watchlist-activity\`, \`--safelist\` → \`/api/safelist-audit\`) — this catalog is the ` +
      `source of truth for the mapping.`,
  );
  lines.push("");
  lines.push(
    `_Self-describing catalog generated offline by SecTool. It is a **curated** index of the tool's own reports — it ` +
      `reads no alert data. A newly added report must be registered here to appear; the report count above is the ` +
      `honest tell if it has drifted._`,
  );
  lines.push("");
  return lines.join("\n");
}

/**
 * Build the report-catalog model + Markdown directory.
 *
 * @param opts {@link CatalogOptions}: an optional `query` substring filter, a
 *             `category` restriction, and a `nowMs` pin for deterministic tests.
 */
export function buildCatalog(opts: CatalogOptions = {}): CatalogReport {
  const generatedMs = opts.nowMs ?? Date.now();
  const query = opts.query?.trim().toLowerCase() || undefined;
  const categoryFilter = opts.category;

  const entries = REPORT_CATALOG.filter(
    (e) => (!categoryFilter || e.category === categoryFilter) && (!query || matchesQuery(e, query)),
  );

  const groups: CatalogGroup[] = CATEGORY_ORDER.map((category) => {
    const groupEntries = entries.filter((e) => e.category === category);
    return { category, count: groupEntries.length, entries: groupEntries };
  }).filter((g) => g.count > 0);

  const model: CatalogReport = {
    generatedMs,
    totalReports: entries.length,
    catalogSize: REPORT_CATALOG.length,
    query,
    categoryFilter,
    groups,
    entries,
    markdown: "",
  };
  model.markdown = renderMarkdown(model);
  return model;
}

/** A filesystem-safe filename for a downloaded report catalog. */
export function catalogFilename(nowMs: number): string {
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  return `sectool-catalog-${stamp}.md`;
}
