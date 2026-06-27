/**
 * Abuse-report / upstream-takedown generator — "**I know which external IPs are
 * hammering me; now write the complaint that gets them taken down at the
 * source.**"
 *
 * Every other source-side report in SecTool stops one step short of the action a
 * defender can actually take against an *external* attacker. You cannot patch a
 * stranger's botnet, and a perimeter block (see `fwrules`, `blockplan`,
 * `autoblock`) only stops that IP from reaching *you* — the host keeps scanning
 * the rest of the internet from rented or compromised infrastructure. The one
 * lever that removes the attacker rather than merely deflecting it is **reporting
 * the source to the network responsible for it**: a hosting provider that
 * terminates an abusive instance, or an ISP/RIR contact that nudges a
 * compromised customer. That lever is almost never pulled, for a boring reason —
 * writing a credible abuse complaint by hand (correct abuse desk, UTC
 * timestamps, concrete evidence, a sober tone) is tedious, so it doesn't happen.
 *
 * This report removes that friction. For the worst public attacking sources in
 * the window it produces, per IP, a **ready-to-send abuse complaint** — addressed
 * to the right desk, pre-filled with the evidence an abuse team needs to act, and
 * grouped by provider so a week's worth of complaints can be batch-sent. It is
 * the human-action sibling of the machine-feed exporters and the perimeter
 * codegen:
 *
 *   - **cloud.ts** attributes each public source to its hosting provider and
 *     surfaces the provider's abuse desk — this report *consumes* that mapping
 *     (via the shared {@link classifyProvider} / {@link providerInfo}) and turns
 *     it into the actual complaint text, per source, with evidence attached.
 *   - **fwrules.ts** renders the blocklist into deployable firewall config — a
 *     *defensive* action that keeps the attacker off your edge. This is the
 *     *offensive-disclosure* counterpart: get the attacker removed upstream.
 *   - **iocs / stix / sigma / cef** are machine-to-machine feeds for SIEMs and
 *     intel platforms. This is the one export meant for a **human** at another
 *     organisation to read and act on.
 *   - **blockplan.ts** ranks which sources to *block*; this ranks which sources
 *     are worth the effort of *reporting* — a higher bar (sustained, severe,
 *     attributable volume), because an abuse desk ignores low-signal noise.
 *
 * Selection & ranking. Only **public** IPv4 sources are eligible — RFC1918 /
 * loopback / CGN / bogon space and IPv6 are excluded (you cannot file abuse
 * against your own LAN, and a spoofable bogon source is meaningless to a
 * provider). **Safelisted** (vetted-benign) sources are excluded outright — you
 * never want to accidentally complain about a partner's scanner — and the count
 * of skipped safelisted IPs is surfaced honestly. A source must clear a
 * `minCount` evidence floor (default 5 alerts) to be worth a desk's attention.
 * Survivors are ranked by a **severity-weighted impact score** (the same
 * {@link SEVERITY_WEIGHT} the risk / efficacy / cloud reports use), so a handful
 * of critical exploit attempts outranks a flood of low-severity probes, and the
 * top `limit` become complaints.
 *
 * Each complaint carries the evidence an abuse team expects: the **attack window
 * in UTC** (first→last seen — abuse desks key everything off UTC), the **event
 * count**, the **distinct internal targets** hit, the **top signatures** (what
 * the source actually did), a few **sample raw detections** (sanitised, single-
 * line, clipped), the gateway's own **enforcement disposition** (so you can say
 * "we already block this, and it is still trying"), and the **provider
 * attribution + abuse desk**. For sources whose provider cannot be matched from
 * the offline range table, the draft degrades gracefully to RIR-whois guidance
 * (`whois <ip>` → `abuse-c` / `OrgAbuseEmail`) instead of inventing a contact.
 *
 * Honest caveats baked into the output:
 *
 *   - **Detections, not proof of malice.** IPS signatures fire on patterns; a
 *     report is a *good-faith* complaint, not an adjudication. The drafts are
 *     deliberately factual and non-accusatory.
 *   - **Source identity can be borrowed.** NAT, shared egress, rotating botnets
 *     and (for non-TCP signatures) spoofed sources all blur the address — the
 *     provider, not SecTool, confirms who actually held the IP at the time.
 *   - **Attribution is best-effort.** The provider table is a representative
 *     offline subset; a miss means *unknown desk*, never *not abusive*.
 *
 * Pure in-memory math over alertStore (plus blocklist / safelist membership and
 * the offline provider table) — no SSH, no Claude, no network. Output is both a
 * structured model and a ready-to-paste Markdown document with each complaint in
 * its own fenced block, mirroring cloud.ts, fwrules.ts and the other offline
 * exporters.
 */
import { isIP } from "node:net";
import { alertStore, type StoredAlert } from "../store/alertStore.ts";
import { blockStore } from "../store/blocklist.ts";
import { safeStore } from "../store/safelist.ts";
import { classifyProvider, providerInfo, type ProviderKind } from "./cloud.ts";
import { classifyDisposition } from "./efficacy.ts";
import { SEVERITY_WEIGHT } from "./risk.ts";
import { SEVERITY_ORDER, type Severity } from "../types.ts";

/** One signature the source tripped, with how many times. */
export interface AbuseSignatureCount {
  signature: string;
  count: number;
}

/** A single sample detection retained as evidence in a complaint. */
export interface AbuseSampleEvent {
  /** Event time (ms epoch). */
  timeMs: number;
  /** Signature that fired (may be empty if the alert had none). */
  signature: string;
  /** Derived severity of the event. */
  severity: Severity;
  /** Internal target the source hit, if known. */
  target?: string;
  /** The sanitised, single-line, clipped raw detection line. */
  raw: string;
}

/** A complete, ready-to-send abuse complaint for one source IP. */
export interface AbuseComplaint {
  /** The offending public source IP. */
  ip: string;
  /** Provider key from {@link classifyProvider}, or null if unattributable. */
  providerKey: string | null;
  /** Human provider label (or an "unknown" placeholder). */
  providerLabel: string;
  /** Coarse provider class, or "unknown" when unattributed. */
  providerKind: ProviderKind | "unknown";
  /** Abuse desk (email or URL); empty string when unknown. */
  abuseContact: string;
  /** True when the provider (and thus a desk) was matched. */
  attributable: boolean;
  /** Total windowed alerts attributed to this source. */
  alerts: number;
  /** Alerts the gateway actively blocked / dropped. */
  blocked: number;
  /** Alerts detected but passed through. */
  passed: number;
  /** Alerts with no recorded enforcement action. */
  unknown: number;
  /** blocked / (blocked + passed), or null if nothing was actioned. */
  blockRate: number | null;
  /** Alerts at medium severity or worse. */
  severe: number;
  /** Alerts at critical severity. */
  critical: number;
  /** Worst severity observed from this source. */
  severityMax: Severity;
  /** Severity-weighted impact score — the ranking key. */
  score: number;
  /** First sighting in the window (ms epoch). */
  firstSeenMs: number;
  /** Last sighting in the window (ms epoch). */
  lastSeenMs: number;
  /** Distinct internal targets this source struck. */
  distinctTargets: number;
  /** Top signatures by count (capped), the "what it did" evidence. */
  topSignatures: AbuseSignatureCount[];
  /** A few sample raw detections retained as evidence. */
  samples: AbuseSampleEvent[];
  /** The source is already on the enforced blocklist. */
  onBlocklist: boolean;
  /** Ready-to-send plain-text complaint body. */
  draft: string;
}

/** Complaints sharing one provider, for batch sending to a single desk. */
export interface AbuseProviderGroup {
  providerKey: string | null;
  providerLabel: string;
  abuseContact: string;
  attributable: boolean;
  complaints: AbuseComplaint[];
  /** Sum of alerts across the group's complaints. */
  totalAlerts: number;
}

export interface AbuseReport {
  hours: number;
  windowStartMs: number;
  windowEndMs: number;
  /** When the report was generated (ms epoch); pins draft timestamps. */
  generatedMs: number;
  /** Evidence floor: minimum alerts for a source to be worth reporting. */
  minCount: number;
  /** Max complaints emitted (after ranking). */
  limit: number;
  /** Reporting-organisation name woven into the drafts. */
  org: string;
  /** Distinct public IPv4 sources seen in the window. */
  totalPublicSources: number;
  /** Public sources that cleared the evidence floor (pre-limit, post-safelist). */
  eligibleSources: number;
  /** Safelisted public sources skipped despite clearing the floor. */
  skippedSafelisted: number;
  /** Complaints actually emitted (≤ limit). */
  reportedSources: number;
  /** Of the emitted complaints, how many have a matched abuse desk. */
  attributableSources: number;
  /** Ranked complaints, worst impact first. */
  complaints: AbuseComplaint[];
  /** Complaints grouped by provider, attributable groups first. */
  groups: AbuseProviderGroup[];
  /** Plain-language, action-oriented call-outs. */
  highlights: string[];
  /** The finished Markdown document. */
  markdown: string;
}

export interface AbuseOptions {
  /** Max complaints to emit (clamped to [1, 200]). Default 20. */
  limit?: number;
  /** Minimum alerts for a source to qualify (clamped to [1, 100000]). Default 5. */
  minCount?: number;
  /** Sample raw detections retained per complaint (clamped to [0, 10]). Default 3. */
  samples?: number;
  /** Reporting-organisation name woven into the drafts. Default "our network". */
  org?: string;
  /** Pins the window end for deterministic tests; defaults to now. */
  nowMs?: number;
}

const DEFAULT_LIMIT = 20;
const DEFAULT_MIN_COUNT = 5;
const DEFAULT_SAMPLES = 3;
const DEFAULT_ORG = "our network";
const MS_PER_HOUR = 3_600_000;
/** Top signatures retained per complaint (the "what it did" evidence). */
const MAX_TOP_SIGNATURES = 6;

// ----- shared helpers (mirror cloud.ts / silence.ts) ------------------------

/** RFC1918 / loopback / link-local / ULA / CGN / multicast — non-public. */
function isPrivate(ip: string): boolean {
  return /^(0\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|22[4-9]\.|23\d\.|24\d\.|25[0-5]\.|::1|::$|fe80|fc|fd|ff)/i.test(
    ip,
  );
}

/** A valid, public IPv4 source address, or undefined if unusable for a complaint. */
function publicIpv4(ip: string | undefined): string | undefined {
  if (!ip) return undefined;
  if (isIP(ip) !== 4) return undefined; // IPv4 only — provider table is IPv4
  return isPrivate(ip) ? undefined : ip;
}

function sevRank(s: string | undefined): number {
  const i = (SEVERITY_ORDER as readonly string[]).indexOf(s ?? "");
  return i < 0 ? 0 : i;
}

function asSeverity(s: string | undefined): Severity {
  const i = sevRank(s);
  return SEVERITY_ORDER[i] ?? "info";
}

function maxSeverity(a: Severity, b: string | undefined): Severity {
  if (!b) return a;
  return sevRank(b) > sevRank(a) ? (b as Severity) : a;
}

function weightOf(s: string | undefined): number {
  return SEVERITY_WEIGHT[(s as Severity) ?? "info"] ?? SEVERITY_WEIGHT.info;
}

function round4(n: number): number {
  return Math.round(n * 10000) / 10000;
}

function pct(frac: number | null): string {
  return frac === null ? "—" : `${Math.round(frac * 100)}%`;
}

function fmtTime(ms: number): string {
  return new Date(ms).toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
}

/** Compact "3d 4h" / "5h" / "12m" span label for a duration in hours. */
function fmtSpan(hours: number): string {
  if (hours < 1) return `${Math.max(1, Math.round(hours * 60))}m`;
  if (hours < 48) return `${Math.round(hours)}h`;
  const days = Math.floor(hours / 24);
  const rem = Math.round(hours - days * 24);
  return rem > 0 ? `${days}d ${rem}h` : `${days}d`;
}

/** Collapse a raw log line to a single, clipped, table-safe string. */
function sanitizeRaw(raw: string, max = 160): string {
  const flat = raw.replace(/[\r\n\t]+/g, " ").replace(/\s{2,}/g, " ").trim();
  return flat.length > max ? `${flat.slice(0, max - 1)}…` : flat;
}

function cell(v: unknown): string {
  return String(v ?? "").replace(/\|/g, "\\|").replace(/\n/g, " ");
}

function clip(s: string, max = 44): string {
  const t = s.trim();
  return t.length > max ? `${t.slice(0, max - 1)}…` : t;
}

function mdTable(headers: string[], rows: string[][]): string {
  if (!rows.length) return "_None._";
  const head = `| ${headers.join(" | ")} |`;
  const sep = `| ${headers.map(() => "---").join(" | ")} |`;
  const body = rows.map((r) => `| ${r.join(" | ")} |`).join("\n");
  return `${head}\n${sep}\n${body}`;
}

// ----- aggregation ----------------------------------------------------------

interface SrcAcc {
  alerts: number;
  blocked: number;
  passed: number;
  unknown: number;
  severe: number;
  critical: number;
  score: number;
  severityMax: Severity;
  firstSeenMs: number;
  lastSeenMs: number;
  targets: Set<string>;
  sigCounts: Map<string, number>;
  samples: AbuseSampleEvent[];
}

function newSrcAcc(): SrcAcc {
  return {
    alerts: 0,
    blocked: 0,
    passed: 0,
    unknown: 0,
    severe: 0,
    critical: 0,
    score: 0,
    severityMax: "info",
    firstSeenMs: Number.POSITIVE_INFINITY,
    lastSeenMs: Number.NEGATIVE_INFINITY,
    targets: new Set(),
    sigCounts: new Map(),
    samples: [],
  };
}

function fold(acc: SrcAcc, a: StoredAlert): void {
  acc.alerts++;
  const disp = classifyDisposition(a.action);
  if (disp === "blocked") acc.blocked++;
  else if (disp === "passed") acc.passed++;
  else acc.unknown++;

  const rank = sevRank(a.severity);
  if (rank >= 2) acc.severe++;
  if (rank >= 4) acc.critical++;
  acc.score += weightOf(a.severity);
  acc.severityMax = maxSeverity(acc.severityMax, a.severity);

  if (a.time < acc.firstSeenMs) acc.firstSeenMs = a.time;
  if (a.time > acc.lastSeenMs) acc.lastSeenMs = a.time;

  const dst = a.dstIp;
  if (dst && isPrivate(dst)) acc.targets.add(dst);

  const sig = (a.signature ?? "").trim();
  if (sig) acc.sigCounts.set(sig, (acc.sigCounts.get(sig) ?? 0) + 1);

  // Keep a bounded pool of the most compelling sample detections: highest
  // severity first, then most recent. We over-collect a little then trim.
  if (a.raw) {
    acc.samples.push({
      timeMs: a.time,
      signature: sig,
      severity: asSeverity(a.severity),
      ...(dst ? { target: dst } : {}),
      raw: a.raw,
    });
  }
}

function topSignatures(counts: Map<string, number>, limit: number): AbuseSignatureCount[] {
  return [...counts.entries()]
    .map(([signature, count]) => ({ signature, count }))
    .sort((a, b) => b.count - a.count || (a.signature < b.signature ? -1 : 1))
    .slice(0, limit);
}

function pickSamples(pool: AbuseSampleEvent[], limit: number): AbuseSampleEvent[] {
  if (limit <= 0) return [];
  return [...pool]
    .sort((a, b) => sevRank(b.severity) - sevRank(a.severity) || b.timeMs - a.timeMs)
    .slice(0, limit)
    .map((s) => ({ ...s, raw: sanitizeRaw(s.raw) }));
}

// ----- complaint drafting ---------------------------------------------------

/**
 * Render the plain-text complaint body for one source. Deterministic: every
 * timestamp comes from the event data or the pinned `generatedMs`, never a live
 * clock, so re-running over the same store yields byte-identical drafts.
 */
function draftComplaint(c: Omit<AbuseComplaint, "draft">, org: string, generatedMs: number): string {
  const lines: string[] = [];
  const desk = c.attributable && c.abuseContact ? c.abuseContact : "(see note below)";

  lines.push(`To: ${desk}`);
  lines.push(
    `Subject: Network abuse report — ${c.ip} (${c.severityMax} severity, ${c.alerts} event(s), ${fmtTime(c.firstSeenMs)} – ${fmtTime(c.lastSeenMs)})`,
  );
  lines.push("");
  lines.push(`Hello${c.attributable ? ` ${c.providerLabel} Abuse Team` : ""},`);
  lines.push("");
  lines.push(
    `We are writing to report network abuse originating from an IP address ${c.attributable ? `within your network` : `that we believe is under your administration`}. ` +
      `Our intrusion-detection systems recorded ${c.alerts} security event(s) from this source against ${org}. ` +
      `All timestamps below are UTC.`,
  );
  lines.push("");
  lines.push(`  Offending IP:      ${c.ip}`);
  if (c.attributable) lines.push(`  Attributed to:     ${c.providerLabel} (${c.providerKind})`);
  lines.push(`  Events observed:   ${c.alerts}` + (c.severe ? ` (${c.severe} medium+, ${c.critical} critical)` : ""));
  lines.push(`  First seen (UTC):  ${fmtTime(c.firstSeenMs)}`);
  lines.push(`  Last seen (UTC):   ${fmtTime(c.lastSeenMs)}`);
  lines.push(`  Distinct targets:  ${c.distinctTargets} host(s) on our network`);
  lines.push(`  Worst severity:    ${c.severityMax}`);
  lines.push("");

  if (c.topSignatures.length) {
    lines.push(`Observed activity (intrusion-detection signatures, most frequent first):`);
    for (const s of c.topSignatures) lines.push(`  - ${s.signature} (${s.count}x)`);
    lines.push("");
  }

  if (c.samples.length) {
    lines.push(`Sample detections (raw, UTC-timestamped):`);
    for (const s of c.samples) {
      lines.push(`  [${fmtTime(s.timeMs)}] ${s.raw}`);
    }
    lines.push("");
  }

  lines.push(
    `We have ${c.onBlocklist ? "already blocked this source at our perimeter" : "logged this activity"}, ` +
      `but the traffic ${c.onBlocklist ? "continued to arrive, indicating the source remains active" : "is ongoing"}. ` +
      `We ask that you investigate the account or instance responsible and take appropriate action ` +
      `(suspension, remediation, or notification of the responsible party) under your acceptable-use policy.`,
  );
  lines.push("");
  if (!c.attributable) {
    lines.push(
      `NOTE: We could not automatically determine the correct abuse contact for ${c.ip}. ` +
        `Look it up with "whois ${c.ip}" and send to the listed abuse-c / OrgAbuseEmail / RIR abuse address.`,
    );
    lines.push("");
  }
  lines.push(`Please reference ${c.ip} in any reply. Thank you for your prompt attention.`);
  lines.push("");
  lines.push(`Regards,`);
  lines.push(`${org} — Security Operations`);
  lines.push(`(Report generated ${fmtTime(generatedMs)})`);

  return lines.join("\n");
}

// ----- highlights -----------------------------------------------------------

function writeHighlights(
  base: Omit<AbuseReport, "highlights" | "markdown">,
): string[] {
  const out: string[] = [];
  if (base.reportedSources === 0) return out; // handled in the empty Markdown branch

  const top = base.complaints[0];
  if (top) {
    out.push(
      `🚩 Top complaint: \`${top.ip}\`${top.attributable ? ` (${top.providerLabel})` : " (unattributed — whois needed)"} ` +
        `fired **${top.alerts}** event(s) (${top.severe} medium+, ${top.critical} critical) across ` +
        `${fmtSpan((top.lastSeenMs - top.firstSeenMs) / MS_PER_HOUR)}, worst severity **${top.severityMax}**. ` +
        `${top.attributable ? `Send to **${top.abuseContact}**.` : `Resolve the desk with \`whois ${top.ip}\`.`}`,
    );
  }

  const attributable = base.groups.filter((g) => g.attributable);
  if (attributable.length) {
    const desks = attributable
      .slice(0, 4)
      .map((g) => `${g.providerLabel} (${g.complaints.length})`)
      .join(", ");
    out.push(
      `📬 ${base.attributableSources}/${base.reportedSources} complaint(s) have a known abuse desk, across ` +
        `${attributable.length} provider(s): ${desks}${attributable.length > 4 ? ", …" : ""}. ` +
        `Batch-send each provider's group in one message.`,
    );
  }

  const unattributed = base.reportedSources - base.attributableSources;
  if (unattributed > 0) {
    out.push(
      `🔎 ${unattributed} complaint(s) hit an unmatched network (residential / ISP / RIR space). ` +
        `The drafts include \`whois\` guidance to find the right abuse-c address.`,
    );
  }

  const stillTrying = base.complaints.filter((c) => c.onBlocklist).length;
  if (stillTrying > 0) {
    out.push(
      `⛔ ${stillTrying} source(s) you **already block** are still firing — perimeter deflection isn't stopping them at ` +
        `the origin, which is exactly the case an upstream takedown is for.`,
    );
  }

  if (base.skippedSafelisted > 0) {
    out.push(
      `✅ Skipped ${base.skippedSafelisted} safelisted (vetted-benign) source(s) that cleared the evidence floor — ` +
        `you never want to file abuse against a partner's scanner.`,
    );
  }

  return out;
}

// ----- markdown -------------------------------------------------------------

function complaintEvidenceTable(c: AbuseComplaint): string {
  return mdTable(
    ["Field", "Value"],
    [
      ["Events", `${c.alerts} (${c.severe} medium+, ${c.critical} critical)`],
      ["Window (UTC)", `${fmtTime(c.firstSeenMs)} → ${fmtTime(c.lastSeenMs)} (${fmtSpan((c.lastSeenMs - c.firstSeenMs) / MS_PER_HOUR)})`],
      ["Worst severity", c.severityMax],
      ["Distinct targets", String(c.distinctTargets)],
      ["Gateway disposition", `${c.blocked} blocked / ${c.passed} passed / ${c.unknown} unknown (block rate ${pct(c.blockRate)})`],
      ["Abuse desk", c.attributable ? `\`${c.abuseContact || "—"}\`` : "_unmatched — run `whois`_"],
      ["Already blocked here", c.onBlocklist ? "yes ⛔" : "no"],
    ].map((r) => r.map(cell)),
  );
}

function renderMarkdown(m: AbuseReport): string {
  const lines: string[] = [];
  lines.push(`# 📮 SecTool Abuse-Report / Upstream-Takedown Worklist`);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(m.generatedMs)}`);
  lines.push(`**Window:** last ${m.hours} hour(s) — ${fmtTime(m.windowStartMs)} → ${fmtTime(m.windowEndMs)}`);
  lines.push(
    `**Method:** public IPv4 sources with **≥ ${m.minCount}** alert(s) (safelisted excluded), ranked by ` +
      `severity-weighted impact; top **${m.limit}** become complaints. Offline, deterministic · ` +
      `**Public sources:** ${m.totalPublicSources} · **Eligible:** ${m.eligibleSources} · **Reported:** ${m.reportedSources}`,
  );
  lines.push("");

  lines.push(`## Summary`);
  lines.push("");
  if (m.reportedSources === 0) {
    lines.push(
      `No public source cleared the evidence floor of **${m.minCount}** alert(s) in the last ${m.hours}h` +
        (m.skippedSafelisted > 0
          ? ` (after excluding ${m.skippedSafelisted} safelisted source(s))`
          : ``) +
        `, so there is nothing worth an upstream complaint. Lower the bar with \`--min-count <n>\` or widen the ` +
        `window (\`--abuse <more hours>\`) if you want to report lighter-touch scanners.`,
    );
    lines.push("");
    lines.push("---");
    lines.push(`_Generated offline by SecTool. No live gateway query was performed._`);
    lines.push("");
    return lines.join("\n");
  }
  for (const h of m.highlights) lines.push(`- ${h}`);
  lines.push("");

  // Send queue: one row per provider group so a desk's complaints batch together.
  lines.push(`## Send queue (grouped by abuse desk)`);
  lines.push("");
  lines.push(
    mdTable(
      ["Provider / network", "Abuse desk", "Complaints", "Total events"],
      m.groups.map((g) => [
        cell(g.providerLabel),
        g.attributable ? cell(`\`${g.abuseContact || "—"}\``) : "_whois needed_",
        String(g.complaints.length),
        String(g.totalAlerts),
      ]),
    ),
  );
  lines.push("");
  lines.push(
    `**Legend:** complaints are ranked by severity-weighted impact (a few critical events outweigh a flood of ` +
      `probes). Each complaint below is a ready-to-send draft — copy the fenced block, confirm the desk, and send. ` +
      `Drafts are factual and non-accusatory by design: an abuse report is a good-faith notice, not a verdict.`,
  );
  lines.push("");

  // Per-complaint detail, grouped by provider for batch sending.
  let n = 0;
  for (const g of m.groups) {
    lines.push(`## ${g.providerLabel}${g.attributable && g.abuseContact ? ` — \`${g.abuseContact}\`` : ""}`);
    lines.push("");
    if (!g.attributable) {
      lines.push(
        `_No abuse desk was matched from the offline provider table for these sources. Resolve each with ` +
          `\`whois <ip>\` and use the listed \`abuse-c\` / \`OrgAbuseEmail\` / RIR abuse address._`,
      );
      lines.push("");
    }
    for (const c of g.complaints) {
      n++;
      lines.push(`### ${n}. \`${c.ip}\` — ${c.severityMax}, ${c.alerts} event(s)`);
      lines.push("");
      lines.push(complaintEvidenceTable(c));
      lines.push("");
      if (c.topSignatures.length) {
        lines.push(`**Top signatures:** ` + c.topSignatures.map((s) => `${clip(s.signature, 50)} (${s.count})`).join("; "));
        lines.push("");
      }
      lines.push(`**Draft complaint** — copy and send:`);
      lines.push("");
      lines.push("```text");
      lines.push(c.draft);
      lines.push("```");
      lines.push("");
    }
  }

  lines.push("---");
  lines.push(
    `_Generated offline by SecTool. These drafts are **good-faith abuse notices** built from IPS **detections**, ` +
      `not adjudicated proof of malice — keep them factual. Source identity can be borrowed (NAT, shared egress, ` +
      `rotating botnets, spoofed non-TCP sources): the provider, not SecTool, confirms who held the IP at the time. ` +
      `Provider attribution is a best-effort offline match — an unmatched network means *unknown desk*, never *not ` +
      `abusive*; resolve those with \`whois\`. Safelisted sources are excluded so you never file against a vetted ` +
      `partner. No live gateway query was performed._`,
  );
  lines.push("");
  return lines.join("\n");
}

/**
 * Build the abuse-report / upstream-takedown worklist from the stored alert
 * history.
 *
 * @param hours Look-back window in hours (clamped to [1, 90 days]).
 * @param opts  {@link AbuseOptions}: `limit`, `minCount`, `samples`, `org`, and a
 *              `nowMs` pin for deterministic tests.
 */
export function buildAbuse(hours: number, opts: AbuseOptions = {}): AbuseReport {
  const safeHours = Math.max(1, Math.min(24 * 90, Math.floor(hours)));
  const limit = Math.max(1, Math.min(200, Math.floor(opts.limit ?? DEFAULT_LIMIT)));
  const minCount = Math.max(1, Math.min(100_000, Math.floor(opts.minCount ?? DEFAULT_MIN_COUNT)));
  const samples = Math.max(0, Math.min(10, Math.floor(opts.samples ?? DEFAULT_SAMPLES)));
  const org = (opts.org ?? DEFAULT_ORG).trim() || DEFAULT_ORG;
  const generatedMs = opts.nowMs ?? Date.now();
  const windowEndMs = generatedMs;
  const windowStartMs = windowEndMs - safeHours * MS_PER_HOUR;

  const windowed = alertStore
    .all()
    .filter((a): a is StoredAlert => typeof a.time === "number" && Number.isFinite(a.time))
    .filter((a) => a.time >= windowStartMs && a.time <= windowEndMs);

  const bySource = new Map<string, SrcAcc>();
  for (const a of windowed) {
    const src = publicIpv4(a.srcIp);
    if (!src) continue;
    let acc = bySource.get(src);
    if (!acc) {
      acc = newSrcAcc();
      bySource.set(src, acc);
    }
    fold(acc, a);
  }

  const totalPublicSources = bySource.size;

  // Eligibility: clear the evidence floor and not be safelisted.
  let skippedSafelisted = 0;
  const eligible: Array<[string, SrcAcc]> = [];
  for (const [ip, acc] of bySource) {
    if (acc.alerts < minCount) continue;
    if (safeStore.has(ip)) {
      skippedSafelisted++;
      continue;
    }
    eligible.push([ip, acc]);
  }

  // Rank by severity-weighted impact, then raw volume, then IP for determinism.
  eligible.sort(
    (a, b) =>
      b[1].score - a[1].score ||
      b[1].alerts - a[1].alerts ||
      (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0),
  );

  const complaints: AbuseComplaint[] = eligible.slice(0, limit).map(([ip, acc]) => {
    const providerKey = classifyProvider(ip);
    const info = providerKey ? providerInfo(providerKey) : null;
    const attributable = info !== null && !!info.abuse;
    const actioned = acc.blocked + acc.passed;
    const base: Omit<AbuseComplaint, "draft"> = {
      ip,
      providerKey,
      providerLabel: info?.label ?? "Unknown network (RIR lookup needed)",
      providerKind: info?.kind ?? "unknown",
      abuseContact: info?.abuse ?? "",
      attributable,
      alerts: acc.alerts,
      blocked: acc.blocked,
      passed: acc.passed,
      unknown: acc.unknown,
      blockRate: actioned ? round4(acc.blocked / actioned) : null,
      severe: acc.severe,
      critical: acc.critical,
      severityMax: acc.severityMax,
      score: round4(acc.score),
      firstSeenMs: Number.isFinite(acc.firstSeenMs) ? acc.firstSeenMs : windowStartMs,
      lastSeenMs: Number.isFinite(acc.lastSeenMs) ? acc.lastSeenMs : windowEndMs,
      distinctTargets: acc.targets.size,
      topSignatures: topSignatures(acc.sigCounts, MAX_TOP_SIGNATURES),
      samples: pickSamples(acc.samples, samples),
      onBlocklist: blockStore.has(ip),
    };
    return { ...base, draft: draftComplaint(base, org, generatedMs) };
  });

  // Group by provider for batch sending: attributable groups first (by total
  // volume), then the single unattributed bucket last.
  const groupMap = new Map<string, AbuseProviderGroup>();
  for (const c of complaints) {
    const gid = c.attributable ? (c.providerKey ?? "?") : "__unattributed__";
    let g = groupMap.get(gid);
    if (!g) {
      g = {
        providerKey: c.attributable ? c.providerKey : null,
        providerLabel: c.attributable ? c.providerLabel : "Unattributed (whois needed)",
        abuseContact: c.attributable ? c.abuseContact : "",
        attributable: c.attributable,
        complaints: [],
        totalAlerts: 0,
      };
      groupMap.set(gid, g);
    }
    g.complaints.push(c);
    g.totalAlerts += c.alerts;
  }
  const groups = [...groupMap.values()].sort((a, b) => {
    if (a.attributable !== b.attributable) return a.attributable ? -1 : 1;
    return b.totalAlerts - a.totalAlerts || (a.providerLabel < b.providerLabel ? -1 : 1);
  });

  const base: Omit<AbuseReport, "highlights" | "markdown"> = {
    hours: safeHours,
    windowStartMs,
    windowEndMs,
    generatedMs,
    minCount,
    limit,
    org,
    totalPublicSources,
    eligibleSources: eligible.length,
    skippedSafelisted,
    reportedSources: complaints.length,
    attributableSources: complaints.filter((c) => c.attributable).length,
    complaints,
    groups,
  };

  const highlights = writeHighlights(base);
  const model: AbuseReport = { ...base, highlights, markdown: "" };
  model.markdown = renderMarkdown(model);
  return model;
}

/** A filesystem-safe filename for a downloaded abuse-report worklist. */
export function abuseFilename(nowMs: number): string {
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  return `sectool-abuse-${stamp}.md`;
}
