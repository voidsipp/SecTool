/**
 * Snort / Suricata native IDS-rule export — turn the stored alert history into a
 * **ready-to-load `.rules` file** (and a Suricata IP-reputation triplet) that
 * feeds the very kind of sensor that produced these alerts in the first place.
 *
 * SecTool *ingests* Suricata IDS/IPS alerts off the UDM Pro; this export closes
 * the loop on the **sensor** side, the one surface none of the existing exports
 * reach:
 *
 *   - iocExport.ts (`--iocs`) emits plain / csv / json indicator lists — perfect
 *     for `ipset` or a spreadsheet, but no IDS engine recognises them as *rules*.
 *   - stix.ts (`--stix`) emits an OASIS STIX 2.1 bundle — the threat-intel
 *     *interchange* object for a TI platform (MISP / OpenCTI / TAXII), not a
 *     detection engine.
 *   - sigma.ts (`--sigma`) emits vendor-neutral **Sigma** rules — detection-as-code
 *     for a *SIEM* (Splunk / Elastic / Sentinel) that fires on ingested *logs*.
 *   - fwrules.ts (`--fwrules`) renders the enforced blocklist into *firewall*
 *     config (iptables / nft / pf / UniFi) — the perimeter-enforcement codegen.
 *   - ruleset.ts (`--ruleset`) *inventories* which Suricata SIDs already fired
 *     (provenance) — it reads rules, it does not write them.
 *
 * This module emits the one format the **inline IDS/IPS** ecosystem speaks
 * natively: Snort / Suricata `.rules`. A generated rule drops straight into a
 * sensor's `local.rules` (or a Suricata `rule-files:` include) and the engine
 * starts `alert`-ing — or, in IPS mode, `drop`-ping — the moment a known-bad
 * address appears, **in either direction** (an inbound probe *or* an internal
 * host calling back out to the same address — the C2-beacon case). That is the
 * packet-level enforcement a SIEM Sigma rule (log-side) and a STIX bundle (intel)
 * structurally cannot do, and it lives on the sensor rather than the firewall, so
 * it complements `--fwrules` instead of duplicating it.
 *
 * Rather than re-deriving the indicator set, this report **reuses
 * {@link buildIocExport}** as its scoring engine — exactly as stix.ts and
 * sigma.ts do — so the same confidence model, severity floor, safelist exclusion
 * and dismissed-alert handling that make the IOC export trustworthy as a
 * blocklist source apply here verbatim. No detection logic is duplicated.
 *
 * Output flavours (`--format`):
 *   - **suricata** (default) — one Suricata `<action> ip [ip] any <> $HOME_NET
 *     any (...)` rule per indicator, bidirectional, with a severity-mapped
 *     `classtype`/`priority`, a `metadata:` provenance trail and a deterministic
 *     `sid`. `--consolidated` collapses the whole set into one IP-list rule.
 *   - **snort** — the same rules tuned for the Snort 2.9/3 dialect (Snort-style
 *     `metadata:` and a `reference:`; `flowbits`-free IP rules).
 *   - **iprep** — the *native* Suricata IP-reputation mechanism: a category file,
 *     a `<ip>,<category>,<reputation>` list (confidence rescaled to Suricata's
 *     1–127 reputation range) and the activating `iprep:` rule. This is how
 *     Suricata is *designed* to consume a large, frequently-refreshed blocklist —
 *     far cheaper than thousands of per-IP address-match rules.
 *   - **json** — the structured model, for programmatic consumers.
 *   - **md** — a human Markdown review twin (eyeball before you load it).
 *
 * **Deterministic, idempotent identifiers.** Every Snort/Suricata rule needs a
 * unique numeric `sid`. Random or sequential ids would re-key the ruleset on
 * every export, so a detection-as-code repo would see churn. Instead each `sid`
 * is derived **deterministically from the indicator IP** inside the local
 * custom-rule range (≥ 1,000,000), de-collided in a fixed order — so the *same
 * attacker IP always maps to the same sid across runs* and a recurring export
 * produces a clean git diff. The `created_at` metadata is driven by the pinned
 * `nowMs`, so identical input yields byte-identical output (testable).
 *
 * Honest caveats baked into the output:
 *   - **`drop` needs inline IPS mode.** A UDM Pro / sensor running in IDS-only
 *     (tap / SPAN) mode cannot drop — it will only `alert`. The default action is
 *     therefore the safe `alert`; pass `--action drop` (or `reject`) once you have
 *     confirmed the sensor is inline. The header documents the requirement.
 *   - **IP-reputation rules age.** An address reassigned to a benign tenant will
 *     start false-positiving; a recurring export naturally retires indicators that
 *     fall out of window.
 *   - **`$HOME_NET` must be defined** in the sensor's `vars` (it almost always is)
 *     — the rules match `[bad-ip] <> $HOME_NET` so they ignore bad-IP↔internet
 *     noise the sensor never sees anyway.
 *   - **Confidence is heuristic, not vetted intel** (same model as `--iocs`);
 *     review before wiring `drop`.
 *   - **Safelisted IPs are excluded by default**, exactly as in the IOC export.
 *
 * Pure in-memory math over alertStore (via iocExport) — no SSH, no Claude, no
 * network. Output is a structured model, a ready-to-load rules string and a human
 * Markdown review twin, mirroring sigma.ts and the other offline reports so it
 * plugs into the same CLI and HTTP plumbing.
 */
import { createHash } from "node:crypto";
import { buildIocExport, type IocIndicator } from "./iocExport.ts";
import type { Severity } from "../types.ts";

/** Engine dialect the rules target. */
export type SnortDialect = "suricata" | "snort";

/** Output flavour the export renders into. */
export type SnortFormat = "suricata" | "snort" | "iprep" | "json" | "md";

/** Rule action verb. `drop`/`reject` require an inline (IPS) sensor. */
export type SnortAction = "alert" | "drop" | "reject";

/**
 * Base of the local custom-rule SID range. Snort/Suricata reserve sid < 1,000,000
 * for distributed rulesets (GPL/ET ≈ 2,000,000+, Talos ≈ 1–1,000,000); local
 * rules conventionally live at ≥ 1,000,000, so we allocate there to avoid ever
 * colliding with a shipped rule.
 */
const SID_BASE = 1_000_000;
/** Width of the per-IP SID space (1,000,000 … 1,899,999); reserved tail above. */
const SID_SPAN = 900_000;
/** Fixed SIDs for the non-per-IP rules (consolidated list rule, iprep activators). */
const SID_CONSOLIDATED = 1_900_001;
const SID_IPREP_SRC = 1_900_010;
const SID_IPREP_DST = 1_900_011;

/** The Suricata iprep category number + short name SecTool publishes under. */
const IPREP_CATEGORY_ID = 1;
const IPREP_CATEGORY_NAME = "SecTool";
/** iprep activates when an IP's reputation in our category exceeds this (1–127). */
const IPREP_THRESHOLD = 30;

/**
 * Severity → Suricata/Snort `classtype` + numeric `priority` (1 = most urgent).
 * `classtype`s are drawn from the stock `classification.config` both engines ship
 * so the generated rules slot into existing severity dashboards.
 */
const SEVERITY_CLASS: Record<Severity, { classtype: string; priority: number }> = {
  critical: { classtype: "attempted-admin", priority: 1 },
  high: { classtype: "trojan-activity", priority: 1 },
  medium: { classtype: "misc-attack", priority: 2 },
  low: { classtype: "misc-activity", priority: 3 },
  info: { classtype: "not-suspicious", priority: 3 },
};

/** A single rendered IDS rule, kept structured for the JSON / markdown views. */
export interface SnortRule {
  /** Deterministic numeric Snort/Suricata `sid`. */
  sid: number;
  /** The attacker IP this rule matches (absent on the consolidated / iprep rules). */
  ip?: string;
  /** Worst observed severity for the indicator (drives classtype/priority). */
  severity?: Severity;
  /** SecTool 0–100 blocklist confidence (absent on consolidated / iprep rules). */
  confidence?: number;
  /** The rule action verb actually emitted. */
  action: SnortAction;
  /** The full rule line. */
  text: string;
}

export interface SnortReport {
  hours: number;
  windowStartMs: number;
  windowEndMs: number;
  /** Severity floor applied to qualify as an indicator (from the IOC engine). */
  minSeverity: Severity;
  /** Engine dialect targeted. */
  dialect: SnortDialect;
  /** Output flavour requested. */
  format: SnortFormat;
  /** Rule action verb emitted. */
  action: SnortAction;
  /** Whether output is the single consolidated list rule (true) or per-indicator. */
  consolidated: boolean;
  /** Distinct attacker IPs that qualified as indicators. */
  indicatorCount: number;
  /** IDS rules emitted (== indicatorCount per-indicator, or 1 consolidated). */
  ruleCount: number;
  /** Indicators dropped because the IP is safelisted (explicitly trusted). */
  excludedSafe: number;
  /** Indicators dropped because their worst severity was below the floor. */
  excludedBelowSeverity: number;
  /** Indicators truncated by the `limit`. */
  truncated: number;
  /** The rendered rules (structured). */
  rules: SnortRule[];
  /** The full deliverable: a ready-to-load `.rules` (or iprep) text string. */
  text: string;
  /** A human Markdown review twin (eyeball before loading). */
  markdown: string;
}

export interface SnortOptions {
  /** Severity floor (default `medium`, inherited from the IOC engine). */
  minSeverity?: Severity;
  /** Cap on emitted indicators, highest confidence first (default: no cap). */
  limit?: number;
  /** Include safelisted IPs instead of excluding them (default false). */
  includeSafe?: boolean;
  /** Emit a single consolidated IP-list rule instead of per-indicator rules. */
  consolidated?: boolean;
  /** Engine dialect (default `suricata`). */
  dialect?: SnortDialect;
  /** Output flavour (default `suricata`). */
  format?: SnortFormat;
  /** Rule action verb (default `alert` — the IDS-safe choice). */
  action?: SnortAction;
  /** Pins the window end / timestamps for deterministic tests; defaults to now. */
  nowMs?: number;
}

// ----- helpers ---------------------------------------------------------------

function fmtTime(ms: number): string {
  return new Date(ms).toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
}

/** Suricata `metadata:` date stamp — `YYYY_MM_DD`. */
function metaDate(ms: number): string {
  return new Date(ms).toISOString().slice(0, 10).replace(/-/g, "_");
}

function mdCell(v: unknown): string {
  return String(v ?? "").replace(/\|/g, "\\|").replace(/\n/g, " ");
}

/**
 * Sanitise free text for inclusion inside a double-quoted rule option (`msg:`).
 * Snort/Suricata option strings are `"..."`-delimited and use `\` escaping; a
 * stray `"`, `;` or `\` would terminate the option or the rule early.
 */
function ruleString(s: string): string {
  return s
    .replace(/\\/g, "\\\\")
    .replace(/"/g, '\\"')
    .replace(/;/g, "\\;")
    .replace(/[\r\n]+/g, " ")
    .trim();
}

/**
 * Deterministic per-IP SID in the local custom range, de-collided against
 * `used` by linear probe. Assigning in a fixed indicator order makes the whole
 * map reproducible, so the same IP keeps the same sid across runs (idempotent
 * exports, clean diffs — the SID analogue of sigma.ts's UUIDv5 ids).
 */
function sidForIp(ip: string, used: Set<number>): number {
  const h = createHash("sha1").update(ip).digest();
  let sid = SID_BASE + (h.readUInt32BE(0) % SID_SPAN);
  while (used.has(sid)) sid = SID_BASE + (((sid - SID_BASE) + 1) % SID_SPAN);
  used.add(sid);
  return sid;
}

/** Rescale the IOC engine's 0–100 confidence onto Suricata's 1–127 reputation. */
function toReputation(confidence: number): number {
  return Math.max(1, Math.min(127, Math.round((confidence / 100) * 127)));
}

// ----- rule builders ---------------------------------------------------------

/** Compose the `msg:` text shared by per-IP rules (already rule-string-safe). */
function indicatorMsg(ind: IocIndicator): string {
  const sig = ind.signatures[0] ? ` lead-sig ${ind.signatures[0]}` : "";
  return ruleString(
    `SecTool blocklist: known-bad host ${ind.ip} ` +
      `[conf ${ind.confidence} sev ${ind.severityMax} alerts ${ind.alertCount}${sig}]`,
  );
}

/**
 * Build one per-indicator IDS rule line. Matches the attacker IP as **either
 * endpoint** of a conversation with `$HOME_NET` (`<>`), so an inbound probe and
 * an internal host's outbound call-back to the same address both fire.
 */
function buildIndicatorRule(
  ind: IocIndicator,
  sid: number,
  action: SnortAction,
  dialect: SnortDialect,
  nowMs: number,
): SnortRule {
  const cls = SEVERITY_CLASS[ind.severityMax] ?? SEVERITY_CLASS.medium;
  const opts: string[] = [];
  opts.push(`msg:"${indicatorMsg(ind)}"`);
  opts.push(`classtype:${cls.classtype}`);
  opts.push(`priority:${cls.priority}`);
  if (dialect === "suricata") {
    opts.push(
      `metadata:created_at ${metaDate(ind.firstSeen)}, updated_at ${metaDate(nowMs)}, ` +
        `sectool_confidence ${ind.confidence}, sectool_severity ${ind.severityMax}`,
    );
  } else {
    // Snort prefers a reference + a simpler metadata list.
    opts.push(`reference:url,github.com/anthropics/sectool`);
    opts.push(`metadata:policy security-ips drop, service unknown`);
  }
  opts.push(`sid:${sid}`);
  opts.push(`rev:1`);
  const text = `${action} ip [${ind.ip}] any <> $HOME_NET any (${opts.join("; ")};)`;
  return { sid, ip: ind.ip, severity: ind.severityMax, confidence: ind.confidence, action, text };
}

/** Build the single consolidated IP-list rule covering every indicator. */
function buildConsolidatedRule(
  indicators: IocIndicator[],
  hours: number,
  action: SnortAction,
  dialect: SnortDialect,
  nowMs: number,
): SnortRule {
  // The rule's classtype tracks the worst severity in the set so one critical
  // indicator does not get diluted into a low-priority alert.
  const order: Severity[] = ["info", "low", "medium", "high", "critical"];
  const worst = indicators.reduce<Severity>(
    (acc, ind) => (order.indexOf(ind.severityMax) > order.indexOf(acc) ? ind.severityMax : acc),
    "info",
  );
  const cls = SEVERITY_CLASS[worst] ?? SEVERITY_CLASS.medium;
  const list = indicators.map((i) => i.ip).join(",");
  const opts: string[] = [];
  opts.push(
    `msg:"${ruleString(
      `SecTool blocklist: traffic to/from any of ${indicators.length} known-bad host(s) (last ${hours}h, worst ${worst})`,
    )}"`,
  );
  opts.push(`classtype:${cls.classtype}`);
  opts.push(`priority:${cls.priority}`);
  if (dialect === "suricata") {
    opts.push(`metadata:updated_at ${metaDate(nowMs)}, sectool_indicators ${indicators.length}, sectool_severity ${worst}`);
  } else {
    opts.push(`metadata:policy security-ips drop`);
  }
  opts.push(`sid:${SID_CONSOLIDATED}`);
  opts.push(`rev:1`);
  const text = `${action} ip [${list}] any <> $HOME_NET any (${opts.join("; ")};)`;
  return { sid: SID_CONSOLIDATED, severity: worst, action, text };
}

// ----- iprep flavour ---------------------------------------------------------

/**
 * The Suricata IP-reputation deliverable: the category-definition line, the
 * `<ip>,<category>,<reputation>` reputation list, and the two activating rules
 * (src + dst) that fire on any IP whose SecTool reputation clears the threshold.
 * This is how Suricata is designed to consume a large, frequently-refreshed
 * blocklist — O(1) per packet via the reputation table, not thousands of
 * address-match rules.
 */
function buildIprep(
  indicators: IocIndicator[],
  action: SnortAction,
  nowMs: number,
): { categories: string; list: string; rules: SnortRule[] } {
  const categories =
    `# SecTool Suricata IP-reputation categories — load via:\n` +
    `#   reputation-categories-file: sectool-categories.txt\n` +
    `# id,short name,description\n` +
    `${IPREP_CATEGORY_ID},${IPREP_CATEGORY_NAME},SecTool-observed attacker reputation (offline export)\n`;

  const listLines: string[] = [
    `# SecTool Suricata IP-reputation list — load via:\n#   reputation-files:\n#     - sectool-reputation.list`,
    `# ip,category,reputation(1-127)   (generated ${fmtTime(nowMs)})`,
  ];
  for (const ind of indicators) {
    listLines.push(`${ind.ip},${IPREP_CATEGORY_ID},${toReputation(ind.confidence)}`);
  }
  const list = listLines.join("\n") + "\n";

  const cls = SEVERITY_CLASS.medium;
  const mk = (sid: number, dir: "src" | "dst"): SnortRule => {
    const opts = [
      `msg:"${ruleString(
        `SecTool iprep: ${dir} IP in category ${IPREP_CATEGORY_NAME} over reputation ${IPREP_THRESHOLD}`,
      )}"`,
      `iprep:${dir},${IPREP_CATEGORY_NAME},>,${IPREP_THRESHOLD}`,
      `classtype:${cls.classtype}`,
      `priority:${cls.priority}`,
      `metadata:updated_at ${metaDate(nowMs)}, sectool_iprep ${IPREP_CATEGORY_NAME}`,
      `sid:${sid}`,
      `rev:1`,
    ];
    return { sid, action, text: `${action} ip any any -> $HOME_NET any (${opts.join("; ")};)` };
  };
  return { categories, list, rules: [mk(SID_IPREP_SRC, "src"), mk(SID_IPREP_DST, "dst")] };
}

// ----- text deliverable headers ----------------------------------------------

function rulesHeader(m: Omit<SnortReport, "text" | "markdown" | "rules">): string {
  const lines = [
    `# SecTool ${m.dialect === "snort" ? "Snort" : "Suricata"} IDS-rule export`,
    `# Window: last ${m.hours}h (${fmtTime(m.windowStartMs)} -> ${fmtTime(m.windowEndMs)})`,
    `# Mode: ${m.consolidated ? "consolidated list rule" : "per-indicator rules"} | ` +
      `Rules: ${m.ruleCount} | Indicators: ${m.indicatorCount} | Min severity: ${m.minSeverity} | Action: ${m.action}`,
    `# Load: append to local.rules (or a file in rule-files:) and reload the sensor.`,
    `# Match: <bad-ip> <> $HOME_NET (either direction) — define $HOME_NET in your vars.`,
  ];
  if (m.action !== "alert") {
    lines.push(`# NOTE: '${m.action}' requires an INLINE (IPS) sensor; IDS/tap mode can only 'alert'.`);
  }
  lines.push(`# Indicators are heuristic (severity/volume/corroboration) - review before 'drop'.`);
  return lines.join("\n");
}

function iprepHeader(m: Omit<SnortReport, "text" | "markdown" | "rules">): string {
  return [
    `# SecTool Suricata IP-reputation (iprep) export`,
    `# Window: last ${m.hours}h | Indicators: ${m.indicatorCount} | Min severity: ${m.minSeverity} | Action: ${m.action}`,
    `# Three artefacts below, separated by markers. Split them into the named files,`,
    `# wire them into suricata.yaml (reputation-categories-file / reputation-files /`,
    `# default-reputation-path) and include the activating rule file, then reload.`,
  ].join("\n");
}

// ----- markdown twin ---------------------------------------------------------

function renderMarkdown(m: SnortReport, indicators: IocIndicator[]): string {
  const lines: string[] = [];
  const engine = m.dialect === "snort" ? "Snort" : "Suricata";
  lines.push(`# 🛡️ SecTool ${engine} IDS-Rule Export`);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(m.windowEndMs)}`);
  lines.push(`**Window:** last ${m.hours} hour(s) — ${fmtTime(m.windowStartMs)} → ${fmtTime(m.windowEndMs)}`);
  lines.push(
    `**Flavour:** ${m.format} · **Dialect:** ${m.dialect} · **Action:** ${m.action} · ` +
      `**Mode:** ${m.consolidated ? "consolidated list rule" : "per-indicator rules"} · ` +
      `**Rules:** ${m.ruleCount} · **Indicators:** ${m.indicatorCount} · **Min severity:** ${m.minSeverity}` +
      (m.excludedSafe ? ` · **Excluded (safelisted):** ${m.excludedSafe}` : "") +
      (m.truncated ? ` · **Truncated:** ${m.truncated} more` : ""),
  );
  lines.push("");

  if (!m.indicatorCount) {
    lines.push(
      `No external attacker IPs at **${m.minSeverity}** severity or above in the last ${m.hours} hour(s).` +
        (m.excludedBelowSeverity
          ? ` (${m.excludedBelowSeverity} lower-severity IP(s) were below the floor.)`
          : ""),
    );
    lines.push("");
    lines.push("Nothing to detect — no IDS rules were generated.");
    lines.push("");
    lines.push("---");
    lines.push(`_Generated offline by SecTool. No live gateway query was performed._`);
    lines.push("");
    return lines.join("\n");
  }

  lines.push(
    `Native **${engine}** IDS rules that feed your observed attackers back into the sensor. Each per-IP rule ` +
      `matches the address as **either endpoint** of a conversation with \`$HOME_NET\` (\`<>\`) so an inbound probe ` +
      `and an internal host's outbound call-back both fire. \`sid\`s are **deterministic per IP** so a recurring ` +
      `export produces a clean diff instead of churn.`,
  );
  lines.push("");
  if (m.action !== "alert") {
    lines.push(
      `> ⚠️ Action is \`${m.action}\` — this requires an **inline (IPS)** sensor. A sensor running in IDS / tap / ` +
        `SPAN mode can only \`alert\`. Re-export with \`--action alert\` if yours is not inline.`,
    );
    lines.push("");
  }

  if (m.format === "iprep") {
    lines.push(
      `**iprep flavour:** instead of per-IP rules, this emits Suricata's native IP-reputation triplet — a category ` +
        `file, a \`<ip>,category,reputation\` list (confidence rescaled to the 1–127 reputation range) and the ` +
        `activating \`iprep:\` rule. This is how Suricata is designed to consume a large, frequently-refreshed ` +
        `blocklist: an O(1) reputation lookup per packet, not thousands of address-match rules.`,
    );
    lines.push("");
  } else if (!m.consolidated) {
    const head = ["IP", "Conf.", "Sev", "Class", "Prio", "SID"];
    lines.push(`| ${head.join(" | ")} |`);
    lines.push(`| ${head.map(() => "---").join(" | ")} |`);
    const bySid = new Map<string, number>();
    for (const r of m.rules) if (typeof r.ip === "string") bySid.set(r.ip, r.sid);
    for (const ind of indicators) {
      const cls = SEVERITY_CLASS[ind.severityMax] ?? SEVERITY_CLASS.medium;
      lines.push(
        `| ${mdCell(ind.ip)} | ${ind.confidence} | ${mdCell(ind.severityMax)} | ${cls.classtype} | ` +
          `${cls.priority} | ${bySid.get(ind.ip) ?? "—"} |`,
      );
    }
    lines.push("");
  } else {
    lines.push(`A single consolidated rule matches all **${m.indicatorCount}** indicators as one IP list — one rule to load and refresh.`);
    lines.push("");
  }

  lines.push(`## ${m.format === "iprep" ? "Reputation artefacts" : "Rules"}`);
  lines.push("");
  lines.push(
    m.format === "iprep"
      ? "Split into the named files, wire into `suricata.yaml`, then reload:"
      : "Append to `local.rules` (or a file in `rule-files:`) and reload the sensor:",
  );
  lines.push("");
  lines.push("```");
  lines.push(m.text.trimEnd());
  lines.push("```");
  lines.push("");

  lines.push("---");
  lines.push(
    `_Generated offline by SecTool from the stored alert history. Confidence is heuristic (severity, volume, ` +
      `gateway corroboration, watchlist — the same model as \`--iocs\`); review before wiring \`drop\`. IP-reputation ` +
      `rules age as addresses are reassigned — a recurring export retires stale indicators. Safelisted IPs are ` +
      `excluded by default. The IDS-sensor sibling of \`--sigma\` (SIEM), \`--stix\` (intel) and \`--fwrules\` ` +
      `(firewall). No live gateway query was performed._`,
  );
  lines.push("");
  return lines.join("\n");
}

// ----- entry point -----------------------------------------------------------

/**
 * Build the Snort / Suricata IDS-rule export from the stored alert history.
 *
 * @param hours Look-back window in hours (clamped by the IOC engine).
 * @param opts  {@link SnortOptions}: severity floor, indicator limit, safelist
 *              handling, consolidated mode, dialect, format, action, and a
 *              `nowMs` pin for deterministic / reproducible output.
 */
export function buildSnort(hours: number, opts: SnortOptions = {}): SnortReport {
  const nowMs = opts.nowMs ?? Date.now();
  const consolidated = opts.consolidated === true;
  const dialect: SnortDialect = opts.dialect === "snort" ? "snort" : "suricata";
  const action: SnortAction =
    opts.action === "drop" || opts.action === "reject" ? opts.action : "alert";
  // The iprep mechanism is Suricata-only; coerce the dialect so the header is honest.
  const format: SnortFormat = opts.format ?? "suricata";
  const effectiveDialect: SnortDialect = format === "iprep" ? "suricata" : dialect;

  // Reuse the IOC engine as the scoring source of truth — same filters, same
  // confidence model, same safelist / dismissed handling. No logic duplicated.
  const ioc = buildIocExport(hours, {
    minSeverity: opts.minSeverity,
    limit: opts.limit,
    includeSafe: opts.includeSafe,
    nowMs,
  });

  let rules: SnortRule[] = [];
  let iprepArtefacts: { categories: string; list: string; rules: SnortRule[] } | null = null;

  if (ioc.indicators.length) {
    if (format === "iprep") {
      iprepArtefacts = buildIprep(ioc.indicators, action, nowMs);
      rules = iprepArtefacts.rules;
    } else if (consolidated) {
      rules = [buildConsolidatedRule(ioc.indicators, ioc.hours, action, effectiveDialect, nowMs)];
    } else {
      const used = new Set<number>();
      rules = ioc.indicators.map((ind) =>
        buildIndicatorRule(ind, sidForIp(ind.ip, used), action, effectiveDialect, nowMs),
      );
    }
  }

  const base: Omit<SnortReport, "text" | "markdown" | "rules"> = {
    hours: ioc.hours,
    windowStartMs: ioc.windowStartMs,
    windowEndMs: ioc.windowEndMs,
    minSeverity: ioc.minSeverity,
    dialect: effectiveDialect,
    format,
    action,
    consolidated: format === "iprep" ? false : consolidated,
    indicatorCount: ioc.indicators.length,
    ruleCount: rules.length,
    excludedSafe: ioc.excludedSafe,
    excludedBelowSeverity: ioc.excludedBelowSeverity,
    truncated: ioc.truncated,
  };

  // Assemble the text deliverable per flavour.
  let text: string;
  if (!ioc.indicators.length) {
    const header = format === "iprep" ? iprepHeader(base) : rulesHeader({ ...base, ruleCount: 0 });
    text = `${header}\n# No indicators qualified in this window — nothing to detect.\n`;
  } else if (format === "iprep" && iprepArtefacts) {
    text =
      `${iprepHeader(base)}\n` +
      `\n# ===== FILE: sectool-categories.txt =====\n${iprepArtefacts.categories}` +
      `\n# ===== FILE: sectool-reputation.list =====\n${iprepArtefacts.list}` +
      `\n# ===== FILE: sectool-iprep.rules =====\n${iprepArtefacts.rules.map((r) => r.text).join("\n")}\n`;
  } else {
    text = `${rulesHeader(base)}\n${rules.map((r) => r.text).join("\n")}\n`;
  }

  const model: SnortReport = { ...base, rules, text, markdown: "" };
  model.markdown = renderMarkdown(model, ioc.indicators);
  return model;
}

/** A filesystem-safe filename for a downloaded ruleset in the given flavour. */
export function snortFilename(nowMs: number, format: SnortFormat = "suricata"): string {
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  const ext = format === "md" ? "md" : format === "json" ? "json" : format === "iprep" ? "txt" : "rules";
  return `sectool-${format === "snort" ? "snort" : "suricata"}-${stamp}.${ext}`;
}

/** Coerce an arbitrary string into a valid {@link SnortFormat}, defaulting to suricata. */
export function parseSnortFormat(raw: string | undefined | null): SnortFormat {
  const f = (raw ?? "").trim().toLowerCase();
  if (f === "snort") return "snort";
  if (f === "iprep" || f === "reputation" || f === "rep") return "iprep";
  if (f === "json") return "json";
  if (f === "md" || f === "markdown") return "md";
  return "suricata";
}

/** Coerce an arbitrary string into a valid {@link SnortAction}, defaulting to alert. */
export function parseSnortAction(raw: string | undefined | null): SnortAction {
  const a = (raw ?? "").trim().toLowerCase();
  return a === "drop" || a === "reject" ? a : "alert";
}
