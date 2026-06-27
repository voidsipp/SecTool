/**
 * Sigma detection-rule export — turn the stored alert history into a set of
 * **Sigma rules** (the open, vendor-neutral SIEM detection format) that any
 * Sigma-aware backend converts to its own query language: Splunk, Elastic /
 * ELK, Microsoft Sentinel, QRadar, Loki, Chronicle, OpenSearch, and dozens more
 * via `sigma convert` / pySigma. It is the *detection-content* sibling of the
 * existing exports and deliberately does not overlap them:
 *
 *   - iocExport.ts (`--iocs`) emits firewall/SIEM-friendly **plain / csv / json /
 *     markdown** indicator lists — great for `ipset restore` or a spreadsheet,
 *     but each is a SecTool-specific shape no SIEM auto-recognises as a *rule*.
 *   - stix.ts (`--stix`) emits an **OASIS STIX 2.1** bundle of Indicator SDOs —
 *     the threat-intel *interchange* object, consumed by a TI platform (MISP /
 *     OpenCTI / TAXII), not by a SIEM's detection engine.
 *   - fwrules.ts (`--fwrules`) renders the *enforced blocklist* into vendor
 *     firewall config — the perimeter-enforcement codegen step.
 *   - This module emits the one format the *detection-engineering* ecosystem
 *     agreed on. A Sigma rule drops into a detection-as-code repo and compiles
 *     to a working SIEM alert that fires the moment a known-bad address shows up
 *     in firewall / proxy / netflow logs — closing the loop on the *log* side,
 *     where STIX (intel) and fwrules (block) cannot reach.
 *
 * Rather than re-deriving the indicator set, this report **reuses
 * {@link buildIocExport}** as its scoring engine — exactly as stix.ts does — so
 * the same confidence model, severity floor, safelist exclusion and
 * dismissed-alert handling that make the IOC export trustworthy as a blocklist
 * source apply here verbatim. No detection logic is duplicated.
 *
 * Two deployment styles, because SIEM operators genuinely split on this:
 *
 *   - **Per-indicator rules (default).** One self-contained Sigma rule per
 *     attacker IP, each with its own deterministic id, severity-mapped `level`,
 *     dominant-signature context and first-seen `date`. Granular: an analyst can
 *     tune, silence or delete a single noisy address without touching the rest —
 *     the same per-object granularity stix.ts gives on the intel side.
 *   - **Consolidated list rule (`consolidated: true`).** A *single* rule whose
 *     `detection` matches the whole IP set as `src_ip`/`dst_ip` lists. One alert
 *     to deploy, far cheaper to evaluate at scale, trivial to refresh on a feed.
 *
 * Each rule matches the indicator as **either endpoint** (`src_ip` OR `dst_ip`)
 * so it catches both an inbound probe *and* an internal host calling back out to
 * the same address — the C2-beacon case a source-only match would miss.
 *
 * **Deterministic, idempotent identifiers.** Sigma requires every rule to carry
 * a UUID `id`. Random UUIDs would re-key the whole ruleset on every run, so a
 * detection-as-code repo would see a churn of "deleted + added" on each refresh.
 * Instead every id here is a **deterministic UUIDv5** (RFC 4122, name-based
 * SHA-1) derived from a fixed SecTool namespace and the indicator value, so the
 * *same attacker IP always maps to the same rule id across runs* — a git diff
 * shows only genuine changes. Dates are driven by the pinned `nowMs`, so the
 * whole ruleset is reproducible (and testable) byte-for-byte for identical input.
 *
 * Honest caveats baked into the output:
 *   - **Confidence is heuristic, not vetted intel.** Each rule's `level` is
 *     mapped from SecTool's worst observed severity for that IP; the 0–100
 *     blocklist confidence is surfaced in the rule description. Review before
 *     wiring a rule to an auto-response action.
 *   - **IP-reputation rules age.** An address reassigned to a benign tenant will
 *     start producing false positives. The `falsepositives` block says so, and
 *     a recurring export naturally retires indicators that fall out of window.
 *   - **`logsource` is generic (`category: firewall`).** Sigma field names are
 *     backend-normalised; verify `src_ip` / `dst_ip` map to your pipeline's
 *     fields (most firewall/zeek/netflow taxonomies already do).
 *   - **Safelisted IPs are excluded by default**, exactly as in the IOC export.
 *   - **Window- & store-bounded.** A long look-back can hit the alert store's
 *     retention cap and clip the earliest indicators.
 *
 * Pure in-memory math over alertStore (via iocExport) — no SSH, no Claude, no
 * network. Output is a structured model, a ready-to-deploy multi-document Sigma
 * YAML string, and a human Markdown review twin, mirroring stix.ts and the other
 * offline reports so it plugs into the same CLI and HTTP plumbing.
 */
import { createHash } from "node:crypto";
import { buildIocExport, type IocIndicator } from "./iocExport.ts";
import type { Severity } from "../types.ts";

/** Sigma rule `level` vocabulary (ordered low → high). */
export type SigmaLevel = "informational" | "low" | "medium" | "high" | "critical";

/**
 * A fixed UUID namespace for SecTool's deterministic Sigma rule identifiers.
 * Pinned forever: changing it would re-key every rule and defeat the idempotency
 * it exists to guarantee. (Distinct from the STIX namespace so the two exports
 * never share an id — purely for tidiness; a collision would be harmless.)
 */
const SIGMA_NAMESPACE = "b2e7c4a1-5d63-4f8e-9a0b-1c2d3e4f5a6b";

/** Maps SecTool's severity ladder onto Sigma's `level` vocabulary. */
const SEVERITY_TO_LEVEL: Record<Severity, SigmaLevel> = {
  info: "informational",
  low: "low",
  medium: "medium",
  high: "high",
  critical: "critical",
};

/** A single rendered Sigma rule, kept structured for the JSON/markdown views. */
export interface SigmaRule {
  /** Deterministic UUIDv5 — Sigma's required `id`. */
  id: string;
  /** Human title of the rule. */
  title: string;
  /** The attacker IP this rule detects (absent on the consolidated rule). */
  ip?: string;
  /** Sigma severity bucket, mapped from the worst observed alert severity. */
  level: SigmaLevel;
  /** SecTool's 0–100 blocklist confidence (absent on the consolidated rule). */
  confidence?: number;
  /** The rule serialised as a Sigma YAML document. */
  yaml: string;
}

export interface SigmaReport {
  hours: number;
  windowStartMs: number;
  windowEndMs: number;
  /** Severity floor applied to qualify as an indicator (from the IOC engine). */
  minSeverity: Severity;
  /** Whether output is the single consolidated rule (true) or per-indicator. */
  consolidated: boolean;
  /** Distinct attacker IPs that qualified as indicators. */
  indicatorCount: number;
  /** Sigma rules emitted (== indicatorCount per-indicator, or 1 consolidated). */
  ruleCount: number;
  /** Indicators dropped because the IP is safelisted (explicitly trusted). */
  excludedSafe: number;
  /** Indicators dropped because their worst severity was below the floor. */
  excludedBelowSeverity: number;
  /** Indicators truncated by the `limit`. */
  truncated: number;
  /** The rendered rules (structured). */
  rules: SigmaRule[];
  /** The full deliverable: a multi-document Sigma YAML string. */
  yaml: string;
  /** A human Markdown review twin (eyeball before deploying). */
  markdown: string;
}

export interface SigmaOptions {
  /** Severity floor (default `medium`, inherited from the IOC engine). */
  minSeverity?: Severity;
  /** Cap on emitted indicators, highest confidence first (default: no cap). */
  limit?: number;
  /** Include safelisted IPs instead of excluding them (default false). */
  includeSafe?: boolean;
  /** Emit a single consolidated list rule instead of per-indicator rules. */
  consolidated?: boolean;
  /** Pins the window end / timestamps for deterministic tests; defaults to now. */
  nowMs?: number;
}

// ----- deterministic UUIDv5 (RFC 4122, name-based SHA-1) ---------------------

/** Parse a canonical 36-char UUID string into its 16 raw bytes. */
function uuidToBytes(uuid: string): Buffer {
  const hex = uuid.replace(/-/g, "");
  const bytes = Buffer.alloc(16);
  for (let i = 0; i < 16; i++) bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return bytes;
}

/** Render 16 raw bytes as a canonical lower-case UUID string. */
function bytesToUuid(bytes: Buffer): string {
  const hex = bytes.toString("hex");
  return (
    `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-` +
    `${hex.slice(16, 20)}-${hex.slice(20, 32)}`
  );
}

/**
 * Deterministic RFC 4122 v5 (SHA-1, name-based) UUID. The same (namespace, name)
 * always yields the same UUID — the property that makes the exported ruleset
 * idempotent across re-runs.
 */
function uuidv5(name: string, namespace = SIGMA_NAMESPACE): string {
  const ns = uuidToBytes(namespace);
  const hash = createHash("sha1").update(ns).update(Buffer.from(name, "utf8")).digest();
  const bytes = Buffer.from(hash.subarray(0, 16));
  bytes[6] = (bytes[6]! & 0x0f) | 0x50; // version 5
  bytes[8] = (bytes[8]! & 0x3f) | 0x80; // RFC 4122 variant
  return bytesToUuid(bytes);
}

// ----- minimal, safe YAML emitter --------------------------------------------
//
// Sigma documents are plain YAML maps of scalars, scalar lists and one level of
// nested maps (logsource / detection). A tiny purpose-built emitter keeps this
// module dependency-free and the output deterministic. We quote conservatively:
// any value that is not an unambiguous plain scalar is double-quoted and escaped.

/** A JSON-ish value the emitter understands. */
type YamlValue = string | number | boolean | null | YamlValue[] | { [k: string]: YamlValue };

/** Tokens YAML would misread as bool/null if left as a bare plain scalar. */
const RESERVED_PLAIN = new Set([
  "true", "false", "yes", "no", "on", "off", "null", "~", "none",
]);

/** True if `s` is safe to emit as an unquoted (plain) YAML scalar. */
function isPlainScalar(s: string): boolean {
  if (s.length === 0) return false;
  // Only a tight, unambiguous character set; anything else gets quoted.
  if (!/^[A-Za-z0-9_./: -]+$/.test(s)) return false;
  // A bare colon-space or trailing colon is a mapping indicator — quote it.
  if (/:(\s|$)/.test(s) || /^\s|\s$/.test(s)) return false;
  if (/^[-?:&*!|>%@`]/.test(s)) return false;
  if (RESERVED_PLAIN.has(s.toLowerCase())) return false;
  // Don't let a number-like string round-trip as a number unexpectedly when it
  // is meant to be a string field — but our numbers are emitted as real numbers,
  // so a numeric-looking *string* (e.g. an all-digit signature) must be quoted.
  if (/^[+-]?(\d+\.?\d*|\.\d+)$/.test(s)) return false;
  return true;
}

/** Render a single scalar (string/number/bool/null) as a YAML token. */
function scalar(v: string | number | boolean | null): string {
  if (v === null) return "null";
  if (typeof v === "number") return Number.isFinite(v) ? String(v) : `"${String(v)}"`;
  if (typeof v === "boolean") return v ? "true" : "false";
  if (isPlainScalar(v)) return v;
  const escaped = v
    .replace(/\\/g, "\\\\")
    .replace(/"/g, '\\"')
    .replace(/\n/g, "\\n")
    .replace(/\t/g, "\\t")
    .replace(/\r/g, "");
  return `"${escaped}"`;
}

/** Emit a YAML block for `obj` at the given indent (2-space steps). */
function emitBlock(obj: { [k: string]: YamlValue }, indent: number, out: string[]): void {
  const pad = " ".repeat(indent);
  for (const [key, value] of Object.entries(obj)) {
    if (value === undefined) continue;
    if (Array.isArray(value)) {
      if (value.length === 0) {
        out.push(`${pad}${key}: []`);
        continue;
      }
      out.push(`${pad}${key}:`);
      for (const item of value) {
        if (item !== null && typeof item === "object" && !Array.isArray(item)) {
          // A list of maps: first key on the dash line, rest indented under it.
          const entries = Object.entries(item);
          entries.forEach(([k, val], i) => {
            const lead = i === 0 ? `${pad}  - ` : `${pad}    `;
            out.push(`${lead}${k}: ${scalar(val as string | number | boolean | null)}`);
          });
        } else {
          out.push(`${pad}  - ${scalar(item as string | number | boolean | null)}`);
        }
      }
    } else if (value !== null && typeof value === "object") {
      out.push(`${pad}${key}:`);
      emitBlock(value, indent + 2, out);
    } else {
      out.push(`${pad}${key}: ${scalar(value)}`);
    }
  }
}

/** Serialise an ordered Sigma rule object to a YAML document string. */
function toYaml(rule: { [k: string]: YamlValue }): string {
  const out: string[] = [];
  emitBlock(rule, 0, out);
  return out.join("\n");
}

// ----- rule builders ---------------------------------------------------------

function isoDate(ms: number): string {
  return new Date(ms).toISOString().slice(0, 10); // YYYY-MM-DD
}

/** The shared `falsepositives` guidance for IP-reputation rules. */
const FALSE_POSITIVES = [
  "Address remediated, reassigned or reallocated to a benign tenant since export",
  "Shared NAT / CGNAT egress also used by legitimate clients",
  "Internal host legitimately contacting a service hosted on a flagged provider",
];

/** Build one per-indicator Sigma rule object (ordered for readable YAML). */
function buildIndicatorRule(ind: IocIndicator, nowMs: number): { [k: string]: YamlValue } {
  const level = SEVERITY_TO_LEVEL[ind.severityMax] ?? "medium";
  const sigContext = ind.signatures.length
    ? ` Dominant signature(s): ${ind.signatures.slice(0, 3).join("; ")}.`
    : "";
  const description =
    `Network traffic to or from ${ind.ip}, an external address SecTool observed in ` +
    `${ind.alertCount} IPS alert(s) (worst severity ${ind.severityMax}) across ` +
    `${ind.signatureCount} signature(s) and ${ind.targetCount} internal host(s). ` +
    `SecTool blocklist confidence ${ind.confidence}/100` +
    (ind.blockedCount > 0 ? `; the gateway already blocked ${ind.blockedCount} of these alert(s)` : "") +
    (ind.watched ? `; on the operator watchlist` : "") +
    `.${sigContext}`;

  const tags: string[] = ["tlp.amber"];
  for (const cat of ind.categories.slice(0, 3)) {
    const t = cat.toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_+|_+$/g, "");
    if (t) tags.push(`sectool.${t}`);
  }

  // Match the indicator as EITHER endpoint so inbound probes and outbound
  // call-backs to the same address both fire.
  return {
    title: `SecTool: known-bad host ${ind.ip}`,
    id: uuidv5(ind.ip),
    status: "experimental",
    description,
    references: ["https://github.com/SigmaHQ/sigma", "Generated offline by SecTool from observed IPS alerts"],
    author: "SecTool",
    date: isoDate(ind.firstSeen),
    modified: isoDate(nowMs),
    tags,
    logsource: { category: "firewall" },
    detection: {
      sel_src: { src_ip: ind.ip },
      sel_dst: { dst_ip: ind.ip },
      condition: "sel_src or sel_dst",
    },
    fields: ["src_ip", "dst_ip", "dst_port"],
    falsepositives: FALSE_POSITIVES,
    level,
  };
}

/** Build the single consolidated list rule covering every indicator. */
function buildConsolidatedRule(
  indicators: IocIndicator[],
  hours: number,
  nowMs: number,
): { [k: string]: YamlValue } {
  // The rule's level tracks the worst severity in the set, so a single critical
  // indicator doesn't get diluted into a low-priority alert.
  const worst = indicators.reduce<SigmaLevel>((acc, ind) => {
    const l = SEVERITY_TO_LEVEL[ind.severityMax] ?? "low";
    const order: SigmaLevel[] = ["informational", "low", "medium", "high", "critical"];
    return order.indexOf(l) > order.indexOf(acc) ? l : acc;
  }, "informational");

  const ips = indicators.map((i) => i.ip);
  // Deterministic id from the window + member set, so identical content is stable.
  const seed = `consolidated:${hours}:${ips.join(",")}`;

  return {
    title: `SecTool: traffic to/from any known-bad host (last ${hours}h, ${ips.length} indicators)`,
    id: uuidv5(seed),
    status: "experimental",
    description:
      `Network traffic where either endpoint is one of ${ips.length} external addresses ` +
      `SecTool flagged from observed IPS alerts in the last ${hours} hour(s). A single ` +
      `consolidated threat-list rule — cheaper to evaluate than per-indicator rules and ` +
      `trivial to refresh on a recurring export. Worst observed severity: ${worst}.`,
    references: ["https://github.com/SigmaHQ/sigma", "Generated offline by SecTool from observed IPS alerts"],
    author: "SecTool",
    date: isoDate(nowMs),
    modified: isoDate(nowMs),
    tags: ["tlp.amber"],
    logsource: { category: "firewall" },
    detection: {
      sel_src: { src_ip: ips },
      sel_dst: { dst_ip: ips },
      condition: "sel_src or sel_dst",
    },
    fields: ["src_ip", "dst_ip", "dst_port"],
    falsepositives: FALSE_POSITIVES,
    level: worst,
  };
}

// ----- markdown twin ---------------------------------------------------------

function fmtTime(ms: number): string {
  return new Date(ms).toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
}

function mdCell(v: unknown): string {
  return String(v ?? "").replace(/\|/g, "\\|").replace(/\n/g, " ");
}

function renderMarkdown(m: SigmaReport, indicators: IocIndicator[]): string {
  const lines: string[] = [];
  lines.push(`# 🛡️ SecTool Sigma Detection-Rule Export`);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(m.windowEndMs)}`);
  lines.push(
    `**Window:** last ${m.hours} hour(s) — ${fmtTime(m.windowStartMs)} → ${fmtTime(m.windowEndMs)}`,
  );
  lines.push(
    `**Mode:** ${m.consolidated ? "consolidated list rule" : "per-indicator rules"} · ` +
      `**Rules:** ${m.ruleCount} · **Indicators:** ${m.indicatorCount} · ` +
      `**Min severity:** ${m.minSeverity}` +
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
    lines.push("Nothing to detect — no Sigma rules were generated.");
    lines.push("");
    lines.push("---");
    lines.push(`_Generated offline by SecTool. No live gateway query was performed._`);
    lines.push("");
    return lines.join("\n");
  }

  lines.push(
    `Vendor-neutral **Sigma** detection rules for any Sigma-aware SIEM (convert with ` +
      `\`sigma convert\` / pySigma to Splunk, Elastic, Sentinel, QRadar, Loki, Chronicle…). ` +
      `Each rule matches the address as **either endpoint** (\`src_ip\` OR \`dst_ip\`) to catch ` +
      `inbound probes and outbound call-backs alike. Rule \`id\`s are **deterministic (UUIDv5)** ` +
      `so a recurring export produces a clean git diff instead of churn.`,
  );
  lines.push("");

  if (!m.consolidated) {
    const head = ["IP", "Conf.", "Sev", "Level", "Rule ID"];
    lines.push(`| ${head.join(" | ")} |`);
    lines.push(`| ${head.map(() => "---").join(" | ")} |`);
    for (const ind of indicators) {
      lines.push(
        `| ${mdCell(ind.ip)} | ${ind.confidence} | ${mdCell(ind.severityMax)} | ` +
          `${SEVERITY_TO_LEVEL[ind.severityMax] ?? "medium"} | \`${uuidv5(ind.ip)}\` |`,
      );
    }
    lines.push("");
  } else {
    lines.push(
      `A single consolidated rule matches all **${m.indicatorCount}** indicators as ` +
        `\`src_ip\`/\`dst_ip\` lists — one alert to deploy and refresh.`,
    );
    lines.push("");
  }

  lines.push(`## Sigma rules (YAML)`);
  lines.push("");
  lines.push("Save as `.yml` and add to your detection-as-code repo / `sigma convert` pipeline:");
  lines.push("");
  lines.push("```yaml");
  lines.push(m.yaml);
  lines.push("```");
  lines.push("");

  lines.push("---");
  lines.push(
    `_Generated offline by SecTool. Each rule's \`level\` is mapped from the worst observed ` +
      `severity for that IP; the 0–100 blocklist confidence (same heuristic model as the IOC ` +
      `export) is in each description — review before wiring a rule to auto-response. ` +
      `IP-reputation rules age: an address reassigned to a benign tenant will eventually false ` +
      `positive (see each rule's \`falsepositives\`). Verify \`src_ip\`/\`dst_ip\` map to your ` +
      `pipeline's fields. Safelisted IPs are excluded by default. A long look-back can hit the ` +
      `alert store's retention cap and clip the earliest indicators. No live gateway query was ` +
      `performed._`,
  );
  lines.push("");
  return lines.join("\n");
}

// ----- entry point -----------------------------------------------------------

/** A leading comment header for the multi-document YAML deliverable. */
function yamlHeader(m: Omit<SigmaReport, "yaml" | "markdown" | "rules">): string {
  return [
    `# SecTool Sigma detection-rule export`,
    `# Window: last ${m.hours}h (${fmtTime(m.windowStartMs)} -> ${fmtTime(m.windowEndMs)})`,
    `# Mode: ${m.consolidated ? "consolidated list rule" : "per-indicator rules"} | ` +
      `Rules: ${m.ruleCount} | Indicators: ${m.indicatorCount} | Min severity: ${m.minSeverity}`,
    `# Convert with: sigma convert -t <backend> <this-file>.yml  (pySigma / sigmac)`,
    `# Indicators are heuristic (severity/volume/corroboration) - review before auto-response.`,
  ].join("\n");
}

/**
 * Build the Sigma detection-rule export from the stored alert history.
 *
 * @param hours Look-back window in hours (clamped by the IOC engine).
 * @param opts  {@link SigmaOptions}: severity floor, indicator limit, safelist
 *              handling, consolidated vs per-indicator mode, and a `nowMs` pin
 *              for deterministic / reproducible output.
 */
export function buildSigma(hours: number, opts: SigmaOptions = {}): SigmaReport {
  const nowMs = opts.nowMs ?? Date.now();
  const consolidated = opts.consolidated === true;

  // Reuse the IOC engine as the scoring source of truth — same filters, same
  // confidence model, same safelist/dismissed handling. No logic duplicated.
  const ioc = buildIocExport(hours, {
    minSeverity: opts.minSeverity,
    limit: opts.limit,
    includeSafe: opts.includeSafe,
    nowMs,
  });

  let rules: SigmaRule[];
  if (!ioc.indicators.length) {
    rules = [];
  } else if (consolidated) {
    const obj = buildConsolidatedRule(ioc.indicators, ioc.hours, nowMs);
    rules = [
      {
        id: obj.id as string,
        title: obj.title as string,
        level: obj.level as SigmaLevel,
        yaml: toYaml(obj),
      },
    ];
  } else {
    rules = ioc.indicators.map((ind) => {
      const obj = buildIndicatorRule(ind, nowMs);
      return {
        id: obj.id as string,
        title: obj.title as string,
        ip: ind.ip,
        level: obj.level as SigmaLevel,
        confidence: ind.confidence,
        yaml: toYaml(obj),
      };
    });
  }

  const model: SigmaReport = {
    hours: ioc.hours,
    windowStartMs: ioc.windowStartMs,
    windowEndMs: ioc.windowEndMs,
    minSeverity: ioc.minSeverity,
    consolidated,
    indicatorCount: ioc.indicators.length,
    ruleCount: rules.length,
    excludedSafe: ioc.excludedSafe,
    excludedBelowSeverity: ioc.excludedBelowSeverity,
    truncated: ioc.truncated,
    rules,
    yaml: "",
    markdown: "",
  };

  // Multi-document YAML: a comment header, then each rule separated by `---`.
  const header = yamlHeader(model);
  model.yaml = rules.length
    ? `${header}\n${rules.map((r) => r.yaml).join("\n---\n")}\n`
    : `${header}\n# No indicators qualified in this window — nothing to detect.\n`;
  model.markdown = renderMarkdown(model, ioc.indicators);
  return model;
}

/** A filesystem-safe filename for a downloaded Sigma ruleset. */
export function sigmaFilename(nowMs: number): string {
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  return `sectool-sigma-${stamp}.yml`;
}
