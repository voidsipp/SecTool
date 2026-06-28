/**
 * Zeek (Bro) Intelligence Framework export — turn the stored alert history into a
 * **ready-to-load Zeek intel file** that feeds your observed attackers into a
 * Zeek / Corelight network-security-monitor's Intel Framework, so the NSM raises
 * an `intel.log` hit (and optionally a Notice) the instant a known-bad address
 * reappears in *any* protocol it parses — a connection, a DNS query, an HTTP
 * request, a TLS handshake, a transferred file.
 *
 * SecTool already ships a deep export family, but every member targets a
 * *different* downstream and **none of them speaks Zeek**:
 *
 *   - iocExport.ts (`--iocs`)  — plain / csv / json indicator lists for a
 *     firewall or spreadsheet; no detection platform consumes them as *intel*.
 *   - stix.ts (`--stix`)       — an OASIS STIX 2.1 bundle for a TI platform
 *     (MISP / OpenCTI / TAXII); a Zeek sensor cannot read STIX directly.
 *   - sigma.ts (`--sigma`)     — vendor-neutral Sigma rules for a *SIEM* that
 *     fires on already-ingested logs.
 *   - snort.ts (`--snort`)     — native Snort / Suricata `.rules` for an inline
 *     *signature* IDS/IPS.
 *   - fwrules.ts (`--fwrules`) — firewall config (the perimeter-drop codegen).
 *
 * Zeek is none of those: it is a *network-security-monitor* (not a
 * signature-matching IDS), and its Intel Framework is a first-class, purpose-built
 * subsystem that watches every connection / DNS / HTTP / SSL / file event Zeek
 * already extracts and cross-references each observed address, domain, URL, hash
 * and certificate against a loaded indicator set. It is, in practice, the single
 * most common way a SOC operationalises an IP/indicator feed on the *monitoring*
 * (as opposed to *blocking*) side — and the one sensor surface SecTool could not
 * reach. This module closes that gap.
 *
 * Rather than re-deriving the indicator set, this export **reuses
 * {@link buildIocExport}** as its scoring engine — exactly as stix.ts, sigma.ts
 * and snort.ts do — so the same confidence model, severity floor, safelist
 * exclusion and dismissed-alert handling that make the IOC export trustworthy as a
 * blocklist source apply here verbatim. No detection logic is duplicated.
 *
 * **Output is a strictly-valid Zeek intel file.** The Intel Framework is fed by
 * the tab-separated input-framework reader, whose grammar is exact: a single
 * `#fields` header naming the columns, then one TAB-delimited row per indicator,
 * with `-` for any unset optional field. Free-form `#` comment lines are *not*
 * part of that grammar and can trip the ASCII reader, so — unlike the `--snort` /
 * `--iocs` text deliverables which embed comment headers — the `intel` flavour
 * here carries **only** the `#fields` header and data rows. All human provenance
 * lives in the Markdown twin and the loader-script comments instead, where it
 * cannot break the parse. Each row is:
 *
 *   indicator  ⇥  indicator_type  ⇥  meta.source  ⇥  meta.desc  ⇥  meta.url  [⇥ meta.do_notice]
 *
 * Indicators are emitted as `Intel::ADDR` (the native Zeek type for a bare host
 * address; Zeek matches it across conn/DNS/HTTP/SSL/file "seen" events). `meta.url`
 * is pre-filled with the AbuseIPDB lookup so an analyst clicking through an
 * `intel.log` hit lands on the address's reputation page.
 *
 * Output flavours (`--format`):
 *   - **intel** (default) — the tab-separated `.dat` file. Drop it into your
 *     Zeek `site/` directory and add it to `Intel::read_files`.
 *   - **script** — a tiny portable `.zeek` loader that `@load`s the Intel
 *     Framework + the `seen` policy (and `do_notice` when `--notice` is set) and
 *     registers the `.dat` next to it via `@DIR`, so the whole bundle drops into
 *     `site/` and is wired in with one `@load`.
 *   - **json** — the structured model, for programmatic consumers.
 *   - **md** — a human Markdown review twin (eyeball before you load it).
 *
 * `--notice` adds the optional `meta.do_notice` column set to `T`, so a hit
 * additionally raises a Zeek `Intel::Notice` (an alert you can route to Slack /
 * email via the Notice framework) rather than only appending to `intel.log`. Off
 * by default — the IDS-safe choice, mirroring `--snort`'s `alert`-by-default.
 *
 * Honest caveats baked into the output:
 *   - **Zeek monitors; it does not block.** An `intel.log` hit (or a Notice) is
 *     *detection*, not enforcement — pair this with `--fwrules` / `--snort` if you
 *     want the traffic dropped, not merely logged.
 *   - **Indicators age.** An address reassigned to a benign tenant will start
 *     false-positiving; a recurring export naturally retires indicators that fall
 *     out of window.
 *   - **Confidence is heuristic, not vetted intel** (same model as `--iocs`);
 *     review before enabling `--notice` so you are not paged on a stale address.
 *   - **Safelisted IPs are excluded by default**, exactly as in the IOC export.
 *
 * Pure in-memory math over alertStore (via iocExport) — no SSH, no Claude, no
 * network. Output is a structured model, a ready-to-load intel file (or loader
 * script) and a human Markdown review twin, mirroring snort.ts and the other
 * offline exports so it plugs into the same CLI and HTTP plumbing.
 */
import { buildIocExport, type IocIndicator } from "./iocExport.ts";
import type { Severity } from "../types.ts";

/** Output flavour the export renders into. */
export type ZeekFormat = "intel" | "script" | "json" | "md";

/** Zeek Intel Framework indicator type. We only emit bare host addresses. */
const INTEL_TYPE_ADDR = "Intel::ADDR";

/** The Input-framework placeholder for an unset optional field. */
const UNSET = "-";

/** Default `meta.source` label stamped on every indicator. */
const DEFAULT_SOURCE = "SecTool";

/** Default basename the loader script wires into `Intel::read_files`. */
const DEFAULT_INTEL_FILENAME = "sectool-intel.dat";

/** One rendered intel-file row, kept structured for the JSON / Markdown views. */
export interface ZeekIndicator {
  /** The attacker IP — the indicator value. */
  indicator: string;
  /** The Zeek indicator type (always `Intel::ADDR` here). */
  indicatorType: string;
  /** `meta.source` — provenance label. */
  source: string;
  /** `meta.desc` — human description (confidence / severity / lead signature). */
  desc: string;
  /** `meta.url` — a pivot link (AbuseIPDB lookup). */
  url: string;
  /** Worst observed severity (carried for the JSON model / Markdown table). */
  severity: Severity;
  /** SecTool 0–100 blocklist confidence (carried for the model / table). */
  confidence: number;
  /** Whether this row carries `meta.do_notice = T`. */
  doNotice: boolean;
}

export interface ZeekReport {
  hours: number;
  windowStartMs: number;
  windowEndMs: number;
  /** Severity floor applied to qualify as an indicator (from the IOC engine). */
  minSeverity: Severity;
  /** Output flavour requested. */
  format: ZeekFormat;
  /** The `meta.source` label stamped on every row. */
  source: string;
  /** Whether `meta.do_notice = T` was emitted (raises a Zeek Notice on a hit). */
  doNotice: boolean;
  /** Basename the loader script registers in `Intel::read_files`. */
  intelFilename: string;
  /** Distinct attacker IPs that qualified as indicators. */
  indicatorCount: number;
  /** Indicators dropped because the IP is safelisted (explicitly trusted). */
  excludedSafe: number;
  /** Indicators dropped because their worst severity was below the floor. */
  excludedBelowSeverity: number;
  /** Indicators truncated by the `limit`. */
  truncated: number;
  /** The rendered indicators (structured). */
  indicators: ZeekIndicator[];
  /** The full deliverable: a ready-to-load intel `.dat` (or `.zeek` loader) string. */
  text: string;
  /** A human Markdown review twin (eyeball before loading). */
  markdown: string;
}

export interface ZeekOptions {
  /** Severity floor (default `medium`, inherited from the IOC engine). */
  minSeverity?: Severity;
  /** Cap on emitted indicators, highest confidence first (default: no cap). */
  limit?: number;
  /** Include safelisted IPs instead of excluding them (default false). */
  includeSafe?: boolean;
  /** Output flavour (default `intel`). */
  format?: ZeekFormat;
  /** Add `meta.do_notice = T` so a hit raises a Zeek Notice (default false). */
  notice?: boolean;
  /** Override the `meta.source` label (default `SecTool`). */
  source?: string;
  /** Override the intel-file basename the loader script registers. */
  intelFilename?: string;
  /** Pins the window end / timestamps for deterministic tests; defaults to now. */
  nowMs?: number;
}

// ----- helpers ---------------------------------------------------------------

function fmtTime(ms: number): string {
  return new Date(ms).toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
}

function mdCell(v: unknown): string {
  return String(v ?? "").replace(/\|/g, "\\|").replace(/\n/g, " ");
}

/**
 * Sanitise free text for a tab-separated intel-file field. TAB is the column
 * separator and `\n`/`\r` ends the record, so both must be collapsed to a space;
 * a leading `#` would otherwise look like a header directive to the reader, so we
 * neutralise it. The result must never be empty (an empty required field would
 * shift columns); callers pass non-empty text and we fall back to `-` defensively.
 */
function intelField(s: string): string {
  const cleaned = s.replace(/[\t\r\n]+/g, " ").replace(/^#+/, "").trim();
  return cleaned.length ? cleaned : UNSET;
}

/** Sanitise the operator-supplied `meta.source` label into a single safe token. */
function sanitizeSource(raw: string | undefined): string {
  const s = (raw ?? "").replace(/[\t\r\n]+/g, " ").trim();
  return s.length ? s : DEFAULT_SOURCE;
}

/**
 * Coerce an operator-supplied intel filename into a safe single-segment basename
 * (no path traversal, no separators) ending in `.dat`. Used purely as a label in
 * the generated loader script.
 */
function sanitizeIntelFilename(raw: string | undefined): string {
  const base = (raw ?? "").replace(/[\t\r\n]+/g, " ").trim().split(/[\\/]/).pop() ?? "";
  const safe = base.replace(/[^A-Za-z0-9._-]/g, "_").replace(/^\.+/, "").trim();
  if (!safe) return DEFAULT_INTEL_FILENAME;
  return /\.dat$/i.test(safe) ? safe : `${safe}.dat`;
}

/** The AbuseIPDB pivot URL for an indicator (provenance for the `intel.log` hit). */
function pivotUrl(ip: string): string {
  return `https://www.abuseipdb.com/check/${encodeURIComponent(ip)}`;
}

/** Compose the `meta.desc` text for one indicator (already field-safe). */
function indicatorDesc(ind: IocIndicator): string {
  const sig = ind.signatures[0] ? ` lead-sig ${ind.signatures[0]}` : "";
  return intelField(
    `SecTool: known-bad host conf=${ind.confidence} sev=${ind.severityMax} alerts=${ind.alertCount}${sig}`,
  );
}

// ----- intel-file / loader-script builders -----------------------------------

/** The ordered `#fields` columns, with the optional notice column when requested. */
function fieldColumns(doNotice: boolean): string[] {
  const cols = ["indicator", "indicator_type", "meta.source", "meta.desc", "meta.url"];
  if (doNotice) cols.push("meta.do_notice");
  return cols;
}

/**
 * Render the strictly-valid Zeek intel `.dat`: a single `#fields` header line
 * followed by one TAB-delimited row per indicator. No comment lines — see the
 * module header for why. An empty indicator set still emits a valid (header-only)
 * file that loads zero indicators.
 */
function renderIntelFile(m: ZeekReport): string {
  const lines: string[] = [`#fields\t${fieldColumns(m.doNotice).join("\t")}`];
  for (const ind of m.indicators) {
    const cols = [ind.indicator, ind.indicatorType, ind.source, ind.desc, ind.url];
    if (m.doNotice) cols.push("T");
    lines.push(cols.join("\t"));
  }
  return lines.join("\n") + "\n";
}

/**
 * Render a portable Zeek loader script. It loads the Intel Framework, the `seen`
 * policy (which is what actually cross-references observed conn/DNS/HTTP/SSL/file
 * data against the indicator set), the `do_notice` policy when notices are on,
 * and registers the `.dat` *relative to the script's own directory* via `@DIR`,
 * so the bundle is path-independent — drop both files into `site/` and `@load`
 * the directory.
 */
function renderLoaderScript(m: ZeekReport): string {
  const lines: string[] = [];
  lines.push(`##! SecTool Zeek Intelligence Framework loader`);
  lines.push(`##! Generated ${fmtTime(m.windowEndMs)} — ${m.indicatorCount} indicator(s) from the last ${m.hours}h.`);
  lines.push(`##!`);
  lines.push(`##! Drop this script and ${m.intelFilename} into your Zeek site/ directory together,`);
  lines.push(`##! then @load the directory (or this file) from local.zeek. The intel file is`);
  lines.push(`##! resolved relative to this script via @DIR, so the pair is path-independent.`);
  lines.push(`##!`);
  lines.push(`##! Hits land in intel.log${m.doNotice ? " and additionally raise an Intel::Notice" : ""}.`);
  lines.push(`##! Zeek MONITORS — it does not block. Pair with --fwrules / --snort to enforce.`);
  lines.push("");
  lines.push(`@load base/frameworks/intel`);
  lines.push(`@load policy/frameworks/intel/seen`);
  if (m.doNotice) lines.push(`@load policy/frameworks/intel/do_notice`);
  lines.push("");
  lines.push(`redef Intel::read_files += {`);
  lines.push(`\tfmt("%s/%s", @DIR, "${m.intelFilename}")`);
  lines.push(`};`);
  return lines.join("\n") + "\n";
}

// ----- markdown twin ---------------------------------------------------------

function renderMarkdown(m: ZeekReport): string {
  const lines: string[] = [];
  lines.push(`# 🦓 SecTool Zeek Intelligence Framework Export`);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(m.windowEndMs)}`);
  lines.push(`**Window:** last ${m.hours} hour(s) — ${fmtTime(m.windowStartMs)} → ${fmtTime(m.windowEndMs)}`);
  lines.push(
    `**Flavour:** ${m.format} · **Source:** \`${m.source}\` · **Notices:** ${m.doNotice ? "on" : "off"} · ` +
      `**Indicators:** ${m.indicatorCount} · **Min severity:** ${m.minSeverity}` +
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
    lines.push("Nothing to monitor — an empty (header-only) intel file would load zero indicators.");
    lines.push("");
    lines.push("---");
    lines.push(`_Generated offline by SecTool. No live gateway query was performed._`);
    lines.push("");
    return lines.join("\n");
  }

  lines.push(
    `A **Zeek Intelligence Framework** indicator file that feeds your observed attackers into a Zeek / Corelight ` +
      `network-security-monitor. Each address is emitted as \`Intel::ADDR\`; once loaded, Zeek raises an ` +
      `\`intel.log\` hit${m.doNotice ? " **and an \`Intel::Notice\`**" : ""} whenever it sees the address in a ` +
      `connection, DNS query, HTTP request, TLS handshake or file transfer — in **either direction**.`,
  );
  lines.push("");
  lines.push(
    `> ℹ️ Zeek **monitors**, it does not block. A hit is detection, not enforcement — pair this with \`--fwrules\` ` +
      `or \`--snort\` if you want the traffic dropped, not merely logged.`,
  );
  lines.push("");
  if (m.doNotice) {
    lines.push(
      `> ⚠️ \`--notice\` is on: every hit carries \`meta.do_notice = T\` and will raise a Zeek Notice (route it via ` +
        `the Notice framework). Confidence is heuristic — re-export without \`--notice\` if you would rather not be ` +
        `paged on a stale indicator.`,
    );
    lines.push("");
  }

  const head = ["Indicator", "Type", "Conf.", "Sev", "Pivot"];
  lines.push(`| ${head.join(" | ")} |`);
  lines.push(`| ${head.map(() => "---").join(" | ")} |`);
  for (const ind of m.indicators) {
    lines.push(
      `| ${mdCell(ind.indicator)} | \`${ind.indicatorType}\` | ${ind.confidence} | ${mdCell(ind.severity)} | ` +
        `[AbuseIPDB](${ind.url}) |`,
    );
  }
  lines.push("");

  // Show the exact strictly-valid intel file so it can be eyeballed / copied.
  const fileText = renderIntelFile(m);
  lines.push(`## Intel file (\`${m.intelFilename}\`)`);
  lines.push("");
  lines.push(
    `Tab-separated, strictly to the Zeek input-framework grammar (a \`#fields\` header then one TAB-delimited row ` +
      `per indicator — no comment lines, which the ASCII reader rejects). Drop it into your Zeek \`site/\` directory ` +
      `and add it to \`Intel::read_files\`:`,
  );
  lines.push("");
  lines.push("```");
  lines.push(fileText.trimEnd());
  lines.push("```");
  lines.push("");

  // And the loader script that wires it in.
  lines.push(`## Loader script`);
  lines.push("");
  lines.push(`A portable \`@load\`-able script that registers the file relative to itself (via \`@DIR\`):`);
  lines.push("");
  lines.push("```");
  lines.push(renderLoaderScript(m).trimEnd());
  lines.push("```");
  lines.push("");

  lines.push("---");
  lines.push(
    `_Generated offline by SecTool from the stored alert history. Confidence is heuristic (severity, volume, ` +
      `gateway corroboration, watchlist — the same model as \`--iocs\`); review before enabling \`--notice\`. ` +
      `Indicators age as addresses are reassigned — a recurring export retires stale ones. Safelisted IPs are ` +
      `excluded by default. The network-security-monitor sibling of \`--snort\` (inline IDS), \`--sigma\` (SIEM), ` +
      `\`--stix\` (intel interchange) and \`--fwrules\` (firewall). No live gateway query was performed._`,
  );
  lines.push("");
  return lines.join("\n");
}

// ----- entry point -----------------------------------------------------------

/**
 * Build the Zeek Intelligence Framework export from the stored alert history.
 *
 * @param hours Look-back window in hours (clamped by the IOC engine).
 * @param opts  {@link ZeekOptions}: severity floor, indicator limit, safelist
 *              handling, format, notice flag, source / intel-filename labels, and
 *              a `nowMs` pin for deterministic / reproducible output.
 */
export function buildZeek(hours: number, opts: ZeekOptions = {}): ZeekReport {
  const nowMs = opts.nowMs ?? Date.now();
  const format: ZeekFormat = opts.format ?? "intel";
  const doNotice = opts.notice === true;
  const source = sanitizeSource(opts.source);
  const intelFilename = sanitizeIntelFilename(opts.intelFilename);

  // Reuse the IOC engine as the scoring source of truth — same filters, same
  // confidence model, same safelist / dismissed handling. No logic duplicated.
  const ioc = buildIocExport(hours, {
    minSeverity: opts.minSeverity,
    limit: opts.limit,
    includeSafe: opts.includeSafe,
    nowMs,
  });

  const indicators: ZeekIndicator[] = ioc.indicators.map((ind) => ({
    indicator: ind.ip,
    indicatorType: INTEL_TYPE_ADDR,
    source,
    desc: indicatorDesc(ind),
    url: pivotUrl(ind.ip),
    severity: ind.severityMax,
    confidence: ind.confidence,
    doNotice,
  }));

  const model: ZeekReport = {
    hours: ioc.hours,
    windowStartMs: ioc.windowStartMs,
    windowEndMs: ioc.windowEndMs,
    minSeverity: ioc.minSeverity,
    format,
    source,
    doNotice,
    intelFilename,
    indicatorCount: indicators.length,
    excludedSafe: ioc.excludedSafe,
    excludedBelowSeverity: ioc.excludedBelowSeverity,
    truncated: ioc.truncated,
    indicators,
    text: "",
    markdown: "",
  };

  // The `text` deliverable is the intel file for `intel`, the loader for `script`.
  model.text = format === "script" ? renderLoaderScript(model) : renderIntelFile(model);
  model.markdown = renderMarkdown(model);
  return model;
}

/** A filesystem-safe filename for a downloaded Zeek export in the given flavour. */
export function zeekFilename(nowMs: number, format: ZeekFormat = "intel"): string {
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  const ext = format === "md" ? "md" : format === "json" ? "json" : format === "script" ? "zeek" : "dat";
  return `sectool-zeek-${stamp}.${ext}`;
}

/** Coerce an arbitrary string into a valid {@link ZeekFormat}, defaulting to intel. */
export function parseZeekFormat(raw: string | undefined | null): ZeekFormat {
  const f = (raw ?? "").trim().toLowerCase();
  if (f === "script" || f === "zeek" || f === "load" || f === "loader") return "script";
  if (f === "json") return "json";
  if (f === "md" || f === "markdown") return "md";
  return "intel";
}
