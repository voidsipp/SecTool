/**
 * Attack-graph visualization export — "**give me a picture I can actually look
 * at**": SecTool's source→target attack topology rendered as a ready-to-paste
 * **GraphViz DOT** diagram, a **Mermaid** flowchart, and the structured node/edge
 * model behind both.
 *
 * Every other report in this project is text — tables, leaderboards, prose
 * call-outs. They are precise but they are not *spatial*: an analyst staring at a
 * forty-row edge table cannot see at a glance that three external sources all
 * converge on one crown-jewel host, or that one compromised box is now reaching
 * laterally into five peers. The human visual system reads a graph far faster
 * than a table, and incident bridges, tickets and post-mortems all want a diagram.
 *
 * This module is deliberately a **rendering**, not a new analysis. `edges.ts`
 * already does the analytical heavy lifting (lateral-movement scoring, topology
 * metrics); this report's job is to take the same source→target relationships and
 * emit them in the two formats every diagramming tool on earth understands:
 *
 *   - **GraphViz DOT** (`.dot`) — paste into `dot -Tsvg`, https://dreampuf.github.io
 *     /GraphvizOnline, VS Code GraphViz preview, Obsidian, etc.
 *   - **Mermaid** (` ```mermaid ` block) — renders inline in GitHub, GitLab,
 *     Obsidian, Notion, mkdocs and the Mermaid Live Editor with zero tooling.
 *
 * What the graph shows:
 *
 *   - **Source nodes** (left, boxes) — addresses seen as an alert *source*, sized
 *     and coloured by how much / how severe their traffic is. A 🚫 marks a source
 *     already on the blocklist, 👁 a watch-listed one.
 *   - **Target nodes** (right, ellipses) — addresses seen as a *destination*. ✅
 *     marks a safe-listed asset.
 *   - **Edges** source→target, the directed attack relationship, labelled with the
 *     alert count and the worst severity carried, with line weight scaled by
 *     volume so the loudest relationships are visually dominant.
 *
 * **Readable by construction.** A full estate can have hundreds of sources; a
 * hairball helps nobody. The graph keeps only the top `maxSources` sources and
 * top `maxTargets` targets by alert volume (small, legible defaults). Everything
 * dropped is **never silent**: by default the trimmed sources and targets are
 * rolled into two clearly-labelled aggregate nodes ("Σ N other sources" / "Σ N
 * other targets") that preserve the dropped edge volume, and the exact hidden
 * counts are stated in the summary and the diagram footer. Set `collapseOthers:
 * false` to drop them entirely (and still see the counts).
 *
 * Honest caveats baked into the output:
 *
 *   - **A diagram is a summary, not the whole truth.** Only the busiest nodes are
 *     drawn; the aggregate "others" nodes and the hidden counts tell you how much
 *     was folded away. For exhaustive per-edge data use the edges report.
 *   - **Alerts, not flows.** SecTool stores IPS *detections*; traffic that tripped
 *     no rule is invisible, so every edge weight is a lower bound.
 *   - **Direction is the alert's, not proven causality.** An edge means "this
 *     source tripped a rule aimed at this destination", not that a session
 *     completed or a host was compromised.
 *   - **Window-bounded & store-capped.** A long look-back can hit the store's
 *     history cap and undercount.
 *
 * Pure in-memory math over alertStore (plus block / watch / safe membership flags
 * on the nodes) — no SSH, no Claude, no network. Mirrors the offline-report shape
 * used across this project (a structured model plus rendered text artifacts).
 */
import { isIP } from "node:net";
import { alertStore, type StoredAlert } from "../store/alertStore.ts";
import { blockStore } from "../store/blocklist.ts";
import { watchStore } from "../store/watchlist.ts";
import { safeStore } from "../store/safelist.ts";
import { SEVERITY_ORDER, type Severity } from "../types.ts";

/** One vertex in the attack graph — a source or a target address (or an aggregate). */
export interface GraphNode {
  /** Stable, render-safe id (e.g. `s0`, `t3`, `others_src`). */
  id: string;
  /** The address, or an aggregate label like "Σ 12 other sources". */
  label: string;
  /** Underlying IP, or undefined for an aggregate node. */
  ip?: string;
  /** Which side of the graph the node sits on. */
  kind: "source" | "target";
  /** Total alerts touching this node within the window (incident volume). */
  alerts: number;
  /** Worst severity carried by this node's traffic. */
  severityMax: Severity;
  /** Source already on the blocklist (sources only). */
  blocked: boolean;
  /** Watch-listed address. */
  watched: boolean;
  /** Safe-listed address (targets only, typically). */
  safe: boolean;
  /** Number of real nodes folded into this one (aggregate nodes only). */
  aggregateOf?: number;
}

/** One directed source→target edge, aggregated over the window. */
export interface GraphEdge {
  /** Source node id. */
  from: string;
  /** Target node id. */
  to: string;
  /** Alerts on this relationship. */
  alerts: number;
  /** Worst severity carried on this edge. */
  severityMax: Severity;
  /** The signature most responsible for this edge, if any (model-only; not drawn). */
  topSignature?: string;
}

export interface AttackGraphReport {
  hours: number;
  windowStartMs: number;
  windowEndMs: number;
  /** Alerts with a usable timestamp inside the window. */
  totalWindowAlerts: number;
  /** Of those, alerts with a valid source and destination (graphable). */
  edgeAlerts: number;
  /** Distinct source addresses seen. */
  distinctSources: number;
  /** Distinct target addresses seen. */
  distinctTargets: number;
  /** Source nodes actually drawn (excludes the aggregate). */
  shownSources: number;
  /** Target nodes actually drawn (excludes the aggregate). */
  shownTargets: number;
  /** Sources folded away (into the aggregate, or dropped). */
  hiddenSources: number;
  /** Targets folded away (into the aggregate, or dropped). */
  hiddenTargets: number;
  /** All rendered nodes (shown + any aggregate). */
  nodes: GraphNode[];
  /** All rendered edges. */
  edges: GraphEdge[];
  /** Plain-language, action-oriented call-outs. */
  highlights: string[];
  /** GraphViz DOT source. */
  dot: string;
  /** Mermaid flowchart source (no fences). */
  mermaid: string;
  /** Markdown document embedding the Mermaid chart, a legend and a summary. */
  markdown: string;
}

export interface AttackGraphOptions {
  /** Max source nodes to draw before collapsing the rest (clamped to [1, 60]). */
  maxSources?: number;
  /** Max target nodes to draw before collapsing the rest (clamped to [1, 60]). */
  maxTargets?: number;
  /** Fold trimmed nodes into "Σ N others" aggregate nodes (default true). */
  collapseOthers?: boolean;
  /** Drop edges below this alert count to de-clutter (≥1, default 1). */
  minEdgeAlerts?: number;
  /** Pins the window end for deterministic tests; defaults to now. */
  nowMs?: number;
}

const DEFAULT_MAX_SOURCES = 12;
const DEFAULT_MAX_TARGETS = 12;
const DEFAULT_MIN_EDGE_ALERTS = 1;
const MS_PER_HOUR = 3_600_000;

const AGG_SRC_ID = "others_src";
const AGG_TGT_ID = "others_tgt";

/** Fill colour per severity, shared by DOT and Mermaid. */
const SEV_FILL: Record<Severity, string> = {
  critical: "#b71c1c",
  high: "#e53935",
  medium: "#fb8c00",
  low: "#fdd835",
  info: "#90a4ae",
};
/** Readable text colour to pair with {@link SEV_FILL}. */
const SEV_TEXT: Record<Severity, string> = {
  critical: "#ffffff",
  high: "#ffffff",
  medium: "#000000",
  low: "#000000",
  info: "#000000",
};

// ----- helpers ---------------------------------------------------------------

function validIp(ip: string | undefined): string | undefined {
  return ip && isIP(ip) !== 0 ? ip : undefined;
}

function sevRank(s: string | undefined): number {
  const i = (SEVERITY_ORDER as readonly string[]).indexOf(s ?? "");
  return i < 0 ? 0 : i;
}

function maxSeverity(a: Severity, b: string | undefined): Severity {
  if (!b) return a;
  return sevRank(b) > sevRank(a) ? (b as Severity) : a;
}

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

/** Line weight for an edge, scaled by volume but capped so it never overwhelms. */
function penWidth(alerts: number): number {
  return Math.round((1 + Math.min(6, Math.log2(alerts + 1))) * 10) / 10;
}

/** Escape a string for a double-quoted GraphViz DOT literal. */
function dotEscape(s: string): string {
  return s.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\n/g, "\\n");
}

/** Escape a string for a double-quoted Mermaid label (it is HTML-ish). */
function mermaidEscape(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/"/g, "&quot;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\n/g, "<br/>");
}

/** Decorative flag suffix appended to a node label. */
function flagSuffix(n: GraphNode): string {
  return (n.blocked ? " 🚫" : "") + (n.watched ? " 👁" : "") + (n.safe ? " ✅" : "");
}

// ----- aggregation -----------------------------------------------------------

interface NodeAcc {
  ip: string;
  alerts: number;
  sevMax: Severity;
}
interface EdgeAcc {
  from: string;
  to: string;
  alerts: number;
  sevMax: Severity;
  sig: Map<string, number>;
}

// ----- highlights ------------------------------------------------------------

function writeHighlights(
  hours: number,
  m: {
    edgeAlerts: number;
    distinctSources: number;
    distinctTargets: number;
    hiddenSources: number;
    hiddenTargets: number;
  },
  nodes: GraphNode[],
  edges: GraphEdge[],
): string[] {
  const out: string[] = [];
  if (!m.edgeAlerts) return out;

  out.push(
    `🕸️ Over the last ${hours}h, **${m.distinctSources} source(s)** → **${m.distinctTargets} target(s)** across ` +
      `**${m.edgeAlerts} graphable alert(s)**. The diagram draws the busiest nodes; ` +
      (m.hiddenSources || m.hiddenTargets
        ? `**${m.hiddenSources} source(s)** and **${m.hiddenTargets} target(s)** are folded into the "Σ others" nodes.`
        : `everything fits — no nodes were trimmed.`),
  );

  // Heaviest edge — the single relationship to look at first.
  const realEdges = edges.filter((e) => e.from !== AGG_SRC_ID && e.to !== AGG_TGT_ID);
  const top = [...realEdges].sort((a, b) => b.alerts - a.alerts)[0];
  if (top) {
    const from = nodes.find((n) => n.id === top.from);
    const to = nodes.find((n) => n.id === top.to);
    out.push(
      `🔥 Heaviest relationship: \`${from?.ip ?? top.from}\` → \`${to?.ip ?? top.to}\` ` +
        `(**${top.alerts} alert(s)**, worst sev *${top.severityMax}*` +
        (top.topSignature ? `, mostly _${top.topSignature}_` : "") +
        `). This is the thickest line in the diagram — start here.`,
    );
  }

  // Convergence — a target with many distinct drawn sources hitting it.
  const inDeg = new Map<string, number>();
  for (const e of realEdges) inDeg.set(e.to, (inDeg.get(e.to) ?? 0) + 1);
  const conv = [...inDeg.entries()].sort((a, b) => b[1] - a[1])[0];
  if (conv && conv[1] >= 3) {
    const t = nodes.find((n) => n.id === conv[0]);
    out.push(
      `🎯 \`${t?.ip ?? conv[0]}\` is a **convergence point** — **${conv[1]} distinct drawn source(s)** aim at it. ` +
        `In the picture it is the node with the most arrows landing on it; treat it as a priority asset.`,
    );
  }

  // Fan-out — a source spraying many drawn targets.
  const outDeg = new Map<string, number>();
  for (const e of realEdges) outDeg.set(e.from, (outDeg.get(e.from) ?? 0) + 1);
  const fan = [...outDeg.entries()].sort((a, b) => b[1] - a[1])[0];
  if (fan && fan[1] >= 3) {
    const s = nodes.find((n) => n.id === fan[0]);
    out.push(
      `📡 \`${s?.ip ?? fan[0]}\` **fans out** to **${fan[1]} drawn target(s)** — a sprayer, not a sniper. ` +
        `It is the node with the most arrows leaving it; blocking it clears several edges at once.`,
    );
  }

  // Already-actioned sources visible in the graph.
  const blocked = nodes.filter((n) => n.kind === "source" && n.blocked).length;
  if (blocked) {
    out.push(
      `🚫 **${blocked}** drawn source(s) are already on the blocklist (marked 🚫). If they are still generating ` +
        `edges, the block is post-detection — confirm enforcement is in place upstream.`,
    );
  }

  return out;
}

// ----- renderers -------------------------------------------------------------

function renderDot(m: AttackGraphReport): string {
  const L: string[] = [];
  L.push(`digraph SecToolAttackGraph {`);
  L.push(`  rankdir=LR;`);
  L.push(`  labelloc="t";`);
  L.push(
    `  label="SecTool attack graph — last ${m.hours}h — ${m.shownSources}/${m.distinctSources} sources, ` +
      `${m.shownTargets}/${m.distinctTargets} targets shown";`,
  );
  L.push(`  fontname="Helvetica"; fontsize=12;`);
  L.push(`  graph [bgcolor="white", nodesep=0.3, ranksep=1.2];`);
  L.push(`  node [fontname="Helvetica", fontsize=10, style="filled"];`);
  L.push(`  edge [fontname="Helvetica", fontsize=8, color="#607d8b"];`);
  L.push(``);

  // Keep sources and targets in vertical columns.
  const sources = m.nodes.filter((n) => n.kind === "source");
  const targets = m.nodes.filter((n) => n.kind === "target");

  for (const n of sources) {
    const fill = n.aggregateOf !== undefined ? "#cfd8dc" : SEV_FILL[n.severityMax];
    const text = n.aggregateOf !== undefined ? "#000000" : SEV_TEXT[n.severityMax];
    const border = n.blocked ? "#000000" : SEV_FILL[n.severityMax];
    const pen = n.blocked ? 3 : 1;
    const label = `${n.label}${flagSuffix(n)}\\n${n.alerts} alert(s)`;
    L.push(
      `  ${n.id} [shape=box, style="rounded,filled", label="${dotEscape(label)}", ` +
        `fillcolor="${fill}", fontcolor="${text}", color="${border}", penwidth=${pen}];`,
    );
  }
  for (const n of targets) {
    const fill = n.aggregateOf !== undefined ? "#cfd8dc" : SEV_FILL[n.severityMax];
    const text = n.aggregateOf !== undefined ? "#000000" : SEV_TEXT[n.severityMax];
    const label = `${n.label}${flagSuffix(n)}\\n${n.alerts} alert(s)`;
    L.push(
      `  ${n.id} [shape=ellipse, label="${dotEscape(label)}", fillcolor="${fill}", fontcolor="${text}"];`,
    );
  }
  L.push(``);

  // Rank the two columns so GraphViz lays them left/right cleanly.
  if (sources.length) L.push(`  { rank=same; ${sources.map((n) => n.id).join("; ")}; }`);
  if (targets.length) L.push(`  { rank=same; ${targets.map((n) => n.id).join("; ")}; }`);
  L.push(``);

  for (const e of m.edges) {
    const color = SEV_FILL[e.severityMax];
    const label = `${e.alerts} · ${e.severityMax}`;
    L.push(
      `  ${e.from} -> ${e.to} [label="${dotEscape(label)}", penwidth=${penWidth(e.alerts)}, ` +
        `color="${color}"];`,
    );
  }
  L.push(`}`);
  return L.join("\n");
}

function renderMermaid(m: AttackGraphReport): string {
  const L: string[] = [];
  L.push(`flowchart LR`);

  for (const n of m.nodes) {
    const label = mermaidEscape(`${n.label}${flagSuffix(n)} — ${n.alerts}`);
    // Boxes for sources, stadiums for targets.
    if (n.kind === "source") L.push(`  ${n.id}["${label}"]:::sev_${n.severityMax}`);
    else L.push(`  ${n.id}(["${label}"]):::sev_${n.severityMax}`);
  }

  for (const e of m.edges) {
    const label = mermaidEscape(`${e.alerts} · ${e.severityMax}`);
    L.push(`  ${e.from} -->|"${label}"| ${e.to}`);
  }

  // Severity classes (Mermaid classDef per severity).
  for (const s of SEVERITY_ORDER) {
    L.push(`  classDef sev_${s} fill:${SEV_FILL[s]},color:${SEV_TEXT[s]},stroke:#37474f;`);
  }
  return L.join("\n");
}

function renderMarkdown(m: AttackGraphReport): string {
  const lines: string[] = [];
  lines.push(`# 🕸️ SecTool Attack-Graph Visualization`);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(m.windowEndMs)}`);
  lines.push(`**Window:** last ${m.hours} hour(s) — ${fmtTime(m.windowStartMs)} → ${fmtTime(m.windowEndMs)}`);
  lines.push(
    `**Scope:** ${m.shownSources}/${m.distinctSources} source(s) and ${m.shownTargets}/${m.distinctTargets} ` +
      `target(s) drawn (busiest first) over ${m.edgeAlerts} of ${m.totalWindowAlerts} window alert(s).`,
  );
  lines.push("");

  if (!m.edgeAlerts) {
    lines.push(`## Summary`);
    lines.push("");
    if (!m.totalWindowAlerts) {
      lines.push(`No alerts with a usable timestamp in the last ${m.hours} hour(s) — nothing to graph.`);
    } else {
      lines.push(
        `${m.totalWindowAlerts} alert(s) in the last ${m.hours} hour(s), but none carried both a valid source and ` +
          `destination IP — no edges to draw.`,
      );
    }
    lines.push("");
    lines.push("---");
    lines.push(`_Generated offline by SecTool. No live gateway query was performed._`);
    lines.push("");
    return lines.join("\n");
  }

  lines.push(`## Highlights`);
  lines.push("");
  for (const h of m.highlights) lines.push(`- ${h}`);
  lines.push("");

  lines.push(`## Diagram`);
  lines.push("");
  lines.push("```mermaid");
  lines.push(m.mermaid);
  lines.push("```");
  lines.push("");
  lines.push(
    `**Legend:** boxes are **sources**, stadiums are **targets**; colour = worst severity ` +
      `(🟥 critical/high · 🟧 medium · 🟨 low · ⬜ info). Edge labels are \`alerts · severity\`; thicker lines carry ` +
      `more alerts. Flags: 🚫 blocked source · 👁 watched · ✅ safe-listed. ` +
      (m.hiddenSources || m.hiddenTargets
        ? `**Σ** nodes fold ${m.hiddenSources} trimmed source(s) and ${m.hiddenTargets} trimmed target(s).`
        : `No nodes were trimmed.`),
  );
  lines.push("");
  lines.push(
    `> Mermaid renders inline on GitHub/GitLab/Obsidian. For a higher-fidelity image, download the **GraphViz DOT** ` +
      `(\`/api/graph.dot\` or \`--format dot\`) and run \`dot -Tsvg\`, or paste it into the GraphViz Online editor.`,
  );
  lines.push("");

  // Top edges table (the model's per-edge detail the diagram abbreviates).
  const realEdges = m.edges
    .filter((e) => e.from !== AGG_SRC_ID && e.to !== AGG_TGT_ID)
    .sort((a, b) => b.alerts - a.alerts)
    .slice(0, 20);
  const idToIp = new Map(m.nodes.map((n) => [n.id, n.ip ?? n.label]));
  lines.push(`## Top edges`);
  lines.push("");
  lines.push(
    mdTable(
      ["#", "Source", "Target", "Alerts", "Worst sev", "Top signature"],
      realEdges.map((e, i) => [
        String(i + 1),
        cell(idToIp.get(e.from)),
        cell(idToIp.get(e.to)),
        String(e.alerts),
        cell(e.severityMax),
        e.topSignature ? cell(e.topSignature) : "—",
      ]),
    ),
  );
  lines.push("");

  lines.push("---");
  lines.push(
    `_Generated offline by SecTool. A **diagram is a summary** — only the busiest nodes are drawn and the rest are ` +
      `folded into the **Σ** aggregate nodes (counts shown); for exhaustive per-edge data use the edges report. These ` +
      `are IPS **detections**, not full flows — traffic that tripped no rule is invisible, so every edge weight is a ` +
      `lower bound. An edge means a rule fired source→destination, **not** that a session completed or a host was ` +
      `compromised. A long look-back can hit the store's history cap and undercount. No live gateway query was ` +
      `performed._`,
  );
  lines.push("");
  return lines.join("\n");
}

/**
 * Build the attack-graph visualization (model + DOT + Mermaid + Markdown) from the
 * stored alert history.
 *
 * @param hours Look-back window in hours (clamped to [1, 90 days]).
 * @param opts  {@link AttackGraphOptions}: `maxSources`, `maxTargets`,
 *              `collapseOthers`, `minEdgeAlerts`, and a `nowMs` pin for tests.
 */
export function buildAttackGraph(hours: number, opts: AttackGraphOptions = {}): AttackGraphReport {
  const safeHours = Math.max(1, Math.min(24 * 90, Math.floor(hours)));
  const maxSources = Math.max(1, Math.min(60, Math.floor(opts.maxSources ?? DEFAULT_MAX_SOURCES)));
  const maxTargets = Math.max(1, Math.min(60, Math.floor(opts.maxTargets ?? DEFAULT_MAX_TARGETS)));
  const collapseOthers = opts.collapseOthers ?? true;
  const minEdgeAlerts = Math.max(1, Math.floor(opts.minEdgeAlerts ?? DEFAULT_MIN_EDGE_ALERTS));
  const windowEndMs = opts.nowMs ?? Date.now();
  const windowStartMs = windowEndMs - safeHours * MS_PER_HOUR;

  const windowed = alertStore
    .all()
    .filter((a): a is StoredAlert => typeof a.time === "number" && Number.isFinite(a.time))
    .filter((a) => a.time >= windowStartMs && a.time <= windowEndMs);

  // Fold into per-source, per-target and per-edge accumulators.
  const srcAcc = new Map<string, NodeAcc>();
  const tgtAcc = new Map<string, NodeAcc>();
  const edgeAcc = new Map<string, EdgeAcc>();
  let edgeAlerts = 0;

  for (const a of windowed) {
    const src = validIp(a.srcIp);
    const dst = validIp(a.dstIp);
    if (!src || !dst) continue;
    edgeAlerts++;

    const s = srcAcc.get(src) ?? { ip: src, alerts: 0, sevMax: "info" as Severity };
    s.alerts++;
    s.sevMax = maxSeverity(s.sevMax, a.severity);
    srcAcc.set(src, s);

    const t = tgtAcc.get(dst) ?? { ip: dst, alerts: 0, sevMax: "info" as Severity };
    t.alerts++;
    t.sevMax = maxSeverity(t.sevMax, a.severity);
    tgtAcc.set(dst, t);

    const key = `${src} ${dst}`;
    const e = edgeAcc.get(key) ?? { from: src, to: dst, alerts: 0, sevMax: "info" as Severity, sig: new Map() };
    e.alerts++;
    e.sevMax = maxSeverity(e.sevMax, a.severity);
    if (a.signature) e.sig.set(a.signature, (e.sig.get(a.signature) ?? 0) + 1);
    edgeAcc.set(key, e);
  }

  const distinctSources = srcAcc.size;
  const distinctTargets = tgtAcc.size;

  // Rank and trim. Volume desc, then severity, then a stable IP tie-break.
  const rank = (a: NodeAcc, b: NodeAcc): number =>
    b.alerts - a.alerts || sevRank(b.sevMax) - sevRank(a.sevMax) || (a.ip < b.ip ? -1 : a.ip > b.ip ? 1 : 0);

  const rankedSrc = [...srcAcc.values()].sort(rank);
  const rankedTgt = [...tgtAcc.values()].sort(rank);
  const shownSrc = rankedSrc.slice(0, maxSources);
  const shownTgt = rankedTgt.slice(0, maxTargets);
  const hiddenSources = distinctSources - shownSrc.length;
  const hiddenTargets = distinctTargets - shownTgt.length;

  // Assign render-safe ids.
  const srcId = new Map<string, string>();
  shownSrc.forEach((n, i) => srcId.set(n.ip, `s${i}`));
  const tgtId = new Map<string, string>();
  shownTgt.forEach((n, i) => tgtId.set(n.ip, `t${i}`));

  const nodes: GraphNode[] = [];
  for (const n of shownSrc) {
    nodes.push({
      id: srcId.get(n.ip)!,
      label: n.ip,
      ip: n.ip,
      kind: "source",
      alerts: n.alerts,
      severityMax: n.sevMax,
      blocked: blockStore.has(n.ip),
      watched: watchStore.has(n.ip),
      safe: safeStore.has(n.ip),
    });
  }
  for (const n of shownTgt) {
    nodes.push({
      id: tgtId.get(n.ip)!,
      label: n.ip,
      ip: n.ip,
      kind: "target",
      alerts: n.alerts,
      severityMax: n.sevMax,
      blocked: blockStore.has(n.ip),
      watched: watchStore.has(n.ip),
      safe: safeStore.has(n.ip),
    });
  }

  // Build edges. Edges between shown nodes are drawn directly; edges touching a
  // trimmed node are folded into the aggregate "others" nodes (when enabled).
  const drawn = new Map<string, GraphEdge>();
  const aggToTarget = new Map<string, { alerts: number; sev: Severity }>(); // hidden src -> shown tgt
  const aggFromSource = new Map<string, { alerts: number; sev: Severity }>(); // shown src -> hidden tgt
  let aggSevSrc: Severity = "info";
  let aggSevTgt: Severity = "info";
  let aggSrcAlertsTotal = 0;
  let aggTgtAlertsTotal = 0;

  for (const e of edgeAcc.values()) {
    if (e.alerts < minEdgeAlerts) continue;
    const sId = srcId.get(e.from);
    const tId = tgtId.get(e.to);
    const topSignature = [...e.sig.entries()].sort((a, b) => b[1] - a[1])[0]?.[0];

    if (sId && tId) {
      drawn.set(`${sId}->${tId}`, { from: sId, to: tId, alerts: e.alerts, severityMax: e.sevMax, topSignature });
    } else if (collapseOthers && sId && !tId) {
      // shown source -> hidden target : fold into others_tgt
      const cur = aggFromSource.get(sId) ?? { alerts: 0, sev: "info" as Severity };
      cur.alerts += e.alerts;
      cur.sev = maxSeverity(cur.sev, e.sevMax);
      aggFromSource.set(sId, cur);
      aggSevTgt = maxSeverity(aggSevTgt, e.sevMax);
      aggTgtAlertsTotal += e.alerts;
    } else if (collapseOthers && !sId && tId) {
      // hidden source -> shown target : fold into others_src
      const cur = aggToTarget.get(tId) ?? { alerts: 0, sev: "info" as Severity };
      cur.alerts += e.alerts;
      cur.sev = maxSeverity(cur.sev, e.sevMax);
      aggToTarget.set(tId, cur);
      aggSevSrc = maxSeverity(aggSevSrc, e.sevMax);
      aggSrcAlertsTotal += e.alerts;
    }
    // hidden -> hidden is omitted (counts still surface via hiddenSources/Targets).
  }

  const edges: GraphEdge[] = [...drawn.values()];

  // Materialise aggregate nodes + their edges only if they actually carry volume.
  if (collapseOthers && aggToTarget.size > 0) {
    nodes.push({
      id: AGG_SRC_ID,
      label: `Σ ${hiddenSources} other source(s)`,
      kind: "source",
      alerts: aggSrcAlertsTotal,
      severityMax: aggSevSrc,
      blocked: false,
      watched: false,
      safe: false,
      aggregateOf: hiddenSources,
    });
    for (const [tId, v] of aggToTarget) {
      edges.push({ from: AGG_SRC_ID, to: tId, alerts: v.alerts, severityMax: v.sev });
    }
  }
  if (collapseOthers && aggFromSource.size > 0) {
    nodes.push({
      id: AGG_TGT_ID,
      label: `Σ ${hiddenTargets} other target(s)`,
      kind: "target",
      alerts: aggTgtAlertsTotal,
      severityMax: aggSevTgt,
      blocked: false,
      watched: false,
      safe: false,
      aggregateOf: hiddenTargets,
    });
    for (const [sId, v] of aggFromSource) {
      edges.push({ from: sId, to: AGG_TGT_ID, alerts: v.alerts, severityMax: v.sev });
    }
  }

  // Sort edges for stable output: heaviest first, then by endpoints.
  edges.sort((a, b) => b.alerts - a.alerts || (a.from < b.from ? -1 : a.from > b.from ? 1 : a.to < b.to ? -1 : 1));

  const highlights = writeHighlights(
    safeHours,
    { edgeAlerts, distinctSources, distinctTargets, hiddenSources, hiddenTargets },
    nodes,
    edges,
  );

  const model: AttackGraphReport = {
    hours: safeHours,
    windowStartMs,
    windowEndMs,
    totalWindowAlerts: windowed.length,
    edgeAlerts,
    distinctSources,
    distinctTargets,
    shownSources: shownSrc.length,
    shownTargets: shownTgt.length,
    hiddenSources,
    hiddenTargets,
    nodes,
    edges,
    highlights,
    dot: "",
    mermaid: "",
    markdown: "",
  };
  model.dot = renderDot(model);
  model.mermaid = renderMermaid(model);
  model.markdown = renderMarkdown(model);
  return model;
}

/** The render format requested on the CLI / API. */
export type GraphFormat = "dot" | "mermaid" | "md" | "json";

/** Parse a `--format` value into a {@link GraphFormat}; defaults to `dot`. */
export function parseGraphFormat(raw: string | undefined): GraphFormat {
  switch ((raw ?? "").trim().toLowerCase()) {
    case "mermaid":
    case "mmd":
      return "mermaid";
    case "md":
    case "markdown":
      return "md";
    case "json":
      return "json";
    case "dot":
    case "gv":
    case "graphviz":
    default:
      return "dot";
  }
}

/** Serialise the report in the requested format. */
export function renderGraph(m: AttackGraphReport, format: GraphFormat): string {
  switch (format) {
    case "mermaid":
      return m.mermaid;
    case "md":
      return m.markdown;
    case "json":
      // Drop the bulky rendered strings from the JSON payload — they are derivable.
      return JSON.stringify(
        { ...m, dot: undefined, mermaid: undefined, markdown: undefined },
        null,
        2,
      );
    case "dot":
    default:
      return m.dot;
  }
}

/** A filesystem-safe filename for a downloaded attack-graph artifact. */
export function graphFilename(nowMs: number, ext: "dot" | "md" | "mmd" | "json"): string {
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  return `sectool-graph-${stamp}.${ext}`;
}
