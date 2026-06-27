/**
 * Alert syndication feed (RSS 2.0 / Atom 1.0 / JSON Feed 1.1) — "let me
 * *subscribe* to my security alerts in the tools I already watch all day."
 *
 * Every other export SecTool ships is a *pull* artefact aimed at a specific
 * downstream machine: iocExport / fwrules feed a firewall, stix feeds a TAXII
 * server, sigma feeds a SIEM, metrics feeds Prometheus. None of them serve the
 * single most universal integration surface a human operator owns — the **feed
 * reader**. RSS/Atom is consumed natively by Slack (`/feed subscribe`), Microsoft
 * Teams (RSS connector), Discord (many bots), Thunderbird, NetNewsWire, Feedly,
 * Home Assistant, and dozens of dashboards, with zero bespoke code on the
 * consumer side. Pointing any of them at `/api/feed.xml` turns SecTool's alert
 * stream into a live, push-style subscription without standing up a webhook,
 * polling the JSON API, or writing a parser.
 *
 * This module renders the most recent windowed alerts from the local alert store
 * into the three syndication formats every reader understands:
 *
 *   - **RSS 2.0** (`application/rss+xml`) — the lowest common denominator; the one
 *     format that works in the widest set of readers and chat integrations.
 *   - **Atom 1.0** (`application/atom+xml`) — the stricter, better-specified XML
 *     sibling (proper `id`/`updated`/`author`), preferred by some readers.
 *   - **JSON Feed 1.1** (`application/feed+json`) — the modern JSON-native format
 *     for scripts and newer clients that would rather not parse XML.
 *
 * All three are generated from one shared item set, so they stay in lock-step.
 * Each item carries the severity, category, Suricata classification, the
 * source-to-destination flow, the enforcement action, and — when SecTool has
 * already produced a Claude write-up for the alert — the AI summary
 * (what-happened / risk / recommended actions) inline, so the feed is readable
 * on its own without clicking through.
 *
 * Honest caveats baked into the design:
 *
 *   - **Newest-first, capped.** A feed is a *recent* view, not the archive: items
 *     are the most recent alerts in the window, limited to `limit` (default 50).
 *     The full history lives behind the JSON API and the offline reports.
 *   - **Severity floor.** `minSeverity` lets a subscriber follow only the alerts
 *     worth interrupting for (e.g. `medium`), keeping the channel signal-dense —
 *     the same alert-fatigue lesson the notify.ts audit teaches.
 *   - **Store-bounded.** The alert store is rotated (newest N), so a long window
 *     can start mid-history; the feed reflects what is retained.
 *   - **Stable, idempotent item ids.** Each entry's `guid`/`id` is a deterministic
 *     `urn:sectool:alert:<id>` derived from the alert's stable hash, so a reader
 *     never shows the same alert twice across refreshes — and item links resolve
 *     to `GET /api/alerts/:id` when a base URL is known.
 *
 * Pure in-memory math over alertStore — no SSH, no Claude, no network. Output is
 * a structured model plus the three rendered feed strings, mirroring stix.ts,
 * sigma.ts and the other offline exports.
 */
import { isIP } from "node:net";
import { alertStore, type StoredAlert } from "../store/alertStore.ts";
import { SEVERITY_ORDER, type Severity } from "../types.ts";

const MS_PER_HOUR = 3_600_000;
const DEFAULT_LIMIT = 50;
const MAX_LIMIT = 500;

/** Supported syndication formats. */
export type FeedFormat = "rss" | "atom" | "json";

/** A single renderable alert as it appears in every feed format. */
export interface AlertFeedItem {
  /** The alert's stable store id. */
  id: string;
  /** Stable, idempotent entry identifier: `urn:sectool:alert:<id>`. */
  guid: string;
  /** Event time (ms epoch). */
  time: number;
  /** RFC-3339 / ISO-8601 event time (for Atom + JSON Feed). */
  isoTime: string;
  /** RFC-822 event time (for RSS `pubDate`). */
  rfc822Time: string;
  title: string;
  severity: Severity;
  category: string;
  signature?: string;
  classification?: string;
  srcIp?: string;
  dstIp?: string;
  action?: string;
  /** Absolute link to the alert detail, when a base URL was supplied. */
  link?: string;
  /** Whether a non-fallback Claude summary is attached. */
  hasSummary: boolean;
  /** Rich HTML body (RSS description / Atom content / JSON content_html). */
  contentHtml: string;
  /** Plain-text body (JSON content_text). */
  contentText: string;
}

/** Structured feed model plus the three rendered documents. */
export interface AlertFeedModel {
  hours: number;
  windowStartMs: number;
  windowEndMs: number;
  /** When the feed was generated (drives lastBuildDate / updated). */
  generatedAtMs: number;
  /** Alerts in the time window before the limit was applied. */
  totalWindowAlerts: number;
  /** Alerts actually emitted (after the severity floor + limit). */
  includedAlerts: number;
  minSeverity: Severity;
  limit: number;
  title: string;
  description: string;
  /** Absolute self URL of this feed, when a base URL was supplied. */
  selfLink?: string;
  /** Absolute home URL (the dashboard), when a base URL was supplied. */
  homeLink?: string;
  items: AlertFeedItem[];
  /** Rendered RSS 2.0 document. */
  rss: string;
  /** Rendered Atom 1.0 document. */
  atom: string;
  /** Rendered JSON Feed 1.1 document. */
  jsonFeed: string;
}

export interface AlertFeedOptions {
  /** Max items emitted, newest first (default 50, capped at 500). */
  limit?: number;
  /** Pin "now" for deterministic output (defaults to Date.now()). */
  nowMs?: number;
  /** Only emit alerts at this severity or higher (default: all). */
  minSeverity?: Severity;
  /**
   * Origin for absolute links, e.g. "http://192.168.1.10:8787" (no trailing
   * slash needed). When set, the feed advertises a self link and each item links
   * to `GET /api/alerts/:id`. When omitted the feed is still valid — entries use
   * their stable urn ids and carry no clickable link.
   */
  baseUrl?: string;
}

/** Position of a severity on the ladder; -1 for unknown so it never passes a floor. */
function sevRank(s: string | undefined): number {
  return (SEVERITY_ORDER as readonly string[]).indexOf(s ?? "");
}

function asSeverity(s: string | undefined): Severity {
  return (SEVERITY_ORDER as readonly string[]).includes(s ?? "") ? (s as Severity) : "info";
}

function validIp(ip: string | undefined): string | undefined {
  return ip && isIP(ip) > 0 ? ip : undefined;
}

/**
 * Drop characters that are illegal in XML 1.0 even when escaped: the C0 control
 * range (except tab 0x09, LF 0x0A, CR 0x0D) and the 0xFFFE/0xFFFF noncharacters.
 * Implemented as a char-code filter so the source carries no literal controls.
 */
function stripInvalidXml(s: string): string {
  let out = "";
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c === 0x09 || c === 0x0a || c === 0x0d || (c >= 0x20 && c !== 0xfffe && c !== 0xffff)) {
      // Per code unit (incl. surrogate halves), so astral chars like emoji survive.
      out += String.fromCharCode(c);
    }
  }
  return out;
}

/** Escape the five XML predefined entities for use in element text/attributes. */
function xmlEscape(s: string): string {
  return stripInvalidXml(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

/**
 * Wrap arbitrary HTML in a CDATA section, neutralising any embedded "]]>" so the
 * section cannot be terminated early by hostile/odd payload text.
 */
function cdata(html: string): string {
  return `<![CDATA[${stripInvalidXml(html).replace(/]]>/g, "]]]]><![CDATA[>")}]]>`;
}

/** HTML-escape a value for inline use inside the rich content body. */
function htmlEscape(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

const SEV_EMOJI: Record<Severity, string> = {
  info: "⚪",
  low: "🟢",
  medium: "🟡",
  high: "🟠",
  critical: "🔴",
};

/** Build the human-readable item title, e.g. "[HIGH] ET SCAN ... - 1.2.3.4 -> 10.0.0.5". */
function buildTitle(a: StoredAlert, sev: Severity): string {
  const label = a.signature?.trim() || a.category?.trim() || "Security alert";
  const src = validIp(a.srcIp);
  const dst = validIp(a.dstIp);
  let flow = "";
  if (src && dst) flow = ` — ${src} → ${dst}`;
  else if (src) flow = ` — from ${src}`;
  else if (dst) flow = ` — to ${dst}`;
  return `${SEV_EMOJI[sev]} [${sev.toUpperCase()}] ${label}${flow}`;
}

interface BodyParts {
  html: string;
  text: string;
}

/** Render the alert's fact sheet (and any Claude summary) as HTML + plain text. */
function buildBody(a: StoredAlert, sev: Severity): BodyParts {
  const rows: Array<[string, string]> = [];
  rows.push(["Severity", sev]);
  if (a.category) rows.push(["Category", a.category]);
  if (a.classification) rows.push(["Classification", a.classification]);
  if (a.signature) rows.push(["Signature", a.signature]);
  const src = validIp(a.srcIp);
  const dst = validIp(a.dstIp);
  if (src) rows.push(["Source", src]);
  if (dst) rows.push(["Destination", dst]);
  if (a.action) rows.push(["Action", a.action]);

  const htmlRows = rows
    .map(([k, v]) => `<li><strong>${htmlEscape(k)}:</strong> ${htmlEscape(v)}</li>`)
    .join("");
  const textRows = rows.map(([k, v]) => `${k}: ${v}`).join("\n");

  let html = `<ul>${htmlRows}</ul>`;
  let text = textRows;

  // Attach the Claude write-up when one exists (skip the non-AI fallback shell).
  const sum = a.summary;
  if (sum && !sum.fallback) {
    const sections: Array<[string, string]> = [];
    if (sum.whatHappened) sections.push(["What happened", sum.whatHappened]);
    if (sum.riskAssessment) sections.push(["Risk assessment", sum.riskAssessment]);
    if (sections.length) {
      html += sections
        .map(([h, b]) => `<h4>${htmlEscape(h)}</h4><p>${htmlEscape(b)}</p>`)
        .join("");
      text += "\n\n" + sections.map(([h, b]) => `${h}:\n${b}`).join("\n\n");
    }
    if (Array.isArray(sum.recommendedActions) && sum.recommendedActions.length) {
      const acts = sum.recommendedActions.filter((x) => typeof x === "string" && x.trim());
      if (acts.length) {
        html +=
          `<h4>Recommended actions</h4><ol>` +
          acts.map((x) => `<li>${htmlEscape(x)}</li>`).join("") +
          `</ol>`;
        text += "\n\nRecommended actions:\n" + acts.map((x) => `- ${x}`).join("\n");
      }
    }
  }

  return { html, text };
}

/** Normalise a base URL: trim, drop a trailing slash. Returns undefined if blank. */
function normaliseBase(raw: string | undefined): string | undefined {
  const s = (raw ?? "").trim().replace(/\/+$/, "");
  return s.length ? s : undefined;
}

/**
 * Build the alert syndication feed model + the three rendered documents.
 *
 * Deterministic for a fixed `nowMs` and store contents: pure in-memory math, no
 * I/O beyond reading the local alert store.
 */
export function buildAlertFeed(hours: number, opts: AlertFeedOptions = {}): AlertFeedModel {
  const safeHours = Math.max(1, Math.min(24 * 90, Math.floor(hours)));
  const limit = Math.max(1, Math.min(MAX_LIMIT, Math.floor(opts.limit ?? DEFAULT_LIMIT)));
  const windowEndMs = opts.nowMs ?? Date.now();
  const windowStartMs = windowEndMs - safeHours * MS_PER_HOUR;
  const minSeverity = opts.minSeverity ?? "info";
  const floor = sevRank(minSeverity);
  const base = normaliseBase(opts.baseUrl);

  const windowed = alertStore
    .all()
    .filter((a): a is StoredAlert => typeof a.time === "number" && Number.isFinite(a.time))
    .filter((a) => a.time >= windowStartMs && a.time <= windowEndMs);

  // Newest first; alertStore.all() already returns newest-first, but sort
  // explicitly so the contract is local and stable.
  const passing = windowed
    .filter((a) => sevRank(a.severity) >= floor)
    .sort((x, y) => y.time - x.time);

  const items: AlertFeedItem[] = passing.slice(0, limit).map((a) => {
    const sev = asSeverity(a.severity);
    const date = new Date(a.time);
    const body = buildBody(a, sev);
    return {
      id: a.id,
      guid: `urn:sectool:alert:${a.id}`,
      time: a.time,
      isoTime: date.toISOString(),
      rfc822Time: date.toUTCString(),
      title: buildTitle(a, sev),
      severity: sev,
      category: a.category,
      signature: a.signature,
      classification: a.classification,
      srcIp: validIp(a.srcIp),
      dstIp: validIp(a.dstIp),
      action: a.action,
      link: base ? `${base}/api/alerts/${encodeURIComponent(a.id)}` : undefined,
      hasSummary: Boolean(a.summary && !a.summary.fallback),
      contentHtml: body.html,
      contentText: body.text,
    } satisfies AlertFeedItem;
  });

  const sevLabel = minSeverity === "info" ? "all severities" : `severity ≥ ${minSeverity}`;
  const title = "SecTool security alerts";
  const description = `IDS/IPS alerts from the UDM Pro, newest first — last ${safeHours} hour(s), ${sevLabel}.`;
  const selfLink = base ? `${base}/api/feed.xml` : undefined;
  const homeLink = base ? `${base}/` : undefined;

  const model: AlertFeedModel = {
    hours: safeHours,
    windowStartMs,
    windowEndMs,
    generatedAtMs: windowEndMs,
    totalWindowAlerts: windowed.length,
    includedAlerts: items.length,
    minSeverity,
    limit,
    title,
    description,
    selfLink,
    homeLink,
    items,
    rss: "",
    atom: "",
    jsonFeed: "",
  };

  model.rss = renderRss(model);
  model.atom = renderAtom(model);
  model.jsonFeed = renderJsonFeed(model);
  return model;
}

/** Render the model as an RSS 2.0 document. */
function renderRss(m: AlertFeedModel): string {
  const lastBuild = new Date(m.generatedAtMs).toUTCString();
  const channelLink = m.homeLink ?? "urn:sectool:feed";
  const lines: string[] = [];
  lines.push(`<?xml version="1.0" encoding="UTF-8"?>`);
  lines.push(`<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">`);
  lines.push(`  <channel>`);
  lines.push(`    <title>${xmlEscape(m.title)}</title>`);
  lines.push(`    <link>${xmlEscape(channelLink)}</link>`);
  lines.push(`    <description>${xmlEscape(m.description)}</description>`);
  lines.push(`    <language>en</language>`);
  lines.push(`    <generator>SecTool</generator>`);
  lines.push(`    <lastBuildDate>${lastBuild}</lastBuildDate>`);
  if (m.selfLink) {
    lines.push(
      `    <atom:link href="${xmlEscape(m.selfLink)}" rel="self" type="application/rss+xml"/>`,
    );
  }
  for (const it of m.items) {
    lines.push(`    <item>`);
    lines.push(`      <title>${xmlEscape(it.title)}</title>`);
    if (it.link) lines.push(`      <link>${xmlEscape(it.link)}</link>`);
    lines.push(`      <guid isPermaLink="false">${xmlEscape(it.guid)}</guid>`);
    lines.push(`      <pubDate>${it.rfc822Time}</pubDate>`);
    lines.push(`      <category>${xmlEscape(it.severity)}</category>`);
    lines.push(`      <description>${cdata(it.contentHtml)}</description>`);
    lines.push(`    </item>`);
  }
  lines.push(`  </channel>`);
  lines.push(`</rss>`);
  return lines.join("\n") + "\n";
}

/** Render the model as an Atom 1.0 document. */
function renderAtom(m: AlertFeedModel): string {
  const updated = new Date(m.generatedAtMs).toISOString();
  const lines: string[] = [];
  lines.push(`<?xml version="1.0" encoding="UTF-8"?>`);
  lines.push(`<feed xmlns="http://www.w3.org/2005/Atom">`);
  lines.push(`  <title>${xmlEscape(m.title)}</title>`);
  lines.push(`  <subtitle>${xmlEscape(m.description)}</subtitle>`);
  lines.push(`  <id>urn:sectool:feed</id>`);
  lines.push(`  <updated>${updated}</updated>`);
  lines.push(`  <generator>SecTool</generator>`);
  lines.push(`  <author><name>SecTool</name></author>`);
  if (m.selfLink) {
    lines.push(`  <link rel="self" href="${xmlEscape(m.selfLink)}" type="application/atom+xml"/>`);
  }
  if (m.homeLink) lines.push(`  <link rel="alternate" href="${xmlEscape(m.homeLink)}"/>`);
  for (const it of m.items) {
    lines.push(`  <entry>`);
    lines.push(`    <title>${xmlEscape(it.title)}</title>`);
    lines.push(`    <id>${xmlEscape(it.guid)}</id>`);
    lines.push(`    <updated>${it.isoTime}</updated>`);
    lines.push(`    <published>${it.isoTime}</published>`);
    lines.push(`    <category term="${xmlEscape(it.severity)}"/>`);
    if (it.link) lines.push(`    <link rel="alternate" href="${xmlEscape(it.link)}"/>`);
    lines.push(`    <content type="html">${cdata(it.contentHtml)}</content>`);
    lines.push(`  </entry>`);
  }
  lines.push(`</feed>`);
  return lines.join("\n") + "\n";
}

/** Render the model as a JSON Feed 1.1 document. */
function renderJsonFeed(m: AlertFeedModel): string {
  const feed: Record<string, unknown> = {
    version: "https://jsonfeed.org/version/1.1",
    title: m.title,
    description: m.description,
  };
  if (m.homeLink) feed.home_page_url = m.homeLink;
  if (m.selfLink) feed.feed_url = m.selfLink.replace(/\.xml$/, ".json");
  feed.items = m.items.map((it) => {
    const item: Record<string, unknown> = {
      id: it.guid,
      title: it.title,
      content_html: it.contentHtml,
      content_text: it.contentText,
      date_published: it.isoTime,
      tags: [it.severity, it.category].filter(Boolean),
    };
    if (it.link) item.url = it.link;
    return item;
  });
  return JSON.stringify(feed, null, 2) + "\n";
}

/** A filesystem-safe filename for a downloaded feed in the given format. */
export function feedFilename(nowMs: number, fmt: FeedFormat): string {
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  const ext = fmt === "rss" ? "xml" : fmt === "atom" ? "atom" : "json";
  return `sectool-feed-${stamp}.${ext}`;
}

/** Coerce an arbitrary string into a {@link FeedFormat}; defaults to "rss". */
export function parseFeedFormat(raw: string | undefined | null): FeedFormat {
  const s = (raw ?? "").trim().toLowerCase();
  if (s === "atom") return "atom";
  if (s === "json" || s === "jsonfeed" || s === "json-feed") return "json";
  return "rss";
}

/** Pick the rendered document for a format. */
export function feedDocument(model: AlertFeedModel, fmt: FeedFormat): string {
  return fmt === "atom" ? model.atom : fmt === "json" ? model.jsonFeed : model.rss;
}

/** The MIME content-type for a feed format. */
export function feedContentType(fmt: FeedFormat): string {
  if (fmt === "atom") return "application/atom+xml; charset=utf-8";
  if (fmt === "json") return "application/feed+json; charset=utf-8";
  return "application/rss+xml; charset=utf-8";
}
