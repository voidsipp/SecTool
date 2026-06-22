/**
 * Shared domain types for SecTool.
 */

/** Ordered severity ladder, lowest to highest. */
export const SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"] as const;
export type Severity = (typeof SEVERITY_ORDER)[number];

/** A single parsed syslog line. */
export interface LogEvent {
  /** Original wire text, minus the trailing newline. */
  raw: string;
  /** ms epoch when this process received the packet. */
  receivedAt: number;
  /** ms epoch parsed from the syslog timestamp, if any. */
  timestamp?: number;
  /** Syslog facility (0-23), if a PRI was present. */
  facility?: number;
  /** Syslog severity (0-7), if a PRI was present. */
  syslogSeverity?: number;
  /** Hostname field from the syslog header. */
  host?: string;
  /** Program / tag (e.g. "suricata", "kernel"). */
  appName?: string;
  /** Message body after the syslog header. */
  message: string;
  /** Source IP of the UDP/TCP packet (i.e. the UDM Pro itself). */
  transport: string;
  /** Every IPv4/IPv6 address found anywhere in the line. */
  ips: string[];
}

/** A log event that has been classified as a security alert. */
export interface SecurityAlert {
  /** Stable hash used for de-duplication. */
  id: string;
  event: LogEvent;
  /** Human category, e.g. "IDS/IPS", "Threat", "Firewall". */
  category: string;
  signature?: string;
  signatureId?: string;
  classification?: string;
  /** Suricata priority (1 = most severe). */
  priority?: number;
  protocol?: string;
  srcIp?: string;
  srcPort?: number;
  dstIp?: string;
  dstPort?: number;
  /** "blocked" | "detected" | "allowed" | undefined. */
  action?: string;
  severity: Severity;
}

/** An alert plus the surrounding log context gathered for it. */
export interface CorrelatedContext {
  alert: SecurityAlert;
  relatedEvents: LogEvent[];
  involvedIps: string[];
}

/** Structured summary returned by Claude. */
export interface AlertSummary {
  title: string;
  severity: Severity;
  whatHappened: string;
  riskAssessment: string;
  recommendedActions: string[];
  /** Set when the summary is a non-AI fallback. */
  fallback?: boolean;
  /** Model id that produced the summary, when applicable. */
  model?: string;
}
