/**
 * Configuration loading & validation. All env access is funneled through here so
 * the rest of the app receives a single, validated, strongly-typed object.
 */
import { homedir } from "node:os";
import { join } from "node:path";
import { LOG_LEVELS, type LogLevel } from "./logger.ts";
import { SEVERITY_ORDER, type Severity } from "./types.ts";

export type AuthMode = "auto" | "oauth" | "apikey";
export type SyslogProtocol = "udp" | "tcp" | "both";

export interface Config {
  discord: {
    webhookUrl: string;
    username: string;
    avatarUrl?: string;
    mention?: string;
  };
  syslog: {
    host: string;
    udpPort: number;
    tcpPort: number;
    protocol: SyslogProtocol;
  };
  claude: {
    authMode: AuthMode;
    apiKey?: string;
    credentialsPath: string;
    model: string;
    maxTokens: number;
    summarizeEnabled: boolean;
  };
  correlation: {
    bufferSize: number;
    bufferTtlMs: number;
    windowMs: number;
    maxEvents: number;
  };
  alerts: {
    minSeverity: Severity;
    dedupeWindowMs: number;
    customPattern?: RegExp;
    /**
     * When true (default), detections the gateway already blocked/dropped are
     * recorded for history but not pushed as notifications — the threat was
     * already stopped at the edge, so it's noise rather than something to act on.
     */
    skipGatewayBlocked: boolean;
  };
  runtime: {
    logLevel: LogLevel;
    dryRun: boolean;
  };
  unifi: {
    host: string;
    site: string;
    username?: string;
    password?: string;
    apiKey?: string;
    verifyTls: boolean;
  };
  backfill: {
    maxEvents: number;
    postDelayMs: number;
  };
  watch: {
    enabled: boolean;
    pollMs: number;
    lookbackMs: number;
  };
  web: {
    enabled: boolean;
    host: string;
    port: number;
    defaultHours: number;
  };
  netflow: {
    enabled: boolean;
    host: string;
    port: number;
    maxFlows: number;
    retentionMinutes: number;
    autoConfigureUdm: boolean;
    advertiseIp?: string;
    persist: boolean;
  };
  enrich: {
    vtApiKey?: string;
    abuseKey?: string;
    ipinfoToken?: string;
    auto: boolean;
    escalateVtMalicious: number;
    escalateAbuseScore: number;
  };
  block: {
    enabled: boolean;
    reassertSec: number;
    allowlist: string[];
  };
  digest: {
    enabled: boolean;
    hour: number;
    periodHours: number;
  };
  intel: {
    enabled: boolean;
    block: boolean;
    refreshHours: number;
  };
  autoRespond: {
    blockOnEscalation: boolean;
    repeatThreshold: number;
    repeatWindowHours: number;
    dailyCap: number;
    dryRun: boolean;
    reactiveInbound: boolean;
    reactiveIntervalSec: number;
  };
  honeypot: {
    enabled: boolean;
    host: string;
    ports: number[];
    autoBlock: boolean;
  };
  anomaly: {
    enabled: boolean;
    minLearnHours: number;
    intervalSec: number;
    volumeSpikeFactor: number;
    alertDiscord: boolean;
  };
  agent: {
    enabled: boolean;
    port: number;
    token?: string;
    distHost: string;
    distPort: number;
  };
  discovery: {
    enabled: boolean;
    ports: number[];
    timeoutMs: number;
    concurrency: number;
    maxHosts: number;
    subnets: string[];
  };
  deploy: {
    enabled: boolean;
    sshUser: string;
    sshPort: number;
    identityFile?: string;
    serverIp?: string;
    concurrency: number;
    timeoutMs: number;
    /**
     * WinRM transport for Windows hosts that don't run SSH. Pushes the agent by
     * driving the local PowerShell client's `Invoke-Command` against the target,
     * which fetches + runs the same /install.ps1 one-liner the dist server serves.
     */
    winrmEnabled: boolean;
    winrmUser: string;
    winrmPort: number;
    winrmUseSsl: boolean;
  };
}

class ConfigError extends Error {}

function str(key: string, fallback?: string): string {
  const v = process.env[key];
  if (v === undefined || v === "") {
    if (fallback !== undefined) return fallback;
    throw new ConfigError(`Missing required env var: ${key}`);
  }
  return v;
}

function optStr(key: string): string | undefined {
  const v = process.env[key];
  return v === undefined || v === "" ? undefined : v;
}

function int(key: string, fallback: number): number {
  const v = process.env[key];
  if (v === undefined || v === "") return fallback;
  const n = Number.parseInt(v, 10);
  if (!Number.isFinite(n)) throw new ConfigError(`Env var ${key} must be an integer, got "${v}"`);
  return n;
}

function bool(key: string, fallback: boolean): boolean {
  const v = process.env[key];
  if (v === undefined || v === "") return fallback;
  return /^(1|true|yes|on)$/i.test(v.trim());
}

function oneOf<T extends string>(key: string, allowed: readonly T[], fallback: T): T {
  const v = process.env[key];
  if (v === undefined || v === "") return fallback;
  const lower = v.trim().toLowerCase() as T;
  if (!allowed.includes(lower)) {
    throw new ConfigError(`Env var ${key} must be one of ${allowed.join(", ")}, got "${v}"`);
  }
  return lower;
}

export function loadConfig(): Config {
  const authMode = oneOf<AuthMode>("CLAUDE_AUTH_MODE", ["auto", "oauth", "apikey"], "auto");
  const apiKey = optStr("ANTHROPIC_API_KEY");

  if (authMode === "apikey" && !apiKey) {
    throw new ConfigError("CLAUDE_AUTH_MODE=apikey but ANTHROPIC_API_KEY is not set.");
  }

  let customPattern: RegExp | undefined;
  const rawPattern = optStr("ALERT_PATTERN");
  if (rawPattern) {
    try {
      customPattern = new RegExp(rawPattern, "i");
    } catch (err) {
      throw new ConfigError(`ALERT_PATTERN is not a valid regex: ${(err as Error).message}`);
    }
  }

  return {
    discord: {
      webhookUrl: str("DISCORD_WEBHOOK_URL"),
      username: str("DISCORD_USERNAME", "UDM Sentinel"),
      avatarUrl: optStr("DISCORD_AVATAR_URL"),
      mention: optStr("DISCORD_MENTION"),
    },
    syslog: {
      host: str("SYSLOG_HOST", "0.0.0.0"),
      udpPort: int("SYSLOG_UDP_PORT", 5514),
      tcpPort: int("SYSLOG_TCP_PORT", 5514),
      protocol: oneOf<SyslogProtocol>("SYSLOG_PROTOCOL", ["udp", "tcp", "both"], "udp"),
    },
    claude: {
      authMode,
      apiKey,
      credentialsPath: str("CLAUDE_CREDENTIALS_PATH", join(homedir(), ".claude", ".credentials.json")),
      model: str("CLAUDE_MODEL", "claude-sonnet-4-6"),
      maxTokens: int("CLAUDE_MAX_TOKENS", 1024),
      summarizeEnabled: bool("SUMMARIZE_ENABLED", true),
    },
    correlation: {
      bufferSize: int("LOG_BUFFER_SIZE", 5000),
      bufferTtlMs: int("LOG_BUFFER_TTL_SEC", 900) * 1000,
      windowMs: int("CORRELATION_WINDOW_SEC", 180) * 1000,
      maxEvents: int("CORRELATION_MAX_EVENTS", 40),
    },
    alerts: {
      minSeverity: oneOf<Severity>("MIN_SEVERITY", SEVERITY_ORDER, "low"),
      dedupeWindowMs: int("DEDUPE_WINDOW_SEC", 300) * 1000,
      customPattern,
      skipGatewayBlocked: bool("SKIP_GATEWAY_BLOCKED", true),
    },
    runtime: {
      logLevel: oneOf<LogLevel>("LOG_LEVEL", LOG_LEVELS, "info"),
      dryRun: bool("DRY_RUN", false),
    },
    unifi: {
      host: str("UNIFI_HOST", "https://192.168.0.1").replace(/\/+$/, ""),
      site: str("UNIFI_SITE", "default"),
      username: optStr("UNIFI_USERNAME"),
      password: optStr("UNIFI_PASSWORD"),
      apiKey: optStr("UNIFI_API_KEY"),
      verifyTls: bool("UNIFI_VERIFY_TLS", false),
    },
    backfill: {
      maxEvents: int("BACKFILL_MAX", 200),
      postDelayMs: int("BACKFILL_POST_DELAY_MS", 1200),
    },
    watch: {
      enabled: bool("WATCH_ENABLED", true),
      pollMs: int("WATCH_POLL_SEC", 45) * 1000,
      lookbackMs: int("WATCH_LOOKBACK_SEC", 600) * 1000,
    },
    web: {
      enabled: bool("WEB_ENABLED", true),
      host: str("WEB_HOST", "127.0.0.1"),
      port: int("WEB_PORT", 8787),
      defaultHours: int("WEB_DEFAULT_HOURS", 48),
    },
    netflow: {
      enabled: bool("NETFLOW_ENABLED", false),
      host: str("NETFLOW_HOST", "0.0.0.0"),
      port: int("NETFLOW_PORT", 2055),
      maxFlows: int("NETFLOW_MAX_FLOWS", 500000),
      retentionMinutes: int("NETFLOW_RETENTION_MIN", 10080), // 7 days
      autoConfigureUdm: bool("NETFLOW_AUTOCONFIGURE_UDM", true),
      advertiseIp: optStr("NETFLOW_ADVERTISE_IP"),
      persist: bool("NETFLOW_PERSIST", true),
    },
    enrich: {
      vtApiKey: optStr("VT_API_KEY"),
      abuseKey: optStr("ABUSEIPDB_API_KEY"),
      ipinfoToken: optStr("IPINFO_TOKEN"),
      auto: bool("ENRICH_AUTO", true),
      escalateVtMalicious: int("ESCALATE_VT_MALICIOUS", 3),
      escalateAbuseScore: int("ESCALATE_ABUSE_SCORE", 50),
    },
    block: {
      enabled: bool("BLOCK_ENABLED", true),
      reassertSec: int("BLOCK_REASSERT_SEC", 90),
      allowlist: (optStr("BLOCK_ALLOWLIST") ?? "")
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean),
    },
    digest: {
      enabled: bool("DIGEST_ENABLED", false),
      hour: int("DIGEST_HOUR", 8),
      periodHours: int("DIGEST_PERIOD_HOURS", 24),
    },
    intel: {
      enabled: bool("INTEL_FEEDS_ENABLED", false),
      block: bool("INTEL_BLOCK", true),
      refreshHours: int("INTEL_REFRESH_HOURS", 24),
    },
    autoRespond: {
      blockOnEscalation: bool("AUTORESPOND_BLOCK_ON_ESCALATION", false),
      repeatThreshold: int("AUTORESPOND_REPEAT_THRESHOLD", 0),
      repeatWindowHours: int("AUTORESPOND_REPEAT_WINDOW_HOURS", 24),
      dailyCap: int("AUTORESPOND_DAILY_CAP", 50),
      dryRun: bool("AUTORESPOND_DRY_RUN", false),
      reactiveInbound: bool("REACTIVE_INBOUND_BLOCK", false),
      reactiveIntervalSec: int("REACTIVE_INBOUND_INTERVAL_SEC", 120),
    },
    honeypot: {
      enabled: bool("HONEYPOT_ENABLED", false),
      host: str("HONEYPOT_HOST", "0.0.0.0"),
      ports: (optStr("HONEYPOT_PORTS") ?? "23,2323,21,2222,3389,5900,1433,8081")
        .split(",")
        .map((s) => Number.parseInt(s.trim(), 10))
        .filter((n) => Number.isFinite(n) && n > 0 && n < 65536),
      autoBlock: bool("HONEYPOT_AUTOBLOCK", false),
    },
    anomaly: {
      enabled: bool("ANOMALY_ENABLED", false),
      minLearnHours: int("ANOMALY_MIN_LEARN_HOURS", 24),
      intervalSec: int("ANOMALY_INTERVAL_SEC", 300),
      volumeSpikeFactor: int("ANOMALY_VOLUME_SPIKE_FACTOR", 8),
      alertDiscord: bool("ANOMALY_ALERT_DISCORD", true),
    },
    agent: {
      enabled: bool("AGENT_ENABLED", false),
      port: int("AGENT_PORT", 7879),
      token: optStr("AGENT_TOKEN"),
      distHost: str("AGENT_DIST_HOST", "0.0.0.0"),
      distPort: int("AGENT_DIST_PORT", 7878),
    },
    discovery: {
      enabled: bool("DISCOVERY_ENABLED", true),
      ports: (optStr("DISCOVERY_PORTS") ?? "22,80,443,445,3389,53,5985,7879")
        .split(",")
        .map((s) => Number.parseInt(s.trim(), 10))
        .filter((n) => Number.isFinite(n) && n > 0 && n < 65536),
      timeoutMs: int("DISCOVERY_TIMEOUT_MS", 600),
      concurrency: int("DISCOVERY_CONCURRENCY", 128),
      maxHosts: int("DISCOVERY_MAX_HOSTS", 1024),
      subnets: (optStr("DISCOVERY_SUBNETS") ?? "")
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean),
    },
    deploy: {
      // Pushing software onto other machines is sensitive — opt-in only.
      enabled: bool("DEPLOY_ENABLED", false),
      sshUser: str("DEPLOY_SSH_USER", "root"),
      sshPort: int("DEPLOY_SSH_PORT", 22),
      // Defaults to the same key SecTool uses for the UDM (set up via --setup-ssh)
      // if present; falls back to the agent's SSH default key/agent otherwise.
      identityFile: optStr("DEPLOY_SSH_KEY"),
      // The IP/host the *target* device uses to reach SecTool's agent dist server.
      // Auto-detected from local interfaces (same-subnet preferred) when unset.
      serverIp: optStr("DEPLOY_SERVER_IP"),
      concurrency: int("DEPLOY_CONCURRENCY", 4),
      timeoutMs: int("DEPLOY_TIMEOUT_MS", 120000),
      // WinRM fallback for Windows hosts without SSH. Needs a password (WinRM has
      // no key auth) and the local `powershell`/`pwsh` client to drive it.
      winrmEnabled: bool("DEPLOY_WINRM_ENABLED", true),
      winrmUser: str("DEPLOY_WINRM_USER", "Administrator"),
      winrmPort: int("DEPLOY_WINRM_PORT", 5985),
      winrmUseSsl: bool("DEPLOY_WINRM_USE_SSL", false),
    },
  };
}

/** Returns a copy of the config safe to print (secrets masked). */
export function redactConfig(cfg: Config): unknown {
  const maskUrl = (u: string) => u.replace(/(https?:\/\/[^/]+\/[^/]+\/).+/i, "$1***");
  return {
    ...cfg,
    discord: { ...cfg.discord, webhookUrl: maskUrl(cfg.discord.webhookUrl) },
    claude: {
      ...cfg.claude,
      apiKey: cfg.claude.apiKey ? "***" : undefined,
    },
    alerts: {
      ...cfg.alerts,
      customPattern: cfg.alerts.customPattern?.source,
    },
    unifi: {
      ...cfg.unifi,
      password: cfg.unifi.password ? "***" : undefined,
      apiKey: cfg.unifi.apiKey ? "***" : undefined,
    },
    enrich: {
      vtApiKey: cfg.enrich.vtApiKey ? "***" : undefined,
      abuseKey: cfg.enrich.abuseKey ? "***" : undefined,
      ipinfoToken: cfg.enrich.ipinfoToken ? "***" : undefined,
    },
  };
}

export { ConfigError };
