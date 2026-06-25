/**
 * Agent distribution + update server. Bound to the LAN (separate from the
 * localhost-only dashboard) so devices can install the endpoint agent with a
 * one-liner and the agent can check for updates on each start.
 *
 * Serves (read-only):
 *   GET /version            -> {version} parsed from the agent source
 *   GET /agent              -> the agent source (sectool-agent.mjs)
 *   GET /install.ps1        -> Windows one-liner installer (templated)
 *   GET /install.sh         -> Linux/macOS one-liner installer (templated)
 *   GET /                   -> human-readable instructions
 *
 * Security: install scripts embed AGENT_TOKEN, so only expose on a trusted LAN.
 */
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import type { Config } from "../config.ts";
import { log } from "../logger.ts";

const AGENT_FILE = fileURLToPath(new URL("../../agent/sectool-agent.mjs", import.meta.url));

function readAgent(): string {
  try {
    return readFileSync(AGENT_FILE, "utf8");
  } catch {
    return "";
  }
}
function versionOf(src: string): string {
  const m = src.match(/AGENT_VERSION\s*=\s*["']([\d.]+)["']/);
  return m ? m[1]! : "0.0.0";
}

function psInstall(server: string, token: string, port: number): string {
  // Note: only ${server}/${token}/${port} are JS-interpolated; every $name below
  // is a literal PowerShell variable. No backticks/backslash-escapes (PowerShell
  // uses different quoting than JS/bash).
  return `# SecTool endpoint agent installer (Windows)
$ErrorActionPreference = 'Stop'
$server = '${server}'
$token  = '${token}'
$port   = ${port}
$node = (Get-Command node -ErrorAction SilentlyContinue).Source
if (-not $node) { Write-Error 'Node.js 18+ is required. Install it (winget install OpenJS.NodeJS.LTS) then re-run.'; return }
$dir = Join-Path $env:LOCALAPPDATA 'SecToolAgent'
New-Item -ItemType Directory -Force -Path $dir | Out-Null
Write-Host "Downloading agent from $server ..."
Invoke-WebRequest -UseBasicParsing "$server/agent" -OutFile (Join-Path $dir 'sectool-agent.mjs')
@{ token = $token; updateUrl = $server; port = $port } | ConvertTo-Json | Set-Content -Encoding UTF8 (Join-Path $dir 'agent.config.json')
$agent = Join-Path $dir 'sectool-agent.mjs'
$vbsPath = Join-Path $dir 'launch.vbs'
# tiny VBS shim launches node windowless (avoids a console flash + quoting issues)
$vbs = 'CreateObject("WScript.Shell").Run """' + $node + '"" ""' + $agent + '""", 0, False'
Set-Content -Path $vbsPath -Value $vbs -Encoding ASCII
$action   = New-ScheduledTaskAction -Execute 'wscript.exe' -Argument ('"' + $vbsPath + '"')
$trigger  = New-ScheduledTaskTrigger -AtLogOn
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName 'SecToolAgent' -Action $action -Trigger $trigger -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName 'SecToolAgent'
Start-Sleep -Seconds 3
try { $h = Invoke-RestMethod "http://127.0.0.1:$port/health" -TimeoutSec 5; Write-Host ('SecTool agent v' + $h.version + ' installed and running on ' + $h.host + '.') -ForegroundColor Green }
catch { Write-Host 'SecTool agent installed (Scheduled Task: SecToolAgent). It will start on next logon.' -ForegroundColor Yellow }
`;
}

function shInstall(server: string, token: string, port: number): string {
  return `#!/usr/bin/env bash
# SecTool endpoint agent installer (Linux/macOS)
set -e
SERVER='${server}'
TOKEN='${token}'
PORT=${port}
NODE="$(command -v node || true)"
if [ -z "$NODE" ]; then echo 'Node.js 18+ is required. Install it, then re-run.'; exit 1; fi
DIR="$HOME/.sectool-agent"; mkdir -p "$DIR"
echo "Downloading agent from $SERVER ..."
curl -fsSL "$SERVER/agent" -o "$DIR/sectool-agent.mjs"
cat > "$DIR/agent.config.json" <<CFG
{"token":"$TOKEN","updateUrl":"$SERVER","port":$PORT}
CFG
if command -v systemctl >/dev/null 2>&1; then
  mkdir -p "$HOME/.config/systemd/user"
  cat > "$HOME/.config/systemd/user/sectool-agent.service" <<UNIT
[Unit]
Description=SecTool endpoint agent
[Service]
ExecStart=$NODE $DIR/sectool-agent.mjs
WorkingDirectory=$DIR
Restart=always
[Install]
WantedBy=default.target
UNIT
  systemctl --user daemon-reload
  systemctl --user enable --now sectool-agent
  echo "SecTool agent installed (systemd user service)."
elif command -v launchctl >/dev/null 2>&1; then
  PLIST="$HOME/Library/LaunchAgents/com.sectool.agent.plist"
  cat > "$PLIST" <<PL
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>com.sectool.agent</string>
<key>ProgramArguments</key><array><string>$NODE</string><string>$DIR/sectool-agent.mjs</string></array>
<key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
<key>WorkingDirectory</key><string>$DIR</string>
</dict></plist>
PL
  launchctl unload "$PLIST" 2>/dev/null || true
  launchctl load "$PLIST"
  echo "SecTool agent installed (launchd)."
else
  echo "Agent downloaded to $DIR. Start it with: node $DIR/sectool-agent.mjs"
fi
`;
}

export function startAgentDistServer(cfg: Config): void {
  const handler = (req: IncomingMessage, res: ServerResponse) => {
    const path = (req.url ?? "/").split("?")[0];
    const host = req.headers.host || `127.0.0.1:${cfg.agent.distPort}`;
    const base = `http://${host}`;
    const token = cfg.agent.token ?? "";
    const send = (code: number, body: string, type: string) => {
      res.writeHead(code, { "content-type": type, "cache-control": "no-store" });
      res.end(body);
    };
    if (path === "/version") return send(200, JSON.stringify({ version: versionOf(readAgent()) }), "application/json");
    if (path === "/agent" || path === "/sectool-agent.mjs") return send(200, readAgent(), "text/javascript; charset=utf-8");
    if (path === "/install.ps1") return send(200, psInstall(base, token, cfg.agent.port), "text/plain; charset=utf-8");
    if (path === "/install.sh") return send(200, shInstall(base, token, cfg.agent.port), "text/plain; charset=utf-8");
    if (path === "/") {
      return send(
        200,
        `SecTool agent distribution (v${versionOf(readAgent())})\n\n` +
          `Windows : irm ${base}/install.ps1 | iex\n` +
          `Linux/macOS: curl -fsSL ${base}/install.sh | bash\n`,
        "text/plain; charset=utf-8",
      );
    }
    send(404, "not found", "text/plain");
  };
  const server = createServer(handler);
  server.on("error", (err) => log.error(`Agent dist server error: ${err.message}`));
  server.listen(cfg.agent.distPort, cfg.agent.distHost, () => {
    log.info(`Agent installer/updater on http://${cfg.agent.distHost}:${cfg.agent.distPort} (irm <host>/install.ps1 | iex)`);
  });
}
