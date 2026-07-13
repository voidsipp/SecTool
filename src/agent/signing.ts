/**
 * Ed25519 signing for agent auto-updates (feature #2). SecTool holds the private
 * key; agents pin the public key (installed by the one-liner installer) and refuse
 * any update whose signature doesn't verify — so a LAN MITM can't push a malicious
 * "update" to agents that now kill/delete/isolate.
 *
 * Private key lives in data/agent-signing.json (chmod best-effort). The public key
 * is safe to hand out (served at /pubkey, embedded in agent.config.json).
 */
import { generateKeyPairSync, createPrivateKey, createPublicKey, sign as cryptoSign, verify as cryptoVerify, type KeyObject } from "node:crypto";
import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname } from "node:path";
import { log } from "../logger.ts";

const KEY_PATH = fileURLToPath(new URL("../../data/agent-signing.json", import.meta.url));

let priv: KeyObject | null = null;
let pubB64 = "";

function load(): void {
  if (priv) return;
  try {
    const raw = JSON.parse(readFileSync(KEY_PATH, "utf8")) as { privateKeyPem: string; publicKeyB64: string };
    priv = createPrivateKey(raw.privateKeyPem);
    pubB64 = raw.publicKeyB64;
    return;
  } catch {
    /* generate a fresh keypair below */
  }
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  priv = privateKey;
  pubB64 = publicKey.export({ format: "der", type: "spki" }).toString("base64");
  const privateKeyPem = privateKey.export({ format: "pem", type: "pkcs8" }).toString();
  try {
    mkdirSync(dirname(KEY_PATH), { recursive: true });
    writeFileSync(KEY_PATH, JSON.stringify({ privateKeyPem, publicKeyB64: pubB64 }, null, 2), { mode: 0o600 });
    log.info("Generated Ed25519 agent-update signing key (data/agent-signing.json).");
  } catch (err) {
    log.warn(`Could not persist agent signing key: ${(err as Error).message}`);
  }
}

/** Base64 SPKI-DER public key — hand this to agents to pin. */
export function agentPublicKeyB64(): string {
  if (!existsSync(KEY_PATH) && !priv) load();
  else load();
  return pubB64;
}

/** Sign agent source bytes; returns a base64 Ed25519 signature. */
export function signAgent(code: Buffer | string): string {
  load();
  const buf = typeof code === "string" ? Buffer.from(code, "utf8") : code;
  return cryptoSign(null, buf, priv!).toString("base64");
}

/** Sanity self-check used by tests. */
export function verifyWithOwnKey(code: Buffer | string, sigB64: string): boolean {
  load();
  const key = createPublicKey({ key: Buffer.from(pubB64, "base64"), format: "der", type: "spki" });
  const buf = typeof code === "string" ? Buffer.from(code, "utf8") : code;
  return cryptoVerify(null, buf, key, Buffer.from(sigB64, "base64"));
}
