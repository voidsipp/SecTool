/**
 * IPFIX (NetFlow v10) and NetFlow v9 decoder.
 *
 * Both are template-based: template records define the layout of subsequent data
 * records. We cache templates per (observation-domain, template-id) and decode
 * data sets into flow records. Options templates are skipped (metadata, not
 * flows); their data sets are simply ignored when no flow template matches.
 */
import { isIP } from "node:net";

export interface Flow {
  srcIp?: string;
  dstIp?: string;
  srcPort?: number;
  dstPort?: number;
  proto?: number;
  bytes?: number;
  packets?: number;
  start?: number; // ms epoch
  end?: number; // ms epoch
  fwdStatus?: number; // IPFIX forwardingStatus (>=128 => dropped)
  tcpFlags?: number;
  receivedAt: number;
}

interface Field {
  id: number;
  len: number;
  enterprise: boolean;
}
interface Template {
  fields: Field[];
}

// IANA IPFIX information element IDs (shared with NetFlow v9 field types).
const IE = {
  octets: 1,
  packets: 2,
  proto: 4,
  tcpFlags: 6,
  srcPort: 7,
  srcIp4: 8,
  dstIp4: 12,
  dstPort: 11,
  srcIp6: 27,
  dstIp6: 28,
  flowEndSysUpTime: 21,
  flowStartSysUpTime: 22,
  fwdStatus: 89,
  flowStartSeconds: 150,
  flowEndSeconds: 151,
  flowStartMs: 152,
  flowEndMs: 153,
  octetsTotal: 85,
  packetsTotal: 86,
};

function uint(buf: Buffer, off: number, len: number): number {
  if (len <= 0) return 0;
  if (len <= 6) return buf.readUIntBE(off, len);
  if (len === 8) return Number(buf.readBigUInt64BE(off));
  // Fallback for unusual widths: read the low 6 bytes.
  return buf.readUIntBE(off + (len - 6), 6);
}

function ipv4(buf: Buffer, off: number): string {
  return `${buf[off]}.${buf[off + 1]}.${buf[off + 2]}.${buf[off + 3]}`;
}
function ipv6(buf: Buffer, off: number, len: number): string {
  const parts: string[] = [];
  for (let i = 0; i < len; i += 2) parts.push(buf.readUInt16BE(off + i).toString(16));
  return parts.join(":");
}

export class IpfixDecoder {
  #templates = new Map<string, Template>();
  templatesSeen = 0;

  decode(buf: Buffer, receivedAt: number): Flow[] {
    if (buf.length < 16) return [];
    const version = buf.readUInt16BE(0);
    let offset: number;
    let end: number;
    let domain: number;
    let sysUptime = 0;
    let unixSecs = 0;

    if (version === 10) {
      end = Math.min(buf.readUInt16BE(2), buf.length);
      domain = buf.readUInt32BE(12);
      offset = 16;
    } else if (version === 9) {
      sysUptime = buf.readUInt32BE(4);
      unixSecs = buf.readUInt32BE(8);
      domain = buf.readUInt32BE(16);
      end = buf.length;
      offset = 20;
    } else {
      return [];
    }

    const flows: Flow[] = [];
    while (offset + 4 <= end) {
      const setId = buf.readUInt16BE(offset);
      const setLen = buf.readUInt16BE(offset + 2);
      if (setLen < 4) break;
      const setEnd = Math.min(offset + setLen, end);
      let p = offset + 4;

      const isTemplate = (version === 10 && setId === 2) || (version === 9 && setId === 0);
      const isOptions = (version === 10 && setId === 3) || (version === 9 && setId === 1);

      if (isTemplate) {
        while (p + 4 <= setEnd) {
          const templateId = buf.readUInt16BE(p);
          const fieldCount = buf.readUInt16BE(p + 2);
          p += 4;
          if (templateId === 0 || fieldCount === 0) break; // padding
          const fields: Field[] = [];
          for (let i = 0; i < fieldCount && p + 4 <= setEnd; i++) {
            let elemId = buf.readUInt16BE(p);
            const fieldLen = buf.readUInt16BE(p + 2);
            p += 4;
            const enterprise = (elemId & 0x8000) !== 0;
            if (enterprise) {
              elemId &= 0x7fff;
              p += 4; // skip enterprise number
            }
            fields.push({ id: elemId, len: fieldLen, enterprise });
          }
          this.#templates.set(`${domain}:${templateId}`, { fields });
          this.templatesSeen++;
        }
      } else if (isOptions) {
        // Skip options templates — they describe metadata, not flows.
      } else if (setId >= 256) {
        const tmpl = this.#templates.get(`${domain}:${setId}`);
        if (tmpl) {
          const fixedLen = tmpl.fields.reduce((s, f) => s + (f.len === 0xffff ? 1 : f.len), 0);
          while (p + fixedLen <= setEnd) {
            const r = this.#readRecord(buf, p, setEnd, tmpl, { version, sysUptime, unixSecs, receivedAt });
            if (!r) break;
            if (r.flow) flows.push(r.flow);
            if (r.next <= p) break;
            p = r.next;
          }
        }
      }
      offset += setLen;
    }
    return flows;
  }

  #readRecord(
    buf: Buffer,
    start: number,
    setEnd: number,
    tmpl: Template,
    ctx: { version: number; sysUptime: number; unixSecs: number; receivedAt: number },
  ): { flow: Flow | null; next: number } | null {
    let p = start;
    const flow: Flow = { receivedAt: ctx.receivedAt };
    let startSys: number | undefined;
    let endSys: number | undefined;

    for (const f of tmpl.fields) {
      let len = f.len;
      if (len === 0xffff) {
        if (p + 1 > setEnd) return null;
        len = buf.readUInt8(p);
        p += 1;
        if (len === 255) {
          if (p + 2 > setEnd) return null;
          len = buf.readUInt16BE(p);
          p += 2;
        }
      }
      if (p + len > setEnd) return { flow: null, next: setEnd };
      if (!f.enterprise) {
        switch (f.id) {
          case IE.srcIp4: flow.srcIp = ipv4(buf, p); break;
          case IE.dstIp4: flow.dstIp = ipv4(buf, p); break;
          case IE.srcIp6: flow.srcIp = ipv6(buf, p, len); break;
          case IE.dstIp6: flow.dstIp = ipv6(buf, p, len); break;
          case IE.srcPort: flow.srcPort = uint(buf, p, len); break;
          case IE.dstPort: flow.dstPort = uint(buf, p, len); break;
          case IE.proto: flow.proto = uint(buf, p, len); break;
          case IE.octets:
          case IE.octetsTotal: flow.bytes = (flow.bytes ?? 0) + uint(buf, p, len); break;
          case IE.packets:
          case IE.packetsTotal: flow.packets = (flow.packets ?? 0) + uint(buf, p, len); break;
          case IE.flowStartMs: flow.start = uint(buf, p, len); break;
          case IE.flowEndMs: flow.end = uint(buf, p, len); break;
          case IE.flowStartSeconds: flow.start = uint(buf, p, len) * 1000; break;
          case IE.flowEndSeconds: flow.end = uint(buf, p, len) * 1000; break;
          case IE.flowStartSysUpTime: startSys = uint(buf, p, len); break;
          case IE.flowEndSysUpTime: endSys = uint(buf, p, len); break;
          case IE.fwdStatus: flow.fwdStatus = uint(buf, p, len); break;
          case IE.tcpFlags: flow.tcpFlags = uint(buf, p, len); break;
          default: break;
        }
      }
      p += len;
    }

    // Resolve NetFlow v9 sysUpTime-relative timestamps to wall-clock.
    if (flow.start === undefined && startSys !== undefined && ctx.unixSecs) {
      flow.start = ctx.unixSecs * 1000 - (ctx.sysUptime - startSys);
    }
    if (flow.end === undefined && endSys !== undefined && ctx.unixSecs) {
      flow.end = ctx.unixSecs * 1000 - (ctx.sysUptime - endSys);
    }
    if (flow.start === undefined) flow.start = ctx.receivedAt;
    if (flow.end === undefined) flow.end = flow.start;

    // Only keep records that actually carry IP endpoints.
    const ok = (flow.srcIp && isIP(flow.srcIp) > 0) || (flow.dstIp && isIP(flow.dstIp) > 0);
    return { flow: ok ? flow : null, next: p };
  }
}
