import type { VmessConfig } from '../types';
import { base64ToUint8Array, uint8ArrayToString } from 'foxts/uint8array-utils';

export function parse(line: string): VmessConfig {
  const data = JSON.parse(uint8ArrayToString(base64ToUint8Array(line.slice(8))));
  const json = (data);
  const name = json.ps;
  const path = json.path;

  return {
    raw: line,
    name,
    server: json.add,
    port: Number.parseInt(json.port, 10),
    encryptMethod: json.scy,
    type: 'vmess',
    username: json.id,
    tls: Boolean(json.tls),
    vmessAead: json.aid === '0' || json.aid === 0,
    sni: json.sni,
    ws: json.net === 'ws',
    wsPath: withLeadingSlash(path),
    wsHeaders: (json.sni || json.host) ? `Host:${json.sni || json.host}` : json.add,
    // ws:
    skipCertVerify: true,
    udp: true
  };
}

function withLeadingSlash(path: string): string {
  return path[0] === '/' ? path : `/${path}`;
}
