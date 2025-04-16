import type { VmessConfig } from '../types';
import { Buffer } from 'node:buffer';

const decoder = new TextDecoder();

export function parse(line: string): VmessConfig {
  const data = JSON.parse(decoder.decode(Buffer.from(line.slice(8), 'base64')));
  const json = (data);
  const name = json.ps;
  const path = json.path;

  console.log({ json });

  return {
    raw: line,
    name,
    server: json.add,
    port: Number.parseInt(json.port, 10),
    type: 'vmess',
    username: json.id,
    tls: json.tls,
    vmessAead: json.aid === '0',
    sni: json.sni,
    ws: json.net === 'ws',
    wsPath: path[0] === '/' ? path : `/${path}`,
    wsHeaders: json.host ? `Host:${json.host}` : undefined,
    // ws:
    skipCertVerify: true,
    udp: true
  };
}
