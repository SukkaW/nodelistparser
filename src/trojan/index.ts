import type { TrojanConfig } from '../types';

export function parse(line: string): TrojanConfig {
  const url = new URL(line);

  // trojan://password@remote_host:remote_port
  const password = url.username;
  const server = url.hostname;
  const port = Number.parseInt(url.port, 10);

  const name = decodeURIComponent(url.hash.slice(1));

  return {
    raw: line,
    name,
    type: 'trojan',
    server,
    port,
    password,
    udp: true,
    sni: url.searchParams.get('sni') ?? server,
    skipCertVerify: true
  };
}
