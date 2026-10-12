import { stringJoin } from 'foxts/string-join';
import type { WireGuardConfig, WireGuardPeer } from '../types';
import { mihomoIpVersion, surgeIpVersion } from '../utils/ip-version';

function assertValid(config: WireGuardConfig): void {
  const tag = `[wireguard] "${config.name}"`;
  if (!config.privateKey) {
    throw new TypeError(`${tag} is missing privateKey`);
  }
  if (!config.selfIp && !config.selfIpV6) {
    throw new TypeError(`${tag} needs selfIp or selfIpV6`);
  }
  if (config.peers.length === 0) {
    throw new TypeError(`${tag} needs at least one peer`);
  }
  for (let i = 0, len = config.peers.length; i < len; i++) {
    const peer = config.peers[i];
    if (!peer.publicKey) {
      throw new TypeError(`${tag} peer ${i} is missing publicKey`);
    }
    if (!peer.server || !peer.port) {
      throw new TypeError(`${tag} peer ${i} is missing server or port`);
    }
    if (peer.allowedIps.length === 0) {
      throw new TypeError(`${tag} peer ${i} needs at least one allowedIps entry`);
    }
  }
}

type WithoutUndefined<T> = T extends unknown
  ? {
    [K in keyof T as undefined extends T[K] ? never : K]: T[K]
  } & {
    [K in keyof T as undefined extends T[K] ? K : never]?: Exclude<T[K], undefined>
  }
  : never;

function withoutUndefined<T extends Record<string, unknown>>(obj: T): WithoutUndefined<T> {
  const result: Record<string, unknown> = {};
  const keys = Object.keys(obj);
  for (let i = 0, len = keys.length; i < len; i++) {
    const key = keys[i];
    if (obj[key] !== undefined) {
      result[key] = obj[key];
    }
  }
  return result as WithoutUndefined<T>;
}

function endpoint(peer: WireGuardPeer): string {
  return `${peer.server.includes(':') ? `[${peer.server}]` : peer.server}:${peer.port}`;
}

const RE_CLIENT_ID_DECIMAL = /^(\d{1,3})\/(\d{1,3})\/(\d{1,3})$/;
const RE_CLIENT_ID_HEX = /^(?:0x)?([\da-f]{6})$/i;
const RE_CLIENT_ID_BASE64 = /^[\d+/a-z]{4}$/i;

/**
 * Surge accepts client-id as `83/12/235`, 3-byte hex (with or without `0x`),
 * or 4-char base64. Mihomo and Stash only take the bytes, so every form is
 * normalised here.
 */
function reservedBytes(reserved: WireGuardPeer['reserved']): [number, number, number] | undefined {
  if (reserved == null) {
    return undefined;
  }

  let bytes: number[];
  if (typeof reserved !== 'string') {
    bytes = reserved;
  } else if (RE_CLIENT_ID_HEX.test(reserved)) {
    const hex = RE_CLIENT_ID_HEX.exec(reserved)![1];
    bytes = [0, 2, 4].map((offset) => Number.parseInt(hex.slice(offset, offset + 2), 16));
  } else if (RE_CLIENT_ID_BASE64.test(reserved)) {
    bytes = Array.from(atob(reserved), (char) => char.charCodeAt(0));
  } else {
    const match = RE_CLIENT_ID_DECIMAL.exec(reserved);
    if (!match) {
      throw new TypeError(`[wireguard] invalid reserved / client-id "${reserved}"`);
    }
    bytes = match.slice(1).map(Number);
  }

  if (bytes.length !== 3 || bytes.some((byte) => !Number.isSafeInteger(byte) || byte < 0 || byte > 255)) {
    throw new TypeError(`[wireguard] reserved / client-id must be exactly 3 bytes, got "${String(reserved)}"`);
  }
  return bytes as [number, number, number];
}

/**
 * `line` goes under `[Proxy]`, `section` is a standalone `[WireGuard <name>]` block.
 * The caller assembles the profile; both `policy-path` and `[WireGuard *]` + `#!include`
 * accept the same file.
 */
export function surge(config: WireGuardConfig): { line: string, section: string } {
  assertValid(config);
  const sectionName = config.sectionName ?? config.name;

  return {
    line: stringJoin([
      `${config.name} = wireguard, section-name=${sectionName}`,
      config.blockQuic && `block-quic=${config.blockQuic}`,
      config.underlyingProxy && `underlying-proxy=${config.underlyingProxy}`,
      config.ipVersion && `ip-version=${surgeIpVersion.encode(config.ipVersion)}`,
      config.testUrl && `test-url=${config.testUrl}`
    ], ', '),
    section: stringJoin([
      `[WireGuard ${sectionName}]`,
      `private-key = ${config.privateKey}`,
      config.selfIp && `self-ip = ${config.selfIp}`,
      config.selfIpV6 && `self-ip-v6 = ${config.selfIpV6}`,
      config.preferIpv6 != null && `prefer-ipv6 = ${config.preferIpv6}`,
      config.dnsServers?.length ? `dns-server = ${config.dnsServers.join(', ')}` : undefined,
      config.mtu && `mtu = ${config.mtu}`,
      ...config.peers.map((peer) => `peer = (${stringJoin([
        `public-key = ${peer.publicKey}`,
        // Surge requires quotes once the value contains a comma
        `allowed-ips = ${peer.allowedIps.length > 1 ? `"${peer.allowedIps.join(', ')}"` : peer.allowedIps[0]}`,
        `endpoint = ${endpoint(peer)}`,
        peer.presharedKey && `preshared-key = ${peer.presharedKey}`,
        peer.keepalive && `keepalive = ${peer.keepalive}`,
        peer.reserved != null && `client-id = ${reservedBytes(peer.reserved)!.join('/')}`
      ], ', ')})`)
    ], '\n')
  };
}

function clashPeer(peer: WireGuardPeer) {
  return withoutUndefined({
    server: peer.server,
    port: peer.port,
    'public-key': peer.publicKey,
    'allowed-ips': peer.allowedIps,
    'pre-shared-key': peer.presharedKey,
    reserved: reservedBytes(peer.reserved)
  });
}

/** Mihomo */
export function clash(config: WireGuardConfig) {
  assertValid(config);
  const [primary] = config.peers;

  // In the single-peer form Mihomo ignores allowed-ips and installs the default
  // routes implied by ip / ipv6, so anything narrower has to use the peers form.
  const impliedAllowedIps: string[] = [];
  if (config.selfIp) {
    impliedAllowedIps.push('0.0.0.0/0');
  }
  if (config.selfIpV6) {
    impliedAllowedIps.push('::/0');
  }
  const useSimplifiedForm = config.peers.length === 1
    && primary.allowedIps.length === impliedAllowedIps.length
    && impliedAllowedIps.every((ip) => primary.allowedIps.includes(ip));

  return withoutUndefined({
    name: config.name,
    type: 'wireguard',
    'private-key': config.privateKey,
    ip: config.selfIp,
    ipv6: config.selfIpV6,
    mtu: config.mtu,
    udp: true,
    'dialer-proxy': config.underlyingProxy,
    'ip-version': mihomoIpVersion.encode(config.ipVersion),
    'remote-dns-resolve': config.dnsServers?.length ? true : undefined,
    dns: config.dnsServers?.length ? config.dnsServers : undefined,
    // Mihomo has no per-peer keepalive
    'persistent-keepalive': primary.keepalive,
    ...(useSimplifiedForm ? clashPeer(primary) : { peers: config.peers.map(clashPeer) })
  });
}

export function stash(config: WireGuardConfig) {
  assertValid(config);
  if (config.peers.length > 1) {
    throw new TypeError(`[wireguard] Stash supports a single WireGuard peer, "${config.name}" has ${config.peers.length}`);
  }
  const [peer] = config.peers;

  return withoutUndefined({
    name: config.name,
    type: 'wireguard',
    server: peer.server,
    port: peer.port,
    ip: config.selfIp,
    ipv6: config.selfIpV6,
    'private-key': config.privateKey,
    'public-key': peer.publicKey,
    'preshared-key': peer.presharedKey,
    dns: config.dnsServers?.length ? config.dnsServers : undefined,
    mtu: config.mtu,
    reserved: reservedBytes(peer.reserved),
    keepalive: peer.keepalive,
    'dialer-proxy': config.underlyingProxy,
    'benchmark-url': config.testUrl
  });
}
