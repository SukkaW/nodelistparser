import * as atom from '../utils/atom';
import type { HttpProxyConfig, Hysteria2Config, ShadowSocksConfig, SharedConfigBase, SnellConfig, Socks5Config, SupportedConfig, TrojanConfig, TuicConfig, VmessConfig } from '../types';

type ProxyBoolKeys =
  | 'udp-relay'
  | 'tfo'
  | 'reuse'
  | 'skip-cert-verify'
  | 'tls'
  | 'vmess-aead'
  | 'ws';
const boolKeys = new Set<ProxyBoolKeys>([
  'udp-relay',
  'tfo',
  'reuse',
  'skip-cert-verify',
  'tls',
  'vmess-aead',
  'ws'
]);
const isProxyBoolKey = (key: string): key is ProxyBoolKeys => boolKeys.has(key as ProxyBoolKeys);
type ProxyNumKeys =
  | 'version'
  | 'download-bandwidth'
  | 'port-hopping-interval';
const numKeys = new Set<ProxyNumKeys>([
  'version',
  'download-bandwidth',
  'port-hopping-interval'
]);
const isProxyNumKey = (key: string): key is ProxyNumKeys => numKeys.has(key as ProxyNumKeys);
type ProxyArrKeys = never;
const arrKeys = new Set([]);
const isProxyArrKey = (key: string): key is ProxyArrKeys => arrKeys.has(key as ProxyArrKeys);
type ProxyStrKeys =
  | 'username'
  | 'password'
  | 'sni'
  | 'encrypt-method'
  | 'psk'
  | 'obfs'
  | 'obfs-host'
  | 'uuid'
  | 'alpn'
  | 'block-quic'
  | 'ws-path'
  | 'ws-headers'
  | 'port-hopping';
const strKeys = new Set<ProxyStrKeys>([
  'username',
  'password',
  'sni',
  'encrypt-method',
  'psk',
  'obfs',
  'obfs-host',
  'uuid',
  'alpn',
  'block-quic',
  'ws-path',
  'ws-headers',
  'port-hopping'
]);
const isProxyStrKey = (key: string): key is ProxyStrKeys => strKeys.has(key as ProxyStrKeys);

const UNSUPPORTED_VALUE = Symbol('unsupported');

export function decode(raw: string): SupportedConfig {
  const parsePart = (part: string) => {
    const [key, value] = atom.assign(part);
    if (isProxyBoolKey(key)) {
      return [key, atom.boolean(value)];
    }
    if (isProxyNumKey(key)) {
      return [key, atom.number(value)];
    }
    if (isProxyArrKey(key)) {
      return [key, atom.comma(value)];
    }
    if (isProxyStrKey(key)) {
      if (
        (value[0] === '"' && value.endsWith('"'))
        || (value[0] === '\'' && value.endsWith('\''))
      ) {
        return [key, value.slice(1, -1)];
      }
      return [key, value];
    }
    return [key, UNSUPPORTED_VALUE];
  };

  const [name, parts] = atom.assign(raw);
  const [type, server, mayPort, ...rest] = atom.comma(parts);

  const port = atom.number(mayPort);

  const restDetails = Object.fromEntries(rest.map(parsePart));

  const shared: SharedConfigBase = {
    raw,
    name,
    server,
    port,
    tfo: restDetails.tfo,
    blockQuic: restDetails['block-quic']
  };

  switch (type) {
    case 'snell': {
      return {
        type: 'snell',
        psk: restDetails.psk,
        version: restDetails.version,
        reuse: restDetails.reuse,
        ...shared
      } satisfies SnellConfig;
    }
    case 'ss': {
      return {
        type: 'ss',
        cipher: restDetails['encrypt-method'],
        password: restDetails.password,
        udp: restDetails['udp-relay'],
        obfs: restDetails.obfs,
        obfsHost: restDetails['obfs-host'],
        obfsUri: restDetails['obfs-uri'],
        ...shared
      } satisfies ShadowSocksConfig;
    }
    case 'trojan': {
      return {
        type: 'trojan',
        password: restDetails.password,
        sni: restDetails.sni,
        skipCertVerify: restDetails['skip-cert-verify'],
        udp: restDetails['udp-relay'],
        ...shared
      } satisfies TrojanConfig;
    }
    case 'tuic': {
      return {
        type: 'tuic',
        sni: restDetails.sni,
        uuid: restDetails.uuid,
        alpn: restDetails.alpn,
        password: restDetails.password,
        version: restDetails.version,
        ...shared
      } satisfies TuicConfig;
    }
    case 'socks5': {
      return {
        type: 'socks5',
        username: rest[0],
        password: rest[1],
        udp: restDetails['udp-relay'],
        ...shared
      } satisfies Socks5Config;
    }
    case 'http': {
      return {
        type: 'http',
        username: rest[0],
        password: rest[1],
        ...shared
      } satisfies HttpProxyConfig;
    }
    case 'vmess': {
      return {
        type: 'vmess',
        username: restDetails.username,
        tls: restDetails.tls,
        vmessAead: restDetails['vmess-aead'],
        ws: restDetails.ws,
        wsPath: restDetails['ws-path'],
        wsHeaders: restDetails['ws-headers'],
        skipCertVerify: restDetails['skip-cert-verify'],
        udp: restDetails['udp-relay'],
        sni: restDetails.sni,
        ...shared
      } satisfies VmessConfig;
    }
    case 'hysteria2':
      return {
        type: 'hysteria2',
        password: restDetails.password,
        skipCertVerify: restDetails['skip-cert-verify'],
        downloadBandwidth: restDetails['download-bandwidth'],
        portHopping: restDetails['port-hopping'],
        portHoppingInterval: restDetails['port-hopping-interval'],
        ...shared
      } satisfies Hysteria2Config;
    default:
      throw new TypeError(`Unsupported type: ${type} (surge decode)`);
  }

  // console.log({
  //   name, type, server, port, restDetails
  // });
}

function assertNever(value: never, msg: string): never {
  throw new TypeError(`Unsupported type: ${msg}`);
}

const joinString = (arr: Array<string | 0 | null | false | undefined>) => arr.filter(Boolean).join(', ');

export function encode(config: SupportedConfig): string {
  const shared = [
    config.tfo && 'tfo=true',
    config.blockQuic && `block-quic=${config.blockQuic}`
  ];

  switch (config.type) {
    case 'snell':
      return joinString([
        `${config.name} = snell, ${config.server}, ${config.port}, psk=${config.psk}, version=${config.version}, reuse=${config.reuse}`,
        ...shared
      ]);
    case 'ss':
      return joinString([
        `${config.name} = ss, ${config.server}, ${config.port}, encrypt-method=${config.cipher}, password=${config.password}`,
        config.udp && 'udp-relay=true',
        config.obfs && `obfs=${config.obfs}`,
        config.obfsHost && `obfs-host=${config.obfsHost}`,
        config.obfsUri && `obfs-uri=${config.obfsUri}`,
        ...shared
      ]);
    case 'trojan':
      return joinString([
        `${config.name} = trojan, ${config.server}, ${config.port}, password=${config.password}`,
        config.sni && `sni=${config.sni}`,
        config.skipCertVerify && 'skip-cert-verify=true',
        ...shared,
        config.udp && 'udp-relay=true'
      ]);
    case 'tuic':
      return joinString([
        `${config.name} = tuic, ${config.server}, ${config.port}, sni=${config.sni}, uuid=${config.uuid}, alpn=${config.alpn}, password=${config.password}, version=${config.version}`,
        ...shared
      ]);
    case 'socks5':
      return joinString([
        `${config.name} = socks5, ${config.server}, ${config.port}, ${config.username}, ${config.password}`,
        config.udp && 'udp-relay=true',
        ...shared
      ]);
    case 'http':
      return joinString([
        `${config.name} = http, ${config.server}, ${config.port}, ${config.username}, ${config.password}`,
        // no udp support for http
        ...shared
      ]);
    case 'vmess':
      return joinString([
        `${config.name} = vmess, ${config.server}, ${config.port}`,
        `username=${config.username}`,
        `tls=${config.tls}`,
        `vmess-aead=${config.vmessAead}`,
        'ws=true',
        config.wsPath && `ws-path=${
          (config.wsPath[0] === '/' ? config.wsPath : `/${config.wsPath}`)
        }`,
        config.wsHeaders && `ws-headers=${config.wsHeaders}`,
        `skip-cert-verify=${config.skipCertVerify}`,
        `tfo=${config.tfo}`,
        `udp-relay=${config.udp}`
      ]);
    case 'hysteria2':
      return joinString([
        `${config.name} = hysteria2, ${config.server}, ${config.port}`,
        `password=${config.password}`,
        `download-bandwidth=${config.downloadBandwidth}`,
        config.portHopping && `port-hopping="${config.portHopping}"`,
        config.portHoppingInterval && `port-hopping-interval=${config.portHoppingInterval}`,
        `skip-cert-verify=${config.skipCertVerify}`,
        ...shared
      ]);
    default:
      assertNever(config, `Unsupported type: ${(config as any).type} (clash encode)`);
  }
}
