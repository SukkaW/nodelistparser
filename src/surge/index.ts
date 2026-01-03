import * as atom from '../utils/atom';
import type { HttpProxyConfig, Hysteria2Config, ShadowSocksConfig, SharedConfigBase, SnellConfig, Socks5Config, SupportedConfig, TrojanConfig, TuicConfig, TuicV5Config, VmessConfig, TlsSharedConfig, AnyTLSConfig } from '../types';
import { never } from 'foxts/guard';
import { stringJoin } from 'foxts/string-join';

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
  | 'port-hopping-interval'
  | 'udp-port'
  | 'shadow-tls-version';
const numKeys = new Set<ProxyNumKeys>([
  'version',
  'download-bandwidth',
  'port-hopping-interval',
  'udp-port',
  'shadow-tls-version'
]);
const isProxyNumKey = (key: string): key is ProxyNumKeys => numKeys.has(key as ProxyNumKeys);
type ProxyArrKeys = never;
const arrKeys = new Set();
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
  | 'port-hopping'
  | 'token'
  | 'underlying-proxy'
  | 'shadow-tls-password'
  | 'shadow-tls-sni';
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
  'port-hopping',
  'token',
  'underlying-proxy',
  'shadow-tls-password',
  'shadow-tls-sni'
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
    blockQuic: restDetails['block-quic'],
    underlyingProxy: restDetails['underlying-proxy']
  };

  const tlsShared: TlsSharedConfig = {
    sni: restDetails.sni,
    skipCertVerify: restDetails['skip-cert-verify']
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
      const shadowTlsPassword = restDetails['shadow-tls-password'];
      const shadowTlsSni = restDetails['shadow-tls-sni'];
      const shadowTlsVersion = restDetails['shadow-tls-version'];

      return {
        type: 'ss',
        cipher: restDetails['encrypt-method'],
        password: restDetails.password,
        udp: restDetails['udp-relay'],
        obfs: restDetails.obfs,
        obfsHost: restDetails['obfs-host'],
        obfsUri: restDetails['obfs-uri'],
        udpPort: restDetails['udp-port'],
        shadowTlsPassword,
        shadowTlsSni,
        shadowTlsVersion,
        ...shared
      } satisfies ShadowSocksConfig;
    }
    case 'trojan': {
      return {
        type: 'trojan',
        password: restDetails.password,
        udp: restDetails['udp-relay'],
        ws: restDetails.ws,
        wsPath: restDetails['ws-path'],
        wsHeaders: restDetails['ws-headers'],
        ...tlsShared,
        ...shared
      } satisfies TrojanConfig;
    }
    case 'tuic': {
      return {
        type: 'tuic',
        uuid: restDetails.uuid,
        alpn: restDetails.alpn,
        token: restDetails.token,
        ...tlsShared,
        ...shared
      } satisfies TuicConfig;
    }
    case 'tuic-v5': {
      return {
        type: 'tuic-v5',
        uuid: restDetails.uuid,
        alpn: restDetails.alpn,
        password: restDetails.password,
        ...tlsShared,
        ...shared
      } satisfies TuicV5Config;
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
        udp: restDetails['udp-relay'],
        ...tlsShared,
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
    case 'anytls':
      return {
        type: 'anytls',
        password: restDetails.password,
        reuse: restDetails.reuse,
        udp: restDetails['udp-relay'],
        ...tlsShared,
        ...shared
      } satisfies AnyTLSConfig;
    default:
      throw new TypeError(`Unsupported type: ${type} (surge decode)`);
  }

  // console.log({
  //   name, type, server, port, restDetails
  // });
}

export function encode(config: SupportedConfig): string {
  const shared = [
    config.tfo && 'tfo=true',
    config.blockQuic && `block-quic=${config.blockQuic}`,
    config.underlyingProxy && `underlying-proxy=${config.underlyingProxy}`
  ];

  switch (config.type) {
    case 'snell':
      return stringJoin([
        `${config.name} = snell, ${config.server}, ${config.port}, psk=${config.psk}, version=${config.version}, reuse=${config.reuse}`,
        ...shared
      ], ', ');
    case 'ss':
      return stringJoin([
        `${config.name} = ss, ${config.server}, ${config.port}, encrypt-method=${config.cipher}, password=${config.password}`,
        config.shadowTlsPassword && `shadow-tls-password=${config.shadowTlsPassword}`,
        config.shadowTlsSni && `shadow-tls-sni=${config.shadowTlsSni}`,
        config.shadowTlsVersion && `shadow-tls-version=${config.shadowTlsVersion}`,
        config.udp && 'udp-relay=true',
        config.udpPort && `udp-port=${config.udpPort}`,
        config.obfs && `obfs=${config.obfs}`,
        config.obfsHost && `obfs-host=${config.obfsHost}`,
        config.obfsUri && `obfs-uri=${config.obfsUri}`,
        ...shared
      ], ', ');
    case 'trojan':
      return stringJoin([
        `${config.name} = trojan, ${config.server}, ${config.port}, password=${config.password}`,
        config.sni && `sni=${config.sni}`,
        config.skipCertVerify && 'skip-cert-verify=true',
        ...shared,
        config.udp && 'udp-relay=true',
        config.ws && 'ws=true',
        config.wsPath && `ws-path=${
          (config.wsPath[0] === '/' ? config.wsPath : `/${config.wsPath}`)
        }`,
        config.wsHeaders && `ws-headers=${config.wsHeaders}`
      ], ', ');
    case 'tuic':
      return stringJoin([
        `${config.name} = tuic, ${config.server}, ${config.port}, sni=${config.sni}, uuid=${config.uuid}, alpn=${config.alpn}, token=${config.token}`,
        ...shared
      ], ', ');
    case 'socks5':
      return stringJoin([
        `${config.name} = socks5, ${config.server}, ${config.port}, ${config.username}, ${config.password}`,
        config.udp && 'udp-relay=true',
        ...shared
      ], ', ');
    case 'http':
      return stringJoin([
        `${config.name} = http, ${config.server}, ${config.port}, ${config.username}, ${config.password}`,
        // no udp support for http
        ...shared
      ], ', ');
    case 'vmess':
      return stringJoin([
        `${config.name} = vmess, ${config.server}, ${config.port}`,
        `username=${config.username}`,
        `tls=${config.tls}`,
        `vmess-aead=${config.vmessAead}`,
        config.ws && 'ws=true',
        // undefined means auto, but surge requires this field to be omitted when using auto
        config.encryptMethod && `encrypt-method=${config.encryptMethod}`,
        config.wsPath && `ws-path=${
          (config.wsPath[0] === '/' ? config.wsPath : `/${config.wsPath}`)
        }`,
        config.wsHeaders && `ws-headers=${config.wsHeaders}`,
        `skip-cert-verify=${config.skipCertVerify}`,
        `udp-relay=${config.udp}`,
        ...shared
      ], ', ');
    case 'hysteria2':
      return stringJoin([
        `${config.name} = hysteria2, ${config.server}, ${config.port}`,
        `password=${config.password}`,
        `download-bandwidth=${config.downloadBandwidth}`,
        config.portHopping && `port-hopping="${config.portHopping}"`,
        config.portHoppingInterval && `port-hopping-interval=${config.portHoppingInterval}`,
        `skip-cert-verify=${config.skipCertVerify}`,
        ...shared
      ], ', ');
    case 'tuic-v5':
      return stringJoin([
        `${config.name} = tuic-v5, ${config.server}, ${config.port}`,
        `password=${config.password}`,
        `uuid=${config.uuid}`,
        `alpn=${config.alpn}`,
        `skip-cert-verify=${config.skipCertVerify}`,
        `sni=${config.sni}`,
        ...shared
      ], ', ');
    case 'anytls':
      return stringJoin([
        `${config.name} = anytls, ${config.server}, ${config.port}, password=${config.password}`,
        `skip-cert-verify=${config.skipCertVerify}`,
        config.sni && `sni=${config.sni}`,
        `reuse=${config.reuse}`,
        ...shared
      ], ', ');
    default:
      never(config, 'config.type (surge encode)');
  }
}
