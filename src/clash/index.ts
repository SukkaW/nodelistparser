import { never } from 'foxts/guard';
import type { SupportedConfig } from '../types';

export function decode(config: Record<string, any>): SupportedConfig {
  if (!('type' in config) || typeof config.type !== 'string') {
    throw new TypeError('Missing or invalid type field');
  }

  const raw = JSON.stringify(config);
  switch (config.type) {
    case 'http':
      return {
        type: 'http',
        name: config.name,
        server: config.server,
        port: Number(config.port),
        username: config.username,
        password: config.password,
        underlyingProxy: config['dialer-proxy'],
        raw
      };
    case 'ss':
      return {
        type: 'ss',
        name: config.name,
        server: config.server,
        port: Number(config.port),
        cipher: config.cipher,
        password: config.password,
        // TODO: Surge uses udp-port but Mihomo doesn't have, so we have no choice but to disable UDP for Shadow TLS
        udp: config.udp || false,
        obfs: config.plugin === 'obfs' ? config['plugin-opts'].mode : undefined,
        underlyingProxy: config['dialer-proxy'],
        shadowTlsSni: config.plugin === 'shadow-tls' ? config['plugin-opts'].host : undefined,
        shadowTlsPassword: config.plugin === 'shadow-tls' ? config['plugin-opts'].password : undefined,
        shadowTlsVersion: config.plugin === 'shadow-tls' ? config['plugin-opts'].version : undefined,
        raw
      };
    case 'socks5':
      return {
        type: 'socks5',
        name: config.name,
        server: config.server,
        port: Number(config.port),
        username: config.username,
        password: config.password,
        udp: config.udp || false,
        underlyingProxy: config['dialer-proxy'],
        raw
      };
    case 'trojan':
      return {
        type: 'trojan',
        name: config.name,
        server: config.server,
        port: Number(config.port),
        password: config.password,
        sni: config.sni,
        skipCertVerify: config['skip-cert-verify'] || false,
        udp: config.udp || false,
        underlyingProxy: config['dialer-proxy'],
        raw
      };
    case 'vmess':
      return {
        type: 'vmess',
        name: config.name,
        server: config.server,
        port: Number(config.port),
        username: config.uuid,
        vmessAead: config.alterId === 1 || config.alterId === '1',
        sni: config.servername,
        ws: config.network === 'ws',
        wsPath: config['ws-path'],
        wsHeaders: config['ws-headers']
          ? Object.entries(config['ws-headers'])
            .map(([key, value]) => `${key}:${value as string}`)
            .join(', ')
          : undefined,
        tls: config.tls || false,
        udp: config.udp ?? true,
        underlyingProxy: config['dialer-proxy'],
        raw,
        skipCertVerify: config['skip-cert-verify'] || false
      };
    default:
      throw new TypeError(`Unsupported type: ${config.type} (clash decode)`);
  }
}

export function encode(config: SupportedConfig) {
  const shared = {
    name: config.name,
    server: config.server,
    port: config.port,

    tfo: config.tfo,
    'dialer-proxy': config.underlyingProxy
  };

  switch (config.type) {
    case 'ss':
      if (config.shadowTlsPassword && (config.udp || config.udpPort)) {
        throw new Error('Clash doesn\'t support plain UDP for Shadow TLS (clash encode)');
      }

      return {
        type: 'ss',
        cipher: config.cipher,
        password: config.password,
        udp: config.udp,
        ...(config.obfs
          ? {
            plugin: 'obfs',
            'plugin-opts': {
              mode: config.obfs,
              host: config.obfsHost,
              uri: config.obfsUri
            }
          }
          : {}
        ),
        ...(config.shadowTlsPassword
          ? {
            plugin: 'shadow-tls',
            'plugin-opts': {
              host: config.shadowTlsSni,
              password: config.shadowTlsPassword,
              version: config.shadowTlsVersion
            }
          }
          : {}
        ),
        ...shared
      };
    case 'trojan':
      return {
        type: 'trojan',
        password: config.password,
        sni: config.sni,
        'skip-cert-verify': config.skipCertVerify,
        udp: config.udp,
        ...shared
      };
    case 'tuic':
    case 'tuic-v5':
      return {
        type: 'tuic',
        sni: config.sni,
        uuid: config.uuid,
        alpn: config.alpn.split(',').map((x) => x.trim()),
        ...(
          config.type === 'tuic'
            ? { token: config.token }
            : { password: config.password }
        ),
        'skip-cert-verify': config.skipCertVerify,
        udp: true,
        version: config.type === 'tuic'
          ? 4
          : (
            // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition -- exhause check
            config.type === 'tuic-v5'
              ? 5
              : never(config)
          ),
        ...shared
      };
    case 'socks5':
      return {
        type: 'socks5',
        username: config.username,
        password: config.password,
        udp: config.udp,
        ...shared
      };
    case 'http':
      return {
        type: 'http',
        username: config.username,
        password: config.password,
        ...shared
      };
    case 'vmess':
      return {
        alterId: config.vmessAead ? 0 : undefined,
        tls: config.tls,
        udp: config.udp,
        uuid: config.username,
        servername: config.sni,
        'ws-path': config.wsPath,
        'ws-headers': config.wsHeaders
          ? parseStringToObject(config.wsHeaders)
          : undefined,
        cipher: 'auto',
        'ws-opts': {
          path: config.wsPath,
          headers: config.wsHeaders
            ? parseStringToObject(config.wsHeaders)
            : undefined
        },
        type: 'vmess',
        network: config.ws ? 'ws' : 'tcp',
        ...shared
      };
    case 'hysteria2':
      return {
        type: 'hysteria2',
        ports: config.portHopping,
        password: config.password,
        down: config.downloadBandwidth + ' Mbps',
        'skip-cert-verify': config.skipCertVerify,
        ...shared
      };
    default:
      throw new TypeError(`Unsupported type: ${config.type} (clash encode)`);
  }
}

function parseStringToObject(input: string): Record<string, string> {
  return input.split(',').reduce<Record<string, string>>((acc, pair) => {
    const [key, value] = pair.split(':');
    acc[key.trim()] = value.trim();
    return acc;
  }, {});
}
