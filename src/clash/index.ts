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
        udp: config.udp || false,
        obfs: config.plugin === 'obfs' ? config['plugin-opts'].mode : undefined,
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
        raw,
        skipCertVerify: config['skip-cert-verify'] || false
      };
    default:
      throw new TypeError(`Unsupported type: ${config.type} (clash decode)`);
  }
}

export function encode(config: SupportedConfig) {
  const shared = {
    tfo: config.tfo
  };

  switch (config.type) {
    case 'ss':
      return {
        name: config.name,
        type: 'ss',
        server: config.server,
        port: config.port,
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
        ...shared
      };
    case 'trojan':
      return {
        name: config.name,
        type: 'trojan',
        server: config.server,
        port: config.port,
        password: config.password,
        sni: config.sni,
        'skip-cert-verify': config.skipCertVerify,
        udp: config.udp,
        ...shared
      };
    case 'tuic':
    case 'tuic-v5':
      return {
        name: config.name,
        type: 'tuic',
        server: config.server,
        port: config.port,
        sni: config.sni,
        uuid: config.uuid,
        alpn: config.alpn.split(',').map((x) => x.trim()),
        ...(
          config.type === 'tuic'
            ? { token: config.token }
            : { password: config.password }
        ),
        udp: true,
        ...shared
      };
    case 'socks5':
      return {
        name: config.name,
        type: 'socks5',
        server: config.server,
        port: config.port,
        username: config.username,
        password: config.password,
        udp: config.udp,
        ...shared
      };
    case 'http':
      return {
        name: config.name,
        type: 'http',
        server: config.server,
        port: config.port,
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
        name: config.name,
        servername: config.sni,
        'ws-path': config.wsPath,
        server: config.server,
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
        port: config.port,
        network: config.ws ? 'ws' : 'tcp'
      };
    case 'hysteria2':
      return {
        name: config.name,
        type: 'hysteria2',
        server: config.server,
        port: config.port,
        ports: config.portHopping,
        password: config.password,
        down: config.downloadBandwidth + ' Mbps',
        'skip-cert-verify': config.skipCertVerify
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
