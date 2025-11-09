import type { ShadowSocksConfig } from '../types';
import * as atom from '../utils/atom';

export function decodeOne(sip002: string): ShadowSocksConfig {
  // ss://YWVzLTEyOC1nY206YzMxNWFhOGMtNGU1NC00MGRjLWJkYzctYzFjMjEwZjIxYTNi@ss1.meslink.xyz:10009#%F0%9F%87%AD%F0%9F%87%B0%20HK1%20HKT
  const [type, payload] = sip002.split('://');

  if (type !== 'ss') {
    throw new Error(`[ss.decodeOne] Unsupported type: ${type}`);
  }

  const [userInfo, server] = payload.split('@');

  let cipher, password;
  if (userInfo.includes(':')) {
    [cipher, ...password] = userInfo.split(':', 3);
  } else {
    [cipher, ...password] = atob(userInfo).split(':', 3);
  }
  password = password.join(':'); // in case password contains ':'

  const [serverName, _1] = server.split(':');
  const [_2, encodedName] = _1.split('#');
  const [port, pluginsStr] = _2.split('/');

  let plugin: string | null = null;
  if (pluginsStr) {
    try {
      plugin = new URLSearchParams(pluginsStr).get('plugin');
    } catch (e) {
      const err = new Error(`[ss.decodeOne] Invalid plugins: ${pluginsStr}`);
      err.cause = e;
      throw err;
    }
  }
  const pluginArgs = (plugin?.split(';') ?? []).reduce<Record<string, string>>((acc, cur) => {
    const [key, value] = cur.split('=');
    acc[key] = value;
    return acc;
  }, {});

  return {
    raw: sip002,
    type: 'ss',
    name: decodeURIComponent(encodedName),
    server: serverName,
    port: atom.number(port),
    cipher,
    password,
    udp: true,
    obfs: 'obfs-local' in pluginArgs && 'obfs' in pluginArgs && (pluginArgs.obfs === 'http' || pluginArgs.obfs === 'tls')
      ? pluginArgs.obfs
      : undefined,
    obfsHost: 'obfs-host' in pluginArgs ? pluginArgs['obfs-host'] : undefined
  } satisfies ShadowSocksConfig;
}

export function decodeBase64Multiline(text: string): string[] {
  return atob(text).replaceAll('\r\n', '\n').split('\n').filter(Boolean);
}

export function decodeMultiline(text: string): ShadowSocksConfig[] {
  return decodeBase64Multiline(text).map((line) => decodeOne(line));
}
