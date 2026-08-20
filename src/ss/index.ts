import type { ShadowSocksConfig } from '../types';
import * as atom from '../utils/atom';

export function decodeOne(sip002: string): ShadowSocksConfig {
  // ss://YWVzLTEyOC1nY206YzMxNWFhOGMtNGU1NC00MGRjLWJkYzctYzFjMjEwZjIxYTNi@ss1.meslink.xyz:10009#%F0%9F%87%AD%F0%9F%87%B0%20HK1%20HKT
  const [type, payload] = atom.splitOnce(sip002, '://');

  if (type !== 'ss') {
    throw new Error(`[ss.decodeOne] Unsupported type: ${type}`);
  }

  const [userInfo, server] = atom.splitOnce(payload, '@');

  // SIP002 allows the userinfo to be either plain `cipher:password` or its
  // base64 form. Split on the first ':' only -- the password itself may
  // contain ':' (e.g. base64-padded 2022-blake3 keys).
  const [cipher, password] = atom.splitOnce(
    userInfo.includes(':') ? userInfo : atob(userInfo),
    ':'
  );

  const [serverName, _1] = atom.splitOnce(server, ':');
  const [_2, encodedName] = atom.splitOnce(_1, '#');
  const [port, pluginsStr] = atom.splitOnce(_2, '/');

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
    const [key, value] = atom.splitOnce(cur, '=');
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
