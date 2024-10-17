import type { ShadowSocksConfig } from '../types';
import * as atom from '../utils/atom';

export function decodeOne(sip002: string) {
  // ss://YWVzLTEyOC1nY206YzMxNWFhOGMtNGU1NC00MGRjLWJkYzctYzFjMjEwZjIxYTNi@ss1.meslink.xyz:10009#%F0%9F%87%AD%F0%9F%87%B0%20HK1%20HKT
  const [_type, payload] = sip002.split('://');

  const [userInfo, server] = payload.split('@');

  let cipher, password;
  if (userInfo.includes(':')) {
    [cipher, password] = userInfo.split(':');
  } else {
    [cipher, password] = atob(userInfo).split(':');
  }

  const [serverName, _1] = server.split(':');
  const [_2, encodedName] = _1.split('#');
  const [port, _plugins] = _2.split('/');

  // TODO: implement plugin parsing

  return {
    raw: sip002,
    type: 'ss',
    name: decodeURIComponent(encodedName),
    server: serverName,
    port: atom.number(port),
    cipher,
    password,
    udp: true
  } satisfies ShadowSocksConfig;
}

export function decodeMultiline(text: string): ShadowSocksConfig[] {
  const lines = atob(text).replaceAll('\r\n', '\n').split('\n');
  return lines.filter(Boolean).map((line) => decodeOne(line));
}
