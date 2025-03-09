import { describe, it } from 'mocha';
import { expect } from 'expect';
import { parse } from '.';
import type { TrojanConfig } from '../types';

describe('trojan', () => {
  it('parse', () => {
    const fixture = 'trojan://sukkaw@example.com:22222?security=tls&sni=trojan.burgerip.co.uk&type=tcp&headerType=none#%E7%BE%8E%E5%9B%BD';

    expect<TrojanConfig>(parse(fixture)).toEqual({
      name: '美国',
      password: 'sukkaw',
      port: 22222,
      raw: fixture,
      server: 'example.com',
      skipCertVerify: true,
      sni: 'trojan.burgerip.co.uk',
      type: 'trojan',
      udp: true
    });
  });
});
