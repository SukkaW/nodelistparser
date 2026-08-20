import { describe, it } from 'mocha';
import { decodeOne } from '.';
import { expect } from 'earl';
import type { ShadowSocksConfig } from '../types';

describe('ss', () => {
  describe('decodeSingle', () => {
    it('sip002', () => {
      const raw = 'ss://cmM0LW1kNTpwYXNzd2Q@example.com:8888/?plugin=obfs-local%3Bobfs%3Dhttp#Example2';
      expect(decodeOne(raw)).toHaveSubset({
        raw,
        type: 'ss',
        name: 'Example2',
        server: 'example.com',
        port: 8888,
        password: 'passwd',
        cipher: 'rc4-md5',
        obfs: 'http',
        udp: true
      } satisfies ShadowSocksConfig);
    });

    it('sip002 passwd contains :', () => {
      const fixture = 'ss://MjAyMi1ibGFrZTMtYWVzLTEyOC1nY206MTE0NTE0PT06MTkxOTgxMD09@example.com:8888/?plugin=obfs-local%3Bobfs%3Dhttp#Example2';
      expect(decodeOne(fixture)).toHaveSubset({
        raw: fixture,
        type: 'ss',
        name: 'Example2',
        server: 'example.com',
        port: 8888,
        password: '114514==:1919810==',
        cipher: '2022-blake3-aes-128-gcm',
        obfs: 'http',
        udp: true
      } satisfies ShadowSocksConfig);
    });

    it('sip002 passwd contains multiple :', () => {
      const fixture = 'ss://MjAyMi1ibGFrZTMtYWVzLTEyOC1nY206YTpiOmM6ZA@example.com:8888/?plugin=obfs-local%3Bobfs%3Dhttp#Example2';
      expect(decodeOne(fixture)).toHaveSubset({
        raw: fixture,
        type: 'ss',
        name: 'Example2',
        server: 'example.com',
        port: 8888,
        password: 'a:b:c:d',
        cipher: '2022-blake3-aes-128-gcm',
        obfs: 'http',
        udp: true
      } satisfies ShadowSocksConfig);
    });

    it('sip002 passwd contains multiple : and base64 padding', () => {
      const fixture = 'ss://MjAyMi1ibGFrZTMtYWVzLTEyOC1nY206cDE9PTpwMj09OnAzPT0=@example.com:8888#Example3';
      expect(decodeOne(fixture)).toHaveSubset({
        raw: fixture,
        type: 'ss',
        name: 'Example3',
        server: 'example.com',
        port: 8888,
        password: 'p1==:p2==:p3==',
        cipher: '2022-blake3-aes-128-gcm',
        udp: true
      } satisfies ShadowSocksConfig);
    });

    it('sip002 plain (non-base64) userinfo w/ passwd containing :', () => {
      const fixture = 'ss://rc4-md5:pa:ss:wd@example.com:8888#Plain';
      expect(decodeOne(fixture)).toHaveSubset({
        raw: fixture,
        type: 'ss',
        name: 'Plain',
        server: 'example.com',
        port: 8888,
        password: 'pa:ss:wd',
        cipher: 'rc4-md5',
        udp: true
      } satisfies ShadowSocksConfig);
    });
  });
});
