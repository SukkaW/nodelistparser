import { describe, it } from 'mocha';
import { decodeOne } from '.';
import { expect } from 'expect';
import type { ShadowSocksConfig } from '../types';

describe('ss', () => {
  describe('decodeSingle', () => {
    it('sip002', () => {
      const raw = 'ss://cmM0LW1kNTpwYXNzd2Q@example.com:8888/?plugin=obfs-local%3Bobfs%3Dhttp#Example2';
      expect(decodeOne(raw)).toMatchObject({
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
      expect(decodeOne(fixture)).toMatchObject({
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
  });
});
