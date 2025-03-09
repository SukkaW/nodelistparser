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
        udp: true
      } satisfies ShadowSocksConfig);
    });
  });
});
