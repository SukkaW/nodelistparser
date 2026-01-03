import { describe, it } from 'mocha';
import { expect } from 'expect';
import { parse } from '.';
import type { VmessConfig } from '../types';

describe('vmess', () => {
  it('parse', () => {
    const fixture = 'vmess://ewogICJ2IjogIjIiLAogICJwcyI6ICJFeGFtcGxlIiwKICAiYWRkIjogInVzMTAtMDguODkwNjA2Lnh5eiIsCiAgInBvcnQiOiAiODAiLAogICJpZCI6ICI1NzZjODFiNi00OTc2LTRmZTMtYjFhOS0wNWE5YzMwMmU5OGUiLAogICJhaWQiOiAiMCIsCiAgInNjeSI6ICJhdXRvIiwKICAibmV0IjogIndzIiwKICAidHlwZSI6ICJub25lIiwKICAiaG9zdCI6ICJ1czEwLTA4Ljg5MDYwNi54eXoiLAogICJwYXRoIjogIi9TTndOZHVudzI4bFZ6dG9wdzkwZW9YZWwiLAogICJ0bHMiOiAiIiwKICAic25pIjogInVzMTAtMDguODkwNjA2Lnh5eiIsCiAgImFscG4iOiAiIgp9';

    expect<VmessConfig>(parse(fixture)).toEqual({
      name: 'Example',
      port: 80,
      raw: fixture,
      server: 'us10-08.890606.xyz',
      skipCertVerify: true,
      sni: 'us10-08.890606.xyz',
      tls: false,
      type: 'vmess',
      udp: true,
      encryptMethod: 'auto',
      username: '576c81b6-4976-4fe3-b1a9-05a9c302e98e',
      vmessAead: true,
      ws: true,
      wsHeaders: 'Host:us10-08.890606.xyz',
      wsPath: '/SNwNdunw28lVztopw90eoXel'
    });
  });

  it('(WIP) vmess - http', () => {
    const fixture = 'vmess://eyJ2IjoiMiIsICJwcyI6IkV4YW1wbGUiLCAiYWRkIjoiZXhhbXBsZS5vcmciLCAicG9ydCI6IjgwIiwgImlkIjoic2trLW1vZSIsICJzY3kiOiJhZXMtMTI4LWdjbSIsICJhaWQiOiIwIiwgIm5ldCI6InRjcCIsICJ0eXBlIjoiaHR0cCIsICJob3N0IjoiZXhhbXBsZS5jb20iLCAicGF0aCI6Ii8iLCAidGxzIjoiIn0=';

    expect<VmessConfig>(parse(fixture)).toEqual({
      name: 'Example',
      port: 80,
      raw: fixture,
      server: 'example.org',
      encryptMethod: 'aes-128-gcm',
      type: 'vmess',
      username: 'skk-moe',
      vmessAead: true,
      ws: false,
      wsHeaders: 'Host:example.com',
      wsPath: '/',
      tls: false,
      skipCertVerify: true,
      udp: true
    });
  });
});
