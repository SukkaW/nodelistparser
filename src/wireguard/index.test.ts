import { describe, it } from 'mocha';
import { expect } from 'earl';
import { surge, clash, stash } from '.';
import type { WireGuardConfig } from '../types';

const warp: WireGuardConfig = {
  type: 'wireguard',
  name: 'WARP',
  privateKey: 'cHJpdmF0ZS1rZXk=',
  selfIp: '172.16.0.2',
  selfIpV6: '2606:4700:110::2',
  dnsServers: ['1.1.1.1', '2606:4700:4700::1111'],
  mtu: 1280,
  blockQuic: 'off',
  underlyingProxy: 'Relay Example',
  ipVersion: 'ipv4-only',
  testUrl: 'https://cdn.jsdelivr.net/npm/latency-test@1.0.1-surge/generate_200',
  peers: [{
    server: 'engage.cloudflareclient.com',
    port: 2408,
    publicKey: 'cHVibGljLWtleQ==',
    allowedIps: ['0.0.0.0/0', '::/0'],
    presharedKey: 'cHJlc2hhcmVkLWtleQ==',
    keepalive: 25,
    reserved: [11, 45, 14]
  }]
};

const twoPeers: WireGuardConfig = {
  type: 'wireguard',
  name: 'WG',
  sectionName: 'Here Goes The WireGuard Section Name',
  privateKey: 'cHJpdmF0ZS1rZXk=',
  selfIp: '10.20.0.2',
  preferIpv6: false,
  peers: [
    { server: 'a.example.com', port: 51820, publicKey: 'cHVibGljLWtleQ==', allowedIps: ['10.10.0.0/16'] },
    { server: '2001:db8::10', port: 51820, publicKey: 'cGVlci1i', allowedIps: ['10.20.0.0/16'], keepalive: 25 }
  ]
};

describe('wireguard', () => {
  it('surge', () => {
    expect(surge(warp)).toEqual({
      line: 'WARP = wireguard, section-name=WARP, block-quic=off, underlying-proxy=Relay Example, ip-version=v4-only, test-url=https://cdn.jsdelivr.net/npm/latency-test@1.0.1-surge/generate_200',
      section: [
        '[WireGuard WARP]',
        'private-key = cHJpdmF0ZS1rZXk=',
        'self-ip = 172.16.0.2',
        'self-ip-v6 = 2606:4700:110::2',
        'dns-server = 1.1.1.1, 2606:4700:4700::1111',
        'mtu = 1280',
        'peer = (public-key = cHVibGljLWtleQ==, allowed-ips = "0.0.0.0/0, ::/0", endpoint = engage.cloudflareclient.com:2408, preshared-key = cHJlc2hhcmVkLWtleQ==, keepalive = 25, client-id = 11/45/14)'
      ].join('\n')
    });
  });

  it('surge w/ section name, multiple peers, ipv6 endpoint', () => {
    expect(surge(twoPeers)).toEqual({
      line: 'WG = wireguard, section-name=Here Goes The WireGuard Section Name',
      section: [
        '[WireGuard Here Goes The WireGuard Section Name]',
        'private-key = cHJpdmF0ZS1rZXk=',
        'self-ip = 10.20.0.2',
        'prefer-ipv6 = false',
        'peer = (public-key = cHVibGljLWtleQ==, allowed-ips = 10.10.0.0/16, endpoint = a.example.com:51820)',
        'peer = (public-key = cGVlci1i, allowed-ips = 10.20.0.0/16, endpoint = [2001:db8::10]:51820, keepalive = 25)'
      ].join('\n')
    });
  });

  it('clash (mihomo) simplified form', () => {
    expect(clash(warp)).toEqual({
      name: 'WARP',
      type: 'wireguard',
      'private-key': 'cHJpdmF0ZS1rZXk=',
      ip: '172.16.0.2',
      ipv6: '2606:4700:110::2',
      mtu: 1280,
      udp: true,
      'dialer-proxy': 'Relay Example',
      'ip-version': 'ipv4',
      'remote-dns-resolve': true,
      dns: ['1.1.1.1', '2606:4700:4700::1111'],
      'persistent-keepalive': 25,
      server: 'engage.cloudflareclient.com',
      port: 2408,
      'public-key': 'cHVibGljLWtleQ==',
      'allowed-ips': ['0.0.0.0/0', '::/0'],
      'pre-shared-key': 'cHJlc2hhcmVkLWtleQ==',
      reserved: [11, 45, 14]
    });
  });

  it('clash (mihomo) peers form for restricted routes', () => {
    expect(clash({ ...warp, peers: [{ ...warp.peers[0], allowedIps: ['10.0.0.0/8'] }] })).toEqual({
      name: 'WARP',
      type: 'wireguard',
      'private-key': 'cHJpdmF0ZS1rZXk=',
      ip: '172.16.0.2',
      ipv6: '2606:4700:110::2',
      mtu: 1280,
      udp: true,
      'dialer-proxy': 'Relay Example',
      'ip-version': 'ipv4',
      'remote-dns-resolve': true,
      dns: ['1.1.1.1', '2606:4700:4700::1111'],
      'persistent-keepalive': 25,
      peers: [{
        server: 'engage.cloudflareclient.com',
        port: 2408,
        'public-key': 'cHVibGljLWtleQ==',
        'allowed-ips': ['10.0.0.0/8'],
        'pre-shared-key': 'cHJlc2hhcmVkLWtleQ==',
        reserved: [11, 45, 14]
      }]
    });
  });

  it('clash (mihomo) peers form for multiple peers', () => {
    expect(clash(twoPeers)).toEqual({
      name: 'WG',
      type: 'wireguard',
      'private-key': 'cHJpdmF0ZS1rZXk=',
      ip: '10.20.0.2',
      udp: true,
      peers: [
        { server: 'a.example.com', port: 51820, 'public-key': 'cHVibGljLWtleQ==', 'allowed-ips': ['10.10.0.0/16'] },
        { server: '2001:db8::10', port: 51820, 'public-key': 'cGVlci1i', 'allowed-ips': ['10.20.0.0/16'] }
      ]
    });
  });

  it('clash (mihomo) w/o dns', () => {
    const out = clash({ ...warp, dnsServers: undefined });
    expect('dns' in out).toEqual(false);
    expect('remote-dns-resolve' in out).toEqual(false);
  });

  it('stash', () => {
    expect(stash(warp)).toEqual({
      name: 'WARP',
      type: 'wireguard',
      server: 'engage.cloudflareclient.com',
      port: 2408,
      ip: '172.16.0.2',
      ipv6: '2606:4700:110::2',
      'private-key': 'cHJpdmF0ZS1rZXk=',
      'public-key': 'cHVibGljLWtleQ==',
      'preshared-key': 'cHJlc2hhcmVkLWtleQ==',
      dns: ['1.1.1.1', '2606:4700:4700::1111'],
      mtu: 1280,
      reserved: [11, 45, 14],
      keepalive: 25,
      'dialer-proxy': 'Relay Example',
      'benchmark-url': 'https://cdn.jsdelivr.net/npm/latency-test@1.0.1-surge/generate_200'
    });

    expect(() => stash(twoPeers)).toThrow(TypeError);
  });

  it('reserved / client-id string forms', () => {
    const forms = ['0B2D0E', '0x0b2d0e', 'Cy0O', '11/45/14'];
    for (let i = 0, len = forms.length; i < len; i++) {
      const config: WireGuardConfig = { ...warp, peers: [{ ...warp.peers[0], reserved: forms[i] }] };
      expect(surge(config).section).toInclude('client-id = 11/45/14');
      expect(clash(config)).toHaveSubset({ reserved: [11, 45, 14] });
      expect(stash(config)).toHaveSubset({ reserved: [11, 45, 14] });
    }

    expect(() => surge({ ...warp, peers: [{ ...warp.peers[0], reserved: 'not-a-client-id' }] })).toThrow(TypeError);
    expect(() => clash({ ...warp, peers: [{ ...warp.peers[0], reserved: [0, 0, 256] }] })).toThrow(TypeError);
  });

  it('validation', () => {
    expect(() => surge({ ...warp, privateKey: '' })).toThrow(TypeError);
    expect(() => clash({ ...warp, selfIp: undefined, selfIpV6: undefined })).toThrow(TypeError);
    expect(() => stash({ ...warp, peers: [] })).toThrow(TypeError);
    expect(() => surge({ ...warp, peers: [{ ...warp.peers[0], allowedIps: [] }] })).toThrow(TypeError);
  });
});
