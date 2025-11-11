import { describe, it } from 'mocha';
import { expect } from 'expect';
import { decode as surgeDecode } from '../surge';
import { encode } from '.';

describe('clash', () => {
  it('socks', () => {
    const fixture = 'S5 = socks5, example.com, 443, user, password, udp-relay=true, tfo=true';

    expect(encode(surgeDecode(fixture))).toMatchObject({
      name: 'S5',
      type: 'socks5',
      server: 'example.com',
      port: 443,
      username: 'user',
      password: 'password',
      udp: true,
      tfo: true
    });
  });

  it('ss', () => {
    const fixture = 'SS = ss, example.com, 114514, encrypt-method=chacha20-ietf-poly1305, password=1145141919810, udp-relay=true';

    expect(encode(surgeDecode(fixture))).toMatchObject({
      name: 'SS',
      type: 'ss',
      server: 'example.com',
      port: 114514,
      cipher: 'chacha20-ietf-poly1305',
      password: '1145141919810',
      udp: true
    });

    const fixtureUdpPort = 'SS = ss, example.com, 114514, encrypt-method=chacha20-ietf-poly1305, password=1145141919810, udp-relay=true, udp-port=443';
    expect(encode(surgeDecode(fixtureUdpPort))).toMatchObject({
      name: 'SS',
      type: 'ss',
      server: 'example.com',
      port: 114514,
      cipher: 'chacha20-ietf-poly1305',
      password: '1145141919810',
      udp: true
    });
  });

  it('ss w/ shadow-tls plugin', () => {
    const fixture = 'SS = ss, example.com, 114514, encrypt-method=chacha20-ietf-poly1305, password=114514, shadow-tls-password=1919810, shadow-tls-sni=example.org, shadow-tls-version=3, udp-relay=false';
    expect(encode(surgeDecode(fixture))).toMatchObject({
      name: 'SS',
      type: 'ss',
      server: 'example.com',
      port: 114514,
      cipher: 'chacha20-ietf-poly1305',
      password: '114514',
      udp: false,
      plugin: 'shadow-tls',
      'plugin-opts': {
        host: 'example.org',
        password: '1919810',
        version: 3
      }
    });
  });

  it('trojan', () => {
    const fixture = 'Trojan = trojan, example.com, 443, password=1145141919810, sni=example.com, skip-cert-verify=true, tfo=true, udp-relay=true';

    expect(encode(surgeDecode(fixture))).toMatchObject({
      name: 'Trojan',
      password: '1145141919810',
      port: 443,
      server: 'example.com',
      'skip-cert-verify': true,
      sni: 'example.com',
      type: 'trojan',
      udp: true
    });
  });

  it('trojan w/ ws', () => {
    const fixture = 'Trojan = trojan, example.com, 443, password=1145141919810, sni=example.com, skip-cert-verify=true, tfo=true, udp-relay=true, ws=true, ws-path=/example/ws-path, ws-headers=Host:"example.org"';

    console.log(surgeDecode(fixture));

    expect(encode(surgeDecode(fixture))).toMatchObject({
      name: 'Trojan',
      password: '1145141919810',
      port: 443,
      server: 'example.com',
      'skip-cert-verify': true,
      sni: 'example.com',
      type: 'trojan',
      udp: true,
      network: 'ws',
      'ws-opts': {
        path: '/example/ws-path',
        headers: {
          Host: 'example.org'
        }
      }
    });
  });

  it('tuic', () => {
    const fixture = 'TUIC = tuic, example.com, 443, sni=example.org, uuid=114514, alpn=h3, token=1919810, block-quic=off';

    expect(encode(surgeDecode(fixture))).toMatchObject({
      name: 'TUIC',
      type: 'tuic',
      server: 'example.com',
      port: 443,
      sni: 'example.org',
      uuid: '114514',
      alpn: ['h3'],
      token: '1919810'
    });
  });

  it('tuic-v5', () => {
    const fixture = 'TUIC = tuic-v5, example.com, 443, sni=example.org, uuid=114514, alpn=h3, password=1919810, block-quic=off';

    expect(encode(surgeDecode(fixture))).toMatchObject({
      name: 'TUIC',
      type: 'tuic',
      server: 'example.com',
      port: 443,
      sni: 'example.org',
      uuid: '114514',
      alpn: ['h3'],
      password: '1919810'
    });
  });
  it('hysteria2', () => {
    const fixture = 'JP HY2 = hysteria2, example.com, 443, password=114514, download-bandwidth=100, port-hopping="1919-114514", port-hopping-interval=30, skip-cert-verify=true';

    expect(encode(surgeDecode(fixture))).toMatchObject({
      name: 'JP HY2',
      type: 'hysteria2',
      server: 'example.com',
      port: 443,
      ports: '443,1919-114514',
      password: '114514',
      down: '100 Mbps'
    });
  });

  it('dialer-proxy', () => {
    const fixture = 'S5 = socks5, example.com, 443, user, password, udp-relay=true, tfo=true, underlying-proxy=relay 114514';

    expect(encode(surgeDecode(fixture))).toMatchObject({
      name: 'S5',
      type: 'socks5',
      server: 'example.com',
      port: 443,
      username: 'user',
      password: 'password',
      udp: true,
      tfo: true,
      'dialer-proxy': 'relay 114514'
    });
  });
});
