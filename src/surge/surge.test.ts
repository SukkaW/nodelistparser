import { describe, it } from 'mocha';
import { expect } from 'expect';
import { decode, encode } from '.';

describe('surge', () => {
  it('snell', () => {
    const fixture = 'Snell = snell, 127.0.0.1, 114514, psk=1145141919810, version=4, reuse=true, tfo=true';

    expect(encode(decode(fixture))).toMatch(fixture);
  });

  it('ss', () => {
    const fixture = 'SS = ss, example.com, 114514, encrypt-method=chacha20-ietf-poly1305, password=1145141919810, udp-relay=true';
    expect(encode(decode(fixture))).toMatch(fixture);

    const fixtureUdpPort = 'SS = ss, example.com, 114514, encrypt-method=chacha20-ietf-poly1305, password=1145141919810, udp-relay=true, udp-port=443';
    expect(encode(decode(fixtureUdpPort))).toMatch(fixtureUdpPort);
  });

  it('ss w/ shadow tls', () => {
    const fixture = 'SS = ss, example.com, 114514, encrypt-method=chacha20-ietf-poly1305, password=114514, shadow-tls-password=1919810, shadow-tls-sni=example.org, shadow-tls-version=3, udp-relay=true, udp-port=1919';
    expect(encode(decode(fixture))).toMatch(fixture);
  });

  it('trojan', () => {
    const fixture = 'Trojan = trojan, example.com, 443, password=1145141919810, sni=example.com, skip-cert-verify=true, tfo=true, udp-relay=true';

    expect(encode(decode(fixture))).toMatch(fixture);
  });

  it('trojan w/ ws', () => {
    const fixture = 'Trojan = trojan, example.com, 443, password=1145141919810, sni=example.com, skip-cert-verify=true, tfo=true, udp-relay=true, ws=true, ws-path=/example/ws-path, ws-headers=Host:"example.org"';

    expect(encode(decode(fixture))).toMatch(fixture);
  });

  it('tuic', () => {
    const fixture = 'TUIC = tuic, example.com, 443, sni=example.org, uuid=114514, alpn=h3, token=1919810, block-quic=off';

    expect(encode(decode(fixture))).toMatch(fixture);
  });

  it('socks5', () => {
    const fixture = 'S5 = socks5, example.com, 443, user, password, udp-relay=true, tfo=true';

    expect(encode(decode(fixture))).toMatch(fixture);
  });

  it('hy2', () => {
    const fixture = 'HY2 = hysteria2, example.com, 8443, password=114514, download-bandwidth=100, port-hopping="4000-9000", port-hopping-interval=30, skip-cert-verify=true';

    expect(encode(decode(fixture))).toMatch(fixture);
  });

  it('tuic-v5', () => {
    const fixture = 'TUIC = tuic-v5, example.com, 443, password=henhenhena114514, uuid=114514, alpn=h3, skip-cert-verify=true, sni=example.org';

    expect(encode(decode(fixture))).toMatch(fixture);
  });

  it('anytls', () => {
    let fixture = 'AnyTLS = anytls, example.com, 443, password=114514, skip-cert-verify=true, sni=example.org, reuse=true';
    expect(encode(decode(fixture))).toMatch(fixture);
    fixture = 'AnyTLS = anytls, example.com, 443, password=114514, skip-cert-verify=false, sni=example.org, reuse=false';
    expect(encode(decode(fixture))).toMatch(fixture);
  });

  it('underlying-proxy', () => {
    const fixture = 'SS = ss, example.com, 114514, encrypt-method=chacha20-ietf-poly1305, password=1145141919810, udp-relay=true, underlying-proxy=relay 114514';
    expect(encode(decode(fixture))).toMatch(fixture);
  });
});
