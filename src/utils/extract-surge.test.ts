import { describe, it } from 'mocha';
import { expect } from 'earl';
import { extractSurgeProfileSection, extractSurgeProfileProxies } from './extract-surge';

const fixture = `[Rule]
# Proxy
PROCESS-NAME,v2ray,DIRECT
GEOIP,CN,DIRECT
FINAL,Final

[Proxy]
DIRECT = direct
AdBlock = reject-tinygif
Cellular = cellular
# comment inside section
; another comment
// yet another comment
Traffic: 13.85 GB | 1000 GB = trojan, example.com, 149, password=114514, sni=example.org, skip-cert-verify=true, tfo=false
🇭🇰 香港-01 = trojan, example.com, 149, password=114514, sni=example.org, skip-cert-verify=true, tfo=false
🇯🇵 日本-01 = ss, example.com, 149, encrypt-method=chacha20-ietf-poly1305, password=114514
Unsupported = wireguard, section-name=jp

[Proxy Group]
Proxies = select,🇭🇰 香港-01,🇯🇵 日本-01
`;

describe('extract-surge', () => {
  it('extractSurgeSection', () => {
    expect(extractSurgeProfileSection(fixture, 'Proxy')).toHaveLength(7);
    expect(extractSurgeProfileSection(fixture, 'Rule')).toEqual([
      'PROCESS-NAME,v2ray,DIRECT',
      'GEOIP,CN,DIRECT',
      'FINAL,Final'
    ]);
    expect(extractSurgeProfileSection(fixture, 'Proxy Group')).toHaveLength(1);
    expect(extractSurgeProfileSection(fixture, 'General')).toHaveLength(0);
  });

  it('extractSurgeProxies', () => {
    const proxies = extractSurgeProfileProxies(fixture);

    expect(proxies).toHaveLength(3);
    expect(proxies.map((proxy) => proxy.name)).toEqual([
      'Traffic: 13.85 GB | 1000 GB',
      '🇭🇰 香港-01',
      '🇯🇵 日本-01'
    ]);
    expect(proxies[1]).toEqual(expect.subset({
      type: 'trojan',
      server: 'example.com',
      port: 149,
      sni: 'example.org',
      skipCertVerify: true
    }));
    expect(proxies[2].type).toEqual('ss');
  });

  it('extractSurgeProxies w/ skipUnsupported=false', () => {
    expect(() => extractSurgeProfileProxies(fixture, false)).toThrow(TypeError);
  });
});
