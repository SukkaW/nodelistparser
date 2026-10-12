import type { IpVersion } from '../types';

function createIpVersionCodec(table: Record<IpVersion, string>) {
  const ipVersions = Object.keys(table) as IpVersion[];

  return {
    encode(ipVersion: IpVersion | undefined): string | undefined {
      return ipVersion && table[ipVersion];
    },
    decode(value: unknown): IpVersion | undefined {
      if (typeof value !== 'string') {
        return undefined;
      }
      const lowered = value.toLowerCase();
      return ipVersions.find((ipVersion) => table[ipVersion] === lowered);
    }
  };
}

export const surgeIpVersion = createIpVersionCodec({
  dual: 'dual',
  'ipv4-only': 'v4-only',
  'ipv6-only': 'v6-only',
  'ipv4-prefer': 'prefer-v4',
  'ipv6-prefer': 'prefer-v6'
});

export const mihomoIpVersion = createIpVersionCodec({
  dual: 'dual',
  'ipv4-only': 'ipv4',
  'ipv6-only': 'ipv6',
  'ipv4-prefer': 'ipv4-prefer',
  'ipv6-prefer': 'ipv6-prefer'
});
