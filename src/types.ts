export type IpVersion = 'dual' | 'ipv4-only' | 'ipv6-only' | 'ipv4-prefer' | 'ipv6-prefer';

export interface SharedConfigBase {
  raw?: string | undefined | null,
  name: string,
  server: string,
  port: number,
  /** tfo */
  tfo?: boolean,
  /** block-quic */
  blockQuic?: string,
  /** underlying-proxy */
  underlyingProxy?: string,
  /** ip-version (Surge, Mihomo) */
  ipVersion?: IpVersion,
  /** test-url (Surge) / benchmark-url (Stash) */
  testUrl?: string
}

export interface TlsSharedConfig {
  /** sni */
  sni: string | undefined,
  /** skip-cert-verify */
  skipCertVerify: boolean
}

export interface HttpProxyConfig extends SharedConfigBase {
  type: 'http',
  username: string,
  password: string
}

export interface ShadowTlsSharedExtension {

  /** Shadow TLS Version */
  shadowTlsVersion?: 1 | 2 | 3,
  /** Shadow TLS Password */
  shadowTlsPassword?: string,
  /** Shadow TLS SNI */
  shadowTlsSni?: string | undefined
}

export interface ShadowSocksConfig extends SharedConfigBase, ShadowTlsSharedExtension {
  type: 'ss',
  /** encrypt-method */
  cipher: string,
  password: string,
  /** udp-relay */
  udp: boolean,
  obfs?: undefined | 'http' | 'tls',
  /** obfs-host */
  obfsHost?: string,
  /** obfs-uri */
  obfsUri?: string,
  /** udp-port */
  udpPort?: number
}

export interface TrojanConfig extends SharedConfigBase, TlsSharedConfig {
  type: 'trojan',
  password: string,
  /** udp-relay */
  udp: boolean,
  /** ws */
  ws?: boolean | undefined,
  /** ws-path */
  wsPath?: string | undefined,
  /** ws-headers */
  wsHeaders?: string | undefined
}

export interface SnellConfig extends SharedConfigBase, ShadowTlsSharedExtension {
  type: 'snell',
  psk: string,
  version: number,
  // TODO: share re-use w/ anytls
  reuse: boolean
}

export interface AnyTLSConfig extends SharedConfigBase, TlsSharedConfig {
  type: 'anytls',
  password: string,
  /** udp-relay */
  udp: boolean,
  // TODO: share re-use w/ snell
  reuse?: boolean
}

export interface TrojanBasicConfig extends SharedConfigBase, TlsSharedConfig {
  type: 'trojan',
  password: string,
  /** udp-relay */
  udp: boolean
}

export interface TuicConfig extends SharedConfigBase, TlsSharedConfig {
  type: 'tuic',
  uuid: string,
  alpn: string,
  token: string
}

export interface TuicV5Config extends SharedConfigBase, TlsSharedConfig {
  type: 'tuic-v5',
  uuid: string,
  alpn: string,
  password: string
}

export interface Socks5Config extends SharedConfigBase {
  type: 'socks5',
  udp: boolean,
  username: string,
  password: string
}

export interface VmessConfig extends SharedConfigBase, TlsSharedConfig {
  type: 'vmess',
  /** uuid */
  username: string,
  tls: boolean,
  /** encrypt-method: chacha20-ietf-poly1305, aes-128-gcm */
  encryptMethod?: string | undefined,
  vmessAead: boolean | undefined,
  ws: boolean | undefined,
  wsPath: string | undefined,
  wsHeaders: string | undefined,
  udp: boolean
}

export interface Hysteria2Config extends SharedConfigBase, Omit<TlsSharedConfig, 'sni'> {
  type: 'hysteria2',
  password: string,
  /** download-bandwidth in mbps */
  downloadBandwidth: number,
  /** port hopping */
  portHopping?: string,
  /** port hopping interval */
  portHoppingInterval?: number
}

export interface WireGuardPeer {
  /** endpoint host: IPv4, IPv6 literal (no brackets), or domain */
  server: string,
  /** endpoint UDP port */
  port: number,
  /** public-key, base64 */
  publicKey: string,
  /** allowed-ips, at least one CIDR */
  allowedIps: string[],
  /** preshared-key (Surge, Stash) / pre-shared-key (Mihomo) */
  presharedKey?: string,
  /** keepalive (Surge, Stash) / persistent-keepalive (Mihomo), seconds */
  keepalive?: number,
  /**
   * client-id (Surge) / reserved (Mihomo, Stash), WARP routing bytes.
   * A string is accepted in every form Surge takes (`83/12/235`, 3-byte hex
   * with or without `0x`, 4-char base64) and is normalised to the bytes on output.
   */
  reserved?: [number, number, number] | string
}

/**
 * Not part of `SupportedConfig`: WireGuard is generated through the
 * `wireguard` namespace, never through `surge.encode` / `clash.encode`.
 */
export interface WireGuardConfig extends Omit<SharedConfigBase, 'server' | 'port'> {
  type: 'wireguard',
  /** [WireGuard <section-name>]; falls back to `name` */
  sectionName?: string,
  /** private-key, base64 */
  privateKey: string,
  /** self-ip / ip; at least one of selfIp / selfIpV6 */
  selfIp?: string,
  /** self-ip-v6 / ipv6 */
  selfIpV6?: string,
  /** prefer-ipv6 (Surge only) */
  preferIpv6?: boolean,
  /** dns-server / dns */
  dnsServers?: string[],
  mtu?: number,
  /** non-empty */
  peers: WireGuardPeer[]
}

export type SupportedConfig =
  | HttpProxyConfig
  | SnellConfig
  | TrojanConfig
  | ShadowSocksConfig
  | TuicConfig
  | TuicV5Config
  | Socks5Config
  | VmessConfig
  | Hysteria2Config
  | AnyTLSConfig;
