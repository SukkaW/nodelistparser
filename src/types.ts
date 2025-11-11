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
  underlyingProxy?: string
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

export interface ShadowSocksConfig extends SharedConfigBase {
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
  udpPort?: number,
  /** Shadow TLS Version */
  shadowTlsVersion?: 1 | 2 | 3,
  /** Shadow TLS Password */
  shadowTlsPassword?: string,
  /** Shadow TLS SNI */
  shadowTlsSni?: string | undefined
}

export interface TrojanConfig extends SharedConfigBase, TlsSharedConfig {
  type: 'trojan',
  password: string,
  /** udp-relay */
  udp: boolean,
  /** ws */
  ws: boolean | undefined,
  /** ws-path */
  wsPath: string | undefined,
  /** ws-headers */
  wsHeaders: string | undefined
}

export interface SnellConfig extends SharedConfigBase {
  type: 'snell',
  psk: string,
  version: number,
  reuse: boolean
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

export type SupportedConfig =
  | HttpProxyConfig
  | SnellConfig
  | TrojanConfig
  | ShadowSocksConfig
  | TuicConfig
  | TuicV5Config
  | Socks5Config
  | VmessConfig
  | Hysteria2Config;
