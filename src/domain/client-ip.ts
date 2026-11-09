/**
 * The client's IP address behind the gateway (L-ID-07; beta: Cloudflare → cloudflared → Traefik → service). Pure.
 *
 * Forwarding headers are believed only from a trusted peer: when the TCP peer of this process is not in
 * `NP_TRUSTED_PROXIES` (CIDRs; default loopback + private ranges, where Traefik lives), the request did not come
 * through the gateway and the peer address itself is the client — no header can spoof it.
 *
 * From a trusted peer, `NP_CLIENT_IP_HEADER` picks the source (default by stage):
 * - `cf-connecting-ip` (server stage): Cloudflare overwrites it on every request. Traefik must accept forwarded
 *   headers from cloudflared only and cloudflared must be its only external path (deploy config).
 * - `x-forwarded-for` (local/test): the rightmost hop that is not a trusted proxy — never the leftmost, which the
 *   client writes itself.
 * Anything that is not an IP literal is refused (null).
 */
import { BlockList, isIP } from "node:net";

export type ClientIpHeader = "cf-connecting-ip" | "x-forwarded-for";
export const CLIENT_IP_HEADERS = ["cf-connecting-ip", "x-forwarded-for"] as const;

/** Loopback and private ranges (Docker networks): the default proxies in front of a service. */
export const DEFAULT_TRUSTED_PROXIES: readonly string[] = [
  "127.0.0.0/8",
  "10.0.0.0/8",
  "172.16.0.0/12",
  "192.168.0.0/16",
  "::1/128",
  "fc00::/7",
];

/** A CIDR list as a BlockList (throws on a malformed entry, so a bad NP_TRUSTED_PROXIES fails at boot). */
export function trustedProxies(cidrs: readonly string[]): BlockList {
  const list = new BlockList();
  for (const c of cidrs) {
    const [addr = "", bits] = c.trim().split("/");
    const family = isIP(addr);
    if (!family) throw new Error(`NP_TRUSTED_PROXIES: not an address or CIDR: ${c}`);
    const type = family === 4 ? "ipv4" : "ipv6";
    if (bits === undefined) list.addAddress(addr, type);
    else {
      const prefix = Number(bits);
      if (!Number.isInteger(prefix) || prefix < 0 || prefix > (family === 4 ? 32 : 128))
        throw new Error(`NP_TRUSTED_PROXIES: bad prefix length: ${c}`);
      list.addSubnet(addr, prefix, type);
    }
  }
  return list;
}

const DEFAULT_LIST = trustedProxies(DEFAULT_TRUSTED_PROXIES);

/** `::ffff:a.b.c.d` → `a.b.c.d`; trims; null unless an IP literal. */
export function normalizeIp(v: string | undefined | null): string | null {
  const s = v?.trim();
  if (!s) return null;
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(s)?.[1];
  const ip = mapped ?? s;
  return isIP(ip) ? ip : null;
}

const trusted = (list: BlockList, ip: string) => list.check(ip, isIP(ip) === 4 ? "ipv4" : "ipv6");

export interface ClientIpRule {
  readonly header: ClientIpHeader;
  readonly trusted: BlockList;
}

/** The rule for a stage: `x-forwarded-for` on local/test, `cf-connecting-ip` elsewhere, unless configured. */
export function clientIpRule(
  env: string,
  o: { header?: ClientIpHeader | undefined; trustedProxies?: readonly string[] | undefined } = {},
): ClientIpRule {
  const dev = env === "local" || env === "test";
  return {
    header: o.header ?? (dev ? "x-forwarded-for" : "cf-connecting-ip"),
    trusted: o.trustedProxies ? trustedProxies(o.trustedProxies) : DEFAULT_LIST,
  };
}

/** The request came through a trusted proxy (or the peer is unknown): forwarded headers may be read. */
export function fromTrustedProxy(rule: ClientIpRule, peer: string | undefined): boolean {
  const ip = normalizeIp(peer);
  return !ip || trusted(rule.trusted, ip);
}

export function resolveClientIp(
  rule: ClientIpRule,
  h: { peer?: string | undefined; cfConnectingIp?: string | undefined; xForwardedFor?: string | undefined },
): string | null {
  // a direct client (not through a trusted proxy): its own address, whatever headers it sent
  if (!fromTrustedProxy(rule, h.peer)) return normalizeIp(h.peer);
  if (rule.header === "cf-connecting-ip") return normalizeIp(h.cfConnectingIp);
  const hops = (h.xForwardedFor ?? "")
    .split(",")
    .map((x) => x.trim())
    .filter(Boolean);
  for (let i = hops.length - 1; i >= 0; i--) {
    const hop = normalizeIp(hops[i]);
    if (!hop) return null;
    if (!trusted(rule.trusted, hop)) return hop;
  }
  // every hop is a trusted proxy (a client on the Docker network itself)
  return hops.length ? normalizeIp(hops[0]) : null;
}
