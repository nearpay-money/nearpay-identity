/**
 * Chain RPC for attestations (lld/identity.md §8.2, §10): NEAR `view_access_key` at final block over
 * a provider pool (2 s each), EVM `eth_call` ERC-1271 on the destination's chain when configured.
 */
import { AttestationUnavailable, type OwnershipLookups } from "../crypto/attestation.js";

const MAGIC_1271 = "0x1626ba7e";

async function jsonRpc(f: typeof fetch, urls: readonly string[], method: string, params: unknown, timeoutMs: number) {
  const errors: string[] = [];
  for (const url of urls) {
    try {
      const res = await f(url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
        signal: AbortSignal.timeout(timeoutMs),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return (await res.json()) as {
        result?: unknown;
        error?: { name?: string; cause?: { name?: string }; message?: string };
      };
    } catch (e) {
      errors.push(`${new URL(url).host}: ${(e as Error).message}`);
    }
  }
  throw new AttestationUnavailable(`all RPC providers failed for ${method} (${errors.join("; ")})`);
}

export function chainLookups(o: {
  nearRpcUrls: readonly string[];
  evmRpcUrls: Readonly<Record<string, readonly string[]>>;
  timeoutMs?: number;
  fetch?: typeof fetch;
}): OwnershipLookups {
  const f = o.fetch ?? fetch;
  const timeout = o.timeoutMs ?? 2_000;
  return {
    async nearAccessKey(accountId, publicKey) {
      const r = await jsonRpc(
        f,
        o.nearRpcUrls,
        "query",
        { request_type: "view_access_key", finality: "final", account_id: accountId, public_key: publicKey },
        timeout,
      );
      if (r.error) {
        const name = r.error.cause?.name ?? r.error.name ?? "";
        const text = JSON.stringify(r.error);
        if (/UNKNOWN_ACCESS_KEY|UNKNOWN_ACCOUNT|does not exist/.test(`${name} ${text}`)) return null;
        throw new AttestationUnavailable(`NEAR RPC error: ${text.slice(0, 200)}`);
      }
      // older nodes report a missing key as a result with an `error` string
      const res = r.result as { permission?: unknown; error?: string } | undefined;
      if (!res || res.error) return null;
      return res.permission === "FullAccess" ? "FullAccess" : "FunctionCall";
    },
    async erc1271(chain, address, hash, signature) {
      const urls = o.evmRpcUrls[chain.slice("eip155:".length)];
      if (!urls?.length) return null;
      const sig = Buffer.from(signature).toString("hex");
      const padded = sig.padEnd(Math.ceil(sig.length / 64) * 64, "0");
      const data = `${MAGIC_1271}${Buffer.from(hash).toString("hex")}${(64).toString(16).padStart(64, "0")}${signature.length
        .toString(16)
        .padStart(64, "0")}${padded}`;
      const r = await jsonRpc(f, urls, "eth_call", [{ to: address, data }, "latest"], timeout);
      if (r.error) return false;
      return typeof r.result === "string" && r.result.toLowerCase().startsWith(MAGIC_1271);
    },
  };
}
