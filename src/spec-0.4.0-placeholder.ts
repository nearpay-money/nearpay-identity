/**
 * PLACEHOLDER — delete in Phase B (step 4.2), when `@nearpay/spec` 0.4.0 is published.
 *
 * The only hand-copied Stage 4 contract pieces in this repo, mirrored exactly from
 * `nearpay-spec` `src/common/chains.ts` and `src/public/identity.ts` on branch `stage-4/4.1-chains`
 * (25ab1af). Replace each import of this file with the spec export named below and delete the file.
 */

/** spec `SOLANA_MAINNET`. */
export const SOLANA_MAINNET = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp" as const;
/** spec `BITCOIN_MAINNET`. */
export const BITCOIN_MAINNET = "bip122:000000000019d6689c085ae165831e93" as const;
/** spec `DESTINATION_SIGNING_STANDARDS`. */
export const DESTINATION_SIGNING_STANDARDS = ["nep413", "eip191", "solana", "bip322"] as const;
/**
 * `attestSettlementDestination.body.standard` of spec 0.4.0 (0.3.1: `nep413 | eip191`). Phase B: use
 * `(typeof DESTINATION_SIGNING_STANDARDS)[number]` from the spec (or the route's body type).
 */
export type AttestStandard = (typeof DESTINATION_SIGNING_STANDARDS)[number];
