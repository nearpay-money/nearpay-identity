/**
 * Settlement destination lifecycle (lld/identity.md §5, FR-SET-01…04). Pure.
 *
 * | from                 | command            | guard                                    | to                              |
 * |----------------------|--------------------|------------------------------------------|---------------------------------|
 * | —                    | create (test mode) | screening allow                          | active (verification `test`)    |
 * | —                    | create (live)      | screening allow, unique, no recovery lock | pending_verification            |
 * | pending_verification | challenge          | earlier unused challenges superseded     | pending_verification (fresh challenge) |
 * | pending_verification | attest             | signature valid, challenge fresh         | cooling_off (1 approver, Stage 1) / pending_approval (2) |
 * | pending_approval     | approve            | distinct approvers ≥ required            | cooling_off                     |
 * | cooling_off          | activate (job)     | not disabled, re-screen allow            | active                          |
 * | any but disabled     | disable / blocked  | —                                        | disabled                        |
 */

export type DestinationStatus = "pending_verification" | "pending_approval" | "cooling_off" | "active" | "disabled";
export type Command = "challenge" | "attest" | "approve" | "activate" | "disable" | "set_default";

export type Step =
  | { readonly ok: true; readonly to: DestinationStatus }
  | { readonly ok: false; readonly state: DestinationStatus };

/** Where `command` moves a destination in `from` (approvals: how many are required after the attestation). */
export function transition(from: DestinationStatus, command: Command, o: { approvalsRequired?: number } = {}): Step {
  switch (command) {
    case "challenge":
      return from === "pending_verification" ? { ok: true, to: from } : { ok: false, state: from };
    case "attest":
      return from === "pending_verification"
        ? { ok: true, to: (o.approvalsRequired ?? 1) > 1 ? "pending_approval" : "cooling_off" }
        : { ok: false, state: from };
    case "approve":
      return from === "pending_approval" ? { ok: true, to: "cooling_off" } : { ok: false, state: from };
    case "activate":
      return from === "cooling_off" ? { ok: true, to: "active" } : { ok: false, state: from };
    case "disable":
      return from === "disabled" ? { ok: false, state: from } : { ok: true, to: "disabled" };
    case "set_default":
      return from === "active" ? { ok: true, to: "active" } : { ok: false, state: from };
  }
}

/**
 * Approvals needed (lld/identity.md §5): 2 when the account has ≥ 2 owner/admin members, else 1
 * (the creator). Stage 1 ships the single-approver flow (two approvers arrive with members in Stage 2).
 */
export function approvalsRequired(ownerAdminMembers: number, twoApproverRule: boolean): number {
  return twoApproverRule && ownerAdminMembers >= 2 ? 2 : 1;
}

/** Live mode (lld/identity.md §5): KYB approved, an active live destination, account active. */
export function liveEnabled(a: { kyb_status: string; status: string }, hasActiveLiveDestination: boolean): boolean {
  return a.kyb_status === "approved" && hasActiveLiveDestination && a.status === "active";
}

/** What is missing before live mode (`GET /v1/account/requirements`). */
export function missingRequirements(
  a: { kyb_status: string; status: string },
  hasActiveLiveDestination: boolean,
): ("kyb" | "destination" | "account_status")[] {
  return [
    ...(a.kyb_status === "approved" ? [] : (["kyb"] as const)),
    ...(hasActiveLiveDestination ? [] : (["destination"] as const)),
    ...(a.status === "active" ? [] : (["account_status"] as const)),
  ];
}

export type SigningStandard = "nep413" | "eip191" | "solana" | "bip322";

/**
 * How a destination proves ownership (lld/identity.md §8.2): NEAR accounts (named or implicit) sign
 * NEP-413; EVM addresses and `0x…` Intents accounts sign EIP-191. Solana and Bitcoin arrive in Stage 4.
 */
export function signingStandard(
  type: "chain_address" | "intents_account",
  family: string,
  addressNorm: string,
): SigningStandard {
  if (/^0x[0-9a-f]{40}$/.test(addressNorm)) return "eip191";
  if (type === "intents_account" || family === "near") return "nep413";
  if (family === "evm") return "eip191";
  if (family === "solana") return "solana";
  return "bip322";
}

/** Standards Stage 1 can verify (the attest route accepts these). */
export const STAGE1_STANDARDS: readonly SigningStandard[] = ["nep413", "eip191"];

export const CHALLENGE_TTL_MS = 10 * 60_000;
export const NEP413_RECIPIENT = "nearpay.money";

/** The exact message a destination key signs (lld/identity.md §8.2). */
export function attestationMessage(m: {
  account: string;
  livemode: boolean;
  assetId: string;
  chain: string;
  address: string;
  nonceHex: string;
  expiresAt: Date;
}): string {
  return [
    "NearPay settlement destination",
    `Account: ${m.account}`,
    `Mode: ${m.livemode ? "live" : "test"}`,
    `Asset: ${m.assetId}`,
    `Network: ${m.chain}`,
    `Address: ${m.address}`,
    `Nonce: ${m.nonceHex}`,
    `Expires: ${m.expiresAt.toISOString()}`,
  ].join("\n");
}

/** USD micros → `UsdAmount` minor units (cents, rounded up: a minimum must not be understated). */
export function usdMicrosToCents(micros: number): number {
  return Math.ceil(micros / 10_000);
}
