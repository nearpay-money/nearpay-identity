/**
 * Console (ops) authenticator policy (lld/identity.md §6.1, §11, spec `opsPasskeyRegistrationVerify`).
 * Pure. Operator passkeys must be hardware security keys:
 *
 * - the attestation statement verified (WebAuthn library) and is not `none`;
 * - the AAGUID is on `NP_OPS_AAGUID_ALLOWLIST` (an empty list refuses everything — fail closed);
 * - the credential is device-bound (a synced / multi-device passkey is refused);
 * - on the server stage the attestation is a full attestation (`x5c` chain) and trust anchors are
 *   configured, so the chain is checked against vendor roots: without anchors an AAGUID is only
 *   self-asserted by the authenticator (anyone can build a software key claiming a YubiKey AAGUID).
 */

import { isDevEnv } from "../env.js";

export const FULL_ATTESTATION_FORMATS: readonly string[] = ["packed", "fido-u2f", "tpm"];

export interface AuthenticatorFacts {
  readonly env: string;
  readonly fmt: string;
  /** The attestation statement carries a certificate chain (full attestation). */
  readonly hasX5c: boolean;
  readonly aaguid: string;
  /** `credentialDeviceType === "multiDevice"` or the backup-eligible flag: a synced passkey. */
  readonly synced: boolean;
  readonly allowlist: ReadonlySet<string>;
  readonly rootsConfigured: boolean;
}

/** Why the authenticator is refused (`authenticator_not_allowed`), or null when it is accepted. */
export function authenticatorProblem(f: AuthenticatorFacts): string | null {
  if (f.fmt === "none") return "the key gave no attestation";
  if (f.synced) return "synced passkeys are not accepted";
  if (f.allowlist.size === 0) return "no hardware keys are allow-listed";
  if (!f.allowlist.has(f.aaguid.toLowerCase())) return "this key model is not allow-listed";
  const strict = !isDevEnv(f.env);
  if (strict && !(FULL_ATTESTATION_FORMATS.includes(f.fmt) && f.hasX5c)) return "the key gave no full attestation";
  if (strict && !f.rootsConfigured) return "no attestation trust anchors are configured";
  return null;
}
