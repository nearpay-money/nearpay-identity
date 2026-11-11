/**
 * Calls to other services (lld/identity.md §10) with identity's own service token (identity signs
 * it locally: it is the issuer). Compliance screening fails closed; rails minimums degrade to null.
 */

import { HttpError, httpClient } from "@nearpay-internal/http";
import {
  createScreening,
  getDestinationMinimums,
  getInternalAsset,
  getInternalKybCase,
  listChainProfiles,
  sendMessage,
} from "@nearpay-internal/spec";
import type { RouteResponse } from "@nearpay-money/spec";

export type Screening = RouteResponse<typeof createScreening>;
export type Asset = RouteResponse<typeof getInternalAsset>;
export type ChainProfiles = RouteResponse<typeof listChainProfiles>;
export type Minimums = RouteResponse<typeof getDestinationMinimums>;
export type KybCase = RouteResponse<typeof getInternalKybCase>;

export interface Peers {
  screen(input: {
    subject_type: "address" | "near_account" | "destination";
    chain?: string;
    subject: string;
    context: "destination";
    account_id: string;
    livemode: boolean;
  }): Promise<Screening>;
  /** null when rails does not know the asset. */
  asset(assetId: string): Promise<Asset | null>;
  chainProfiles(): Promise<ChainProfiles>;
  minimums(keys: readonly string[]): Promise<Minimums>;
  sendMagicLink(m: {
    to: string;
    link_url: string;
    purpose: "signup" | "recovery" | "invite";
    expires_in_minutes: number;
    dedupe_key: string;
  }): Promise<void>;
  /** Stage 2: notify `team.invitation` (the link carries the single-use token in its fragment). */
  sendInvitation(m: {
    to: string;
    link_url: string;
    account_display_name: string;
    role: "owner" | "admin" | "developer" | "finance" | "support" | "viewer";
    expires_in_minutes: number;
    dedupe_key: string;
  }): Promise<void>;
  /** Stage 2: notify `ops.enrolment` (operator-add). */
  sendOpsEnrolment(m: {
    to: string;
    link_url: string;
    role: "ops" | "ops_admin";
    expires_in_minutes: number;
    dedupe_key: string;
  }): Promise<void>;
  /** Stage 2: the account's KYB case with the self-declared details (compliance `getInternalKybCase`). */
  kybCase(accountId: string): Promise<KybCase>;
}

export function httpPeers(o: {
  complianceUrl: string;
  railsUrl: string;
  notifyUrl: string;
  serviceToken: () => Promise<string>;
  fetch?: typeof fetch;
}): Peers {
  const base = { serviceToken: o.serviceToken, ...(o.fetch ? { fetch: o.fetch } : {}) };
  const compliance = httpClient({
    target: "compliance",
    baseUrl: o.complianceUrl,
    timeoutMs: 2_000,
    attempts: 2,
    ...base,
  });
  const rails = httpClient({ target: "rails", baseUrl: o.railsUrl, timeoutMs: 1_000, attempts: 2, ...base });
  const notify = httpClient({ target: "notify", baseUrl: o.notifyUrl, timeoutMs: 2_000, attempts: 2, ...base });
  return {
    screen: (input) => compliance.call(createScreening, { body: input }),
    async asset(assetId) {
      try {
        return await rails.call(getInternalAsset, { params: { asset_id: assetId } });
      } catch (e) {
        if (e instanceof HttpError && e.status === 404) return null;
        throw e;
      }
    },
    chainProfiles: () => rails.call(listChainProfiles),
    minimums: (keys) => rails.call(getDestinationMinimums, { query: { keys: keys.join(",") } }),
    async sendMagicLink(m) {
      await notify.call(sendMessage, {
        body: {
          template: "auth.magic_link",
          to: m.to,
          variables: { link_url: m.link_url, purpose: m.purpose, expires_in_minutes: m.expires_in_minutes },
          dedupe_key: m.dedupe_key,
        },
      });
    },
    async sendInvitation(m) {
      await notify.call(sendMessage, {
        body: {
          template: "team.invitation",
          to: m.to,
          variables: {
            link_url: m.link_url,
            account_display_name: m.account_display_name,
            role: m.role,
            expires_in_minutes: m.expires_in_minutes,
          },
          dedupe_key: m.dedupe_key,
        },
      });
    },
    async sendOpsEnrolment(m) {
      await notify.call(sendMessage, {
        body: {
          template: "ops.enrolment",
          to: m.to,
          variables: { link_url: m.link_url, role: m.role, expires_in_minutes: m.expires_in_minutes },
          dedupe_key: m.dedupe_key,
        },
      });
    },
    kybCase: (accountId) => compliance.call(getInternalKybCase, { params: { id: accountId as `acct_${string}` } }),
  };
}
