/** Stage 2 domain rules (lld/identity.md §5, §6, §6.1, §11): approvals, team, console keys, scopes, sessions. */
import { KEY_SCOPES } from "@nearpay/spec";
import { describe, expect, it } from "vitest";
import { consoleConfig, parseAaguids, parsePemBundle } from "../../src/config.js";
import { checkScopes, expandScopes, restrictedAllows } from "../../src/domain/api-key/key.js";
import { afterAttestation, approvedBy, decide, isComplete, rejectedBy } from "../../src/domain/approval/approval.js";
import { isConsoleHost, isConsolePath } from "../../src/domain/authz/authz.js";
import { authenticatorProblem } from "../../src/domain/console/console.js";
import { idleExpiresAt, LIFETIME, OPS_IDLE_MS, sessionState } from "../../src/domain/session/session.js";
import {
  acceptProblem,
  canChangeRole,
  canInvite,
  canRemove,
  effectiveStatus,
  isOwnerOrAdmin,
} from "../../src/domain/team/team.js";

describe("two-approver rule", () => {
  const pending = {
    status: "pending_approval",
    required: 2,
    createdBy: "a",
    approvals: [{ userId: "a", decision: "approve" as const }],
  };
  it("a second, different owner/admin completes it", () => {
    expect(decide(pending, "b", "approve")).toEqual({
      ok: true,
      record: { userId: "b", decision: "approve" },
      to: "cooling_off",
    });
  });
  it("the creator cannot approve their own destination", () => {
    expect(decide(pending, "a", "approve")).toMatchObject({ ok: false, error: "approver_conflict" });
    expect(decide(pending, "a", "reject")).toMatchObject({ ok: false, error: "approver_conflict" });
  });
  it("an earlier approver cannot decide again", () => {
    const s = { ...pending, createdBy: "z", approvals: [...pending.approvals] };
    expect(decide(s, "a", "approve")).toMatchObject({ ok: false, error: "approver_conflict" });
  });
  it("a rejection disables", () => {
    expect(decide(pending, "b", "reject")).toMatchObject({ ok: true, to: "disabled" });
  });
  it("only pending_approval destinations take decisions", () => {
    for (const status of ["pending_verification", "cooling_off", "active", "disabled"])
      expect(decide({ ...pending, status }, "b", "approve")).toMatchObject({ ok: false, error: "state_conflict" });
  });
  it("three required (never configured) needs a third user", () => {
    expect(decide({ ...pending, required: 3 }, "b", "approve")).toMatchObject({ ok: true, to: "pending_approval" });
  });
  it("completion counts distinct approvers and no rejection", () => {
    expect(isComplete(1, [{ userId: "a", decision: "approve" }])).toBe(true);
    expect(
      isComplete(2, [
        { userId: "a", decision: "approve" },
        { userId: "a", decision: "approve" },
      ]),
    ).toBe(false);
    expect(
      isComplete(1, [
        { userId: "a", decision: "approve" },
        { userId: "b", decision: "reject" },
      ]),
    ).toBe(false);
    expect(isComplete(0, [])).toBe(false);
    expect(afterAttestation(2, pending.approvals)).toBe("pending_approval");
    expect(afterAttestation(1, pending.approvals)).toBe("cooling_off");
    expect(
      approvedBy([
        { userId: "a", decision: "approve" },
        { userId: "b", decision: "reject" },
      ]),
    ).toEqual(["a"]);
    expect(rejectedBy([{ userId: "b", decision: "reject" }])).toBe("b");
    expect(rejectedBy([])).toBeNull();
  });
});

describe("team rules", () => {
  it("owners and admins invite; only owners invite owners", () => {
    expect(canInvite("owner", "owner").ok).toBe(true);
    expect(canInvite("admin", "developer").ok).toBe(true);
    expect(canInvite("admin", "owner")).toMatchObject({ ok: false, error: "permission_denied" });
    expect(canInvite("developer", "viewer")).toMatchObject({ ok: false, error: "permission_denied" });
  });
  it("only owners grant or take away owner; the last owner stays", () => {
    expect(canChangeRole("admin", "developer", "admin", 1).ok).toBe(true);
    expect(canChangeRole("admin", "developer", "owner", 1)).toMatchObject({ error: "permission_denied" });
    expect(canChangeRole("admin", "owner", "admin", 2)).toMatchObject({ error: "permission_denied" });
    expect(canChangeRole("owner", "owner", "admin", 1)).toMatchObject({ error: "last_owner" });
    expect(canChangeRole("owner", "owner", "admin", 2).ok).toBe(true);
    expect(canChangeRole("owner", "owner", "owner", 1).ok).toBe(true);
    expect(canChangeRole("viewer", "viewer", "admin", 1)).toMatchObject({ error: "permission_denied" });
  });
  it("only owners remove owners; never the last one", () => {
    expect(canRemove("admin", "developer", 1).ok).toBe(true);
    expect(canRemove("admin", "owner", 2)).toMatchObject({ error: "permission_denied" });
    expect(canRemove("owner", "owner", 1)).toMatchObject({ error: "last_owner" });
    expect(canRemove("owner", "owner", 2).ok).toBe(true);
    expect(canRemove("finance", "viewer", 1)).toMatchObject({ error: "permission_denied" });
  });
  it("invitations expire after their date and accept only the invited email", () => {
    const now = Date.UTC(2026, 10, 7);
    const inv = { status: "pending" as const, expires_at: new Date(now + 1000), email: "Team@Shop.test" };
    expect(effectiveStatus(inv, now)).toBe("pending");
    expect(effectiveStatus(inv, now + 1000)).toBe("expired");
    expect(effectiveStatus({ ...inv, status: "revoked" }, now)).toBe("revoked");
    expect(acceptProblem(inv, "team@shop.test", now)).toBeNull();
    expect(acceptProblem(inv, "other@shop.test", now)).toMatch(/another email/);
    expect(acceptProblem({ ...inv, status: "accepted" }, "team@shop.test", now)).toMatch(/accepted/);
    expect(isOwnerOrAdmin("admin")).toBe(true);
    expect(isOwnerOrAdmin("developer")).toBe(false);
  });
});

describe("console authenticator policy", () => {
  const base = {
    env: "server",
    fmt: "packed",
    hasX5c: true,
    aaguid: "CB69481E-8FF7-4039-93EC-0A2729A154A8",
    synced: false,
    allowlist: new Set(["cb69481e-8ff7-4039-93ec-0a2729a154a8"]),
    rootsConfigured: true,
  };
  it("accepts an allow-listed, device-bound key with a full attestation chained to configured roots", () => {
    expect(authenticatorProblem(base)).toBeNull();
  });
  it("refuses none attestations, synced passkeys, unknown models and an empty allow-list", () => {
    expect(authenticatorProblem({ ...base, fmt: "none" })).toMatch(/no attestation/);
    expect(authenticatorProblem({ ...base, synced: true })).toMatch(/synced/);
    expect(authenticatorProblem({ ...base, aaguid: "00000000-0000-0000-0000-000000000001" })).toMatch(
      /not allow-listed/,
    );
    expect(authenticatorProblem({ ...base, allowlist: new Set() })).toMatch(/no hardware keys/);
  });
  it("on the server stage requires a full attestation and trust anchors; local stacks accept self attestation", () => {
    expect(authenticatorProblem({ ...base, hasX5c: false })).toMatch(/full attestation/);
    expect(authenticatorProblem({ ...base, fmt: "apple" })).toMatch(/full attestation/);
    expect(authenticatorProblem({ ...base, rootsConfigured: false })).toMatch(/trust anchors/);
    expect(authenticatorProblem({ ...base, env: "local", hasX5c: false, rootsConfigured: false })).toBeNull();
    expect(authenticatorProblem({ ...base, env: "test", hasX5c: false, rootsConfigured: false })).toBeNull();
  });
  it("parses the allow-list; virtual authenticators only outside the server stage", () => {
    const text = "# keys\nCB69481E-8FF7-4039-93EC-0A2729A154A8  # YubiKey 5\n\n01020304-0506-0708-0102-030405060708\n";
    expect([...parseAaguids(text, "server")]).toEqual(["cb69481e-8ff7-4039-93ec-0a2729a154a8"]);
    expect(parseAaguids(text, "local").size).toBe(2);
    expect(() => parseAaguids("not-an-aaguid", "local")).toThrow(/not an AAGUID/);
  });
  it("parses PEM bundles and the console origin", () => {
    const pem = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----";
    expect(parsePemBundle(`junk\n${pem}\n${pem}\n`)).toHaveLength(2);
    expect(consoleConfig({ env: "local", opsOrigin: "https://ops.nearpay.localhost/" })).toMatchObject({
      origin: "https://ops.nearpay.localhost",
      rpId: "ops.nearpay.localhost",
    });
    expect(consoleConfig({ env: "local" })).toMatchObject({ origin: null, rpId: null });
  });
});

describe("restricted-key scopes", () => {
  it("validates and normalises", () => {
    expect(checkScopes("restricted", ["refunds.write", "refunds.write", "events.read"], KEY_SCOPES)).toEqual({
      ok: true,
      scopes: ["events.read", "refunds.write"],
    });
    expect(checkScopes("restricted", ["destinations.write"], KEY_SCOPES)).toMatchObject({
      ok: false,
      error: "scope_unknown",
      scope: "destinations.write",
    });
    expect(checkScopes("restricted", [], KEY_SCOPES)).toMatchObject({ ok: false, error: "invalid_request" });
    expect(checkScopes("restricted", undefined, KEY_SCOPES)).toMatchObject({ ok: false, error: "invalid_request" });
    expect(checkScopes("secret", ["events.read"], KEY_SCOPES)).toMatchObject({ ok: false, error: "invalid_request" });
    expect(checkScopes("publishable", undefined, KEY_SCOPES)).toEqual({ ok: true, scopes: [] });
  });
  it("write implies read; a write scope without a read counterpart stays alone", () => {
    expect(expandScopes(["refunds.write"], KEY_SCOPES)).toEqual(["refunds.read", "refunds.write"]);
    expect(expandScopes(["x.write"], ["x.write"])).toEqual(["x.write"]);
    expect(expandScopes(["gone.read"], KEY_SCOPES)).toEqual([]);
    expect(restrictedAllows(["session", "restricted_key:refunds.read"], ["refunds.read"])).toBe(true);
    expect(restrictedAllows(["session", "secret_key"], ["refunds.read"])).toBe(false);
  });
});

describe("sessions and the console host", () => {
  const T = Date.UTC(2026, 10, 7);
  it("console sessions idle out after 30 minutes, dashboard sessions after 12 hours", () => {
    const s = { expires_at: new Date(T + LIFETIME.ops.absoluteMs), last_seen_at: new Date(T), revoked_at: null };
    expect(sessionState(s, T + OPS_IDLE_MS, "ops")).toBe("valid");
    expect(sessionState(s, T + OPS_IDLE_MS + 1, "ops")).toBe("idle");
    expect(sessionState(s, T + OPS_IDLE_MS + 1, "dashboard")).toBe("valid");
    expect(sessionState(s, T + LIFETIME.ops.absoluteMs, "ops")).toBe("expired");
    expect(idleExpiresAt(s, "ops").getTime()).toBe(T + OPS_IDLE_MS);
    expect(idleExpiresAt({ ...s, last_seen_at: new Date(T + LIFETIME.ops.absoluteMs - 1000) }, "ops").getTime()).toBe(
      T + LIFETIME.ops.absoluteMs,
    );
  });
  it("console paths and hosts", () => {
    expect(isConsolePath("/ops/merchants?q=x")).toBe(true);
    expect(isConsolePath("/v1/account")).toBe(false);
    expect(isConsolePath("/opsx")).toBe(false);
    expect(isConsolePath(undefined)).toBe(false);
    expect(isConsoleHost("ops.nearpay.localhost:443")).toBe(true);
    expect(isConsoleHost(undefined)).toBe(false);
  });
});
