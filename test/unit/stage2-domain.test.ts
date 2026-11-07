/** Stage 2 domain rules (lld/identity.md §5, §6, §6.1, §11): approvals, team, console keys, scopes, sessions. */
import { KEY_SCOPES } from "@nearpay/spec";
import { describe, expect, it } from "vitest";
import { consoleConfig, parseAaguids, parsePemBundle } from "../../src/config.js";
import { checkScopes, expandScopes, restrictedAllows } from "../../src/domain/api-key/key.js";
import {
  afterAttestation,
  applyRoleChange,
  approvedBy,
  approverQualifies,
  atActivation,
  CONTESTED_MANAGER_TENURE_MS,
  decide,
  effectiveRequired,
  evaluate,
  grantQualifiesAt,
  isExpired,
  MANAGER_TENURE_MS,
  type ManagerGrant,
  PENDING_DESTINATION_TTL_MS,
  rejectedBy,
} from "../../src/domain/approval/approval.js";
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

const DAY = 86_400_000;
const NOW = 1_000 * DAY;
/** A grant held since `daysAgo` that qualified long ago. */
const tenured = (userId: string, daysAgo = 60): ManagerGrant => ({
  userId,
  grantedAt: NOW - daysAgo * DAY,
  qualifiesAt: NOW - (daysAgo - 7) * DAY,
  revokedAt: null,
});

describe("two-approver rule", () => {
  const pending = {
    status: "pending_approval",
    required: 2,
    createdBy: "a",
    approvals: [{ userId: "a", decision: "approve" as const }],
    createdAt: NOW - DAY,
    now: NOW,
    cooloffMs: DAY,
    grants: [tenured("a"), tenured("b"), tenured("c")],
  };
  it("a second, different, tenured owner/admin completes it", () => {
    expect(decide(pending, "b", "approve")).toEqual({
      ok: true,
      record: { userId: "b", decision: "approve" },
      required: 2,
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
  it("a rejection disables (no tenure needed to say no)", () => {
    expect(decide(pending, "b", "reject")).toMatchObject({ ok: true, to: "disabled" });
    const fresh = { ...pending, grants: [tenured("a"), { ...tenured("p"), grantedAt: NOW - DAY / 2 }] };
    expect(decide(fresh, "p", "reject")).toMatchObject({ ok: true, to: "disabled" });
  });
  it("only pending_approval destinations take decisions; pending ones expire after 7 days", () => {
    for (const status of ["pending_verification", "cooling_off", "active", "disabled"])
      expect(decide({ ...pending, status }, "b", "approve")).toMatchObject({ ok: false, error: "state_conflict" });
    expect(decide({ ...pending, createdAt: NOW - PENDING_DESTINATION_TTL_MS }, "b", "approve")).toEqual({
      ok: false,
      error: "state_conflict",
      reason: "expired",
    });
    expect(isExpired(NOW - PENDING_DESTINATION_TTL_MS + 1, NOW)).toBe(false);
  });
  it("three required (never configured) needs a third user", () => {
    expect(decide({ ...pending, required: 3 }, "b", "approve")).toMatchObject({ ok: true, to: "pending_approval" });
  });
  it("completion counts distinct qualifying approvers and no rejection", () => {
    const ctx = { createdAt: NOW - DAY, now: NOW, cooloffMs: DAY, grants: [tenured("a")] };
    expect(evaluate(ctx, 1, [{ userId: "a", decision: "approve" }])).toEqual({ required: 1, complete: true });
    const two = { ...ctx, grants: [tenured("a"), tenured("b")] };
    expect(
      evaluate(two, 2, [
        { userId: "a", decision: "approve" },
        { userId: "a", decision: "approve" },
      ]).complete,
    ).toBe(false);
    expect(
      evaluate(ctx, 1, [
        { userId: "a", decision: "approve" },
        { userId: "b", decision: "reject" },
      ]).complete,
    ).toBe(false);
    expect(evaluate(ctx, 0, []).complete).toBe(false);
    // a user who is no longer an owner/admin never counts
    expect(evaluate({ ...ctx, grants: [] }, 1, [{ userId: "a", decision: "approve" }]).complete).toBe(false);
    expect(afterAttestation(two, 2, pending.approvals)).toEqual({ required: 2, to: "pending_approval" });
    expect(afterAttestation(ctx, 1, pending.approvals)).toEqual({ required: 1, to: "cooling_off" });
    expect(atActivation(two, 1, pending.approvals)).toEqual({ required: 2, to: "pending_approval" });
    expect(atActivation(ctx, 1, pending.approvals)).toEqual({ required: 1, to: "active" });
    expect(
      approvedBy([
        { userId: "a", decision: "approve" },
        { userId: "b", decision: "reject" },
      ]),
    ).toEqual(["a"]);
    expect(rejectedBy([{ userId: "b", decision: "reject" }])).toBe("b");
    expect(rejectedBy([])).toBeNull();
  });

  // audit finding 1, scenario A: a puppet admin invited by one manager cannot be the second approver
  it("a manager granted after the destination was created, or too recently, does not count", () => {
    const puppetAfter = { ...tenured("p"), grantedAt: NOW - DAY / 2, qualifiesAt: NOW - DAY / 4 };
    expect(decide({ ...pending, grants: [tenured("a"), tenured("b"), puppetAfter] }, "p", "approve")).toMatchObject({
      ok: false,
      error: "approver_conflict",
    });
    const puppetYoung = { userId: "p", grantedAt: NOW - 3 * DAY, qualifiesAt: NOW + 4 * DAY, revokedAt: null };
    expect(decide({ ...pending, grants: [tenured("a"), tenured("b"), puppetYoung] }, "p", "approve")).toMatchObject({
      ok: false,
      error: "approver_conflict",
    });
    // qualified but within the cool-off
    const withinCooloff = { userId: "p", grantedAt: NOW - 2 * DAY, qualifiesAt: NOW - DAY, revokedAt: null };
    expect(
      approverQualifies({ ...pending, createdAt: NOW - DAY, cooloffMs: 3 * DAY, grants: [withinCooloff] }, 2, "p"),
    ).toBe(false);
    // a puppet creator's own approval does not count either
    const byPuppet = { ...pending, createdBy: "p", approvals: [{ userId: "p", decision: "approve" as const }] };
    expect(decide({ ...byPuppet, grants: [tenured("a"), puppetYoung] }, "a", "approve")).toMatchObject({
      ok: true,
      to: "pending_approval",
    });
  });

  // audit finding 1, scenario B: removing the other managers first does not lower the requirement
  it("the requirement is the 30-day high-water mark of owners/admins, never only the stored value", () => {
    const removed = { ...tenured("b"), revokedAt: NOW - 10 * DAY };
    expect(effectiveRequired(1, [tenured("a"), removed], NOW)).toBe(2);
    expect(effectiveRequired(1, [tenured("a"), { ...removed, revokedAt: NOW - 31 * DAY }], NOW)).toBe(1);
    expect(effectiveRequired(1, [tenured("a"), tenured("b")], NOW)).toBe(2);
    expect(effectiveRequired(2, [tenured("a")], NOW)).toBe(2);
    expect(decide({ ...pending, required: 1, grants: [tenured("a"), removed] }, "b", "approve")).toMatchObject({
      ok: false,
      error: "approver_conflict",
    });
  });

  it("a grant next to two other recent managers waits 30 days, otherwise 7; owner<->admin keeps the grant", () => {
    expect(grantQualifiesAt([tenured("a")], "b", NOW)).toBe(NOW + MANAGER_TENURE_MS);
    expect(grantQualifiesAt([tenured("a"), tenured("b")], "p", NOW)).toBe(NOW + CONTESTED_MANAGER_TENURE_MS);
    // the grantee's own earlier grants do not count
    expect(grantQualifiesAt([tenured("a"), { ...tenured("p"), revokedAt: NOW - DAY }], "p", NOW)).toBe(
      NOW + MANAGER_TENURE_MS,
    );
    let g = applyRoleChange([tenured("a")], "b", false, true, NOW);
    expect(g).toHaveLength(2);
    expect(applyRoleChange(g, "b", true, true, NOW + DAY)).toEqual(g);
    g = applyRoleChange(g, "b", true, false, NOW + DAY);
    expect(g.find((x) => x.userId === "b")?.revokedAt).toBe(NOW + DAY);
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
