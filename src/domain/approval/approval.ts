/**
 * Two-approver rule for settlement destinations (lld/identity.md §5, §18 v1.8). Pure.
 *
 * Who must approve is decided again at every step (attestation, approval, activation), never only at
 * creation:
 * - required = the greatest of the stored `approvals_required`, 2 when the account has ≥ 2 owner/admin
 *   users now, and 2 when ≥ 2 users held owner/admin at any time in the last 30 days (high-water mark:
 *   removing the other managers before creating a destination does not lower the bar);
 * - with 2 required an approval counts only when the approver holds owner/admin now under a grant that
 *   predates the destination's creation, has reached its `qualifiesAt` (7 days after the grant, 30 days
 *   when ≥ 2 other managers held the role in the 30 days before it) and is older than the cool-off;
 * - pending destinations expire 7 days after creation.
 * The creator's creation is the first approval; every approver must differ from the creator and from
 * earlier approvers (`approver_conflict`); a `reject` disables the destination. The database repeats
 * the rule (approvals primary key, the `destination_approvals_complete` trigger and `manager_grants`,
 * migration 0005), so a defect here cannot let one person complete a change.
 */

export type Decision = "approve" | "reject";

export const DAY_MS = 86_400_000;
/** Pending destinations (`pending_verification`, `pending_approval`) are disabled after this. */
export const PENDING_DESTINATION_TTL_MS = 7 * DAY_MS;
/** High-water-mark window of the owner/admin count. */
export const MANAGER_WINDOW_MS = 30 * DAY_MS;
/** A new owner/admin grant counts for approvals after this … */
export const MANAGER_TENURE_MS = 7 * DAY_MS;
/** … or after this when ≥ 2 other managers held the role in the window before the grant. */
export const CONTESTED_MANAGER_TENURE_MS = 30 * DAY_MS;

export interface ApprovalRecord {
  readonly userId: string;
  readonly decision: Decision;
}

/** One owner/admin role grant (times in ms); `revokedAt` null = held now. */
export interface ManagerGrant {
  readonly userId: string;
  readonly grantedAt: number;
  readonly qualifiesAt: number;
  readonly revokedAt: number | null;
}

/** The facts the rule is evaluated against (read in the deciding transaction, database clock). */
export interface ApprovalContext {
  readonly createdAt: number;
  readonly now: number;
  readonly cooloffMs: number;
  readonly grants: readonly ManagerGrant[];
}

export const requiredFor = (managers: number) => (managers >= 2 ? 2 : 1);

const distinct = (xs: Iterable<string>) => [...new Set(xs)];

/** Users holding owner/admin now. */
export const currentManagers = (grants: readonly ManagerGrant[]) =>
  distinct(grants.filter((g) => g.revokedAt === null).map((g) => g.userId));

/** Users who held owner/admin at any time in `[at - window, at]`. */
export const recentManagers = (grants: readonly ManagerGrant[], at: number, except?: string) =>
  distinct(
    grants
      .filter(
        (g) =>
          g.userId !== except && g.grantedAt <= at && (g.revokedAt === null || g.revokedAt >= at - MANAGER_WINDOW_MS),
      )
      .map((g) => g.userId),
  );

/** Approvals required now: never below the stored value, the current managers or the 30-day high-water mark. */
export function effectiveRequired(stored: number, grants: readonly ManagerGrant[], now: number): number {
  return Math.max(stored, requiredFor(currentManagers(grants).length), requiredFor(recentManagers(grants, now).length));
}

/** When a grant of owner/admin to `userId` at `at` starts counting (SQL `manager_qualifies_at`). */
export function grantQualifiesAt(grants: readonly ManagerGrant[], userId: string, at: number): number {
  return at + (recentManagers(grants, at, userId).length >= 2 ? CONTESTED_MANAGER_TENURE_MS : MANAGER_TENURE_MS);
}

/** The grant history after `userId`'s role moves into or out of owner/admin at `at` (the memberships trigger). */
export function applyRoleChange(
  grants: readonly ManagerGrant[],
  userId: string,
  wasManager: boolean,
  isManager: boolean,
  at: number,
): ManagerGrant[] {
  if (wasManager && !isManager)
    return grants.map((g) => (g.userId === userId && g.revokedAt === null ? { ...g, revokedAt: at } : g));
  if (isManager && !wasManager)
    return [...grants, { userId, grantedAt: at, qualifiesAt: grantQualifiesAt(grants, userId, at), revokedAt: null }];
  return [...grants];
}

/** Whether `userId`'s approval counts with `required` approvals. */
export function approverQualifies(ctx: ApprovalContext, required: number, userId: string): boolean {
  const g = ctx.grants.find((x) => x.userId === userId && x.revokedAt === null);
  if (!g) return false;
  if (required < 2) return true;
  return g.grantedAt < ctx.createdAt && g.qualifiesAt <= ctx.now && g.grantedAt <= ctx.now - ctx.cooloffMs;
}

/** Distinct users who approved, in order. */
export function approvedBy(approvals: readonly ApprovalRecord[]): string[] {
  return distinct(approvals.filter((a) => a.decision === "approve").map((a) => a.userId));
}

export const rejectedBy = (approvals: readonly ApprovalRecord[]): string | null =>
  approvals.find((a) => a.decision === "reject")?.userId ?? null;

/** Approvers whose approval counts with `required` approvals. */
export const qualifyingApprovers = (ctx: ApprovalContext, required: number, approvals: readonly ApprovalRecord[]) =>
  approvedBy(approvals).filter((u) => approverQualifies(ctx, required, u));

/** No rejection and enough qualifying approvals for the effective requirement. */
export function evaluate(
  ctx: ApprovalContext,
  stored: number,
  approvals: readonly ApprovalRecord[],
): { readonly required: number; readonly complete: boolean } {
  const required = effectiveRequired(stored, ctx.grants, ctx.now);
  return {
    required,
    complete: rejectedBy(approvals) === null && qualifyingApprovers(ctx, required, approvals).length >= required,
  };
}

export const isExpired = (createdAt: number, now: number) => now >= createdAt + PENDING_DESTINATION_TTL_MS;

/** Where a successful attestation moves the destination. */
export function afterAttestation(
  ctx: ApprovalContext,
  stored: number,
  approvals: readonly ApprovalRecord[],
): { readonly required: number; readonly to: "cooling_off" | "pending_approval" } {
  const e = evaluate(ctx, stored, approvals);
  return { required: e.required, to: e.complete ? "cooling_off" : "pending_approval" };
}

/** Whether a destination in cool-off may still activate; otherwise it waits for approval again. */
export function atActivation(
  ctx: ApprovalContext,
  stored: number,
  approvals: readonly ApprovalRecord[],
): { readonly required: number; readonly to: "active" | "pending_approval" } {
  const e = evaluate(ctx, stored, approvals);
  return { required: e.required, to: e.complete ? "active" : "pending_approval" };
}

export interface ApprovalState extends ApprovalContext {
  readonly status: string;
  /** The stored `approvals_required`. */
  readonly required: number;
  readonly createdBy: string;
  readonly approvals: readonly ApprovalRecord[];
}

export type ApprovalOutcome =
  | {
      readonly ok: true;
      readonly record: ApprovalRecord;
      readonly required: number;
      readonly to: "cooling_off" | "pending_approval" | "disabled";
    }
  | { readonly ok: false; readonly error: "state_conflict" | "approver_conflict"; readonly reason: string };

/** `POST /v1/settlement_destinations/{id}/approve` by `approver` (an owner/admin with a fresh step-up). */
export function decide(s: ApprovalState, approver: string, decision: Decision): ApprovalOutcome {
  if (s.status !== "pending_approval") return { ok: false, error: "state_conflict", reason: s.status };
  if (isExpired(s.createdAt, s.now)) return { ok: false, error: "state_conflict", reason: "expired" };
  if (approver === s.createdBy)
    return { ok: false, error: "approver_conflict", reason: "the creator cannot decide on their own destination" };
  if (s.approvals.some((a) => a.userId === approver))
    return { ok: false, error: "approver_conflict", reason: "this user already decided on the destination" };
  const required = effectiveRequired(s.required, s.grants, s.now);
  const record = { userId: approver, decision };
  if (decision === "reject") return { ok: true, record, required, to: "disabled" };
  if (!approverQualifies(s, required, approver))
    return {
      ok: false,
      error: "approver_conflict",
      reason:
        "only an owner or admin who held the role before the destination was created, for at least 7 days " +
        "(30 days when added next to two other owners/admins), can approve it",
    };
  const e = evaluate(s, s.required, [...s.approvals, record]);
  return { ok: true, record, required: e.required, to: e.complete ? "cooling_off" : "pending_approval" };
}
