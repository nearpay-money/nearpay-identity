/**
 * Team rules (lld/identity.md §5 "Invitation", §6; FR-ACC-01). Pure.
 *
 * Owners and admins manage the team; only owners invite, promote or remove owners; the last owner can
 * be neither demoted nor removed (`last_owner`). Invitations last 7 days, one pending per
 * (account, email); only a user with the invited email can accept.
 */
export type Role = "owner" | "admin" | "developer" | "finance" | "support" | "viewer";

export const INVITATION_MS = 7 * 24 * 3_600_000;

export type TeamCheck =
  | { readonly ok: true }
  | { readonly ok: false; readonly error: "permission_denied" | "last_owner"; readonly reason: string };

const OK: TeamCheck = { ok: true };
const MANAGERS: readonly Role[] = ["owner", "admin"];

/** Owners and admins may hold destination approvals (two-approver rule). */
export const isOwnerOrAdmin = (r: string | null | undefined) => r === "owner" || r === "admin";

export function canInvite(actor: Role, role: Role): TeamCheck {
  if (!MANAGERS.includes(actor)) return { ok: false, error: "permission_denied", reason: "manage the team" };
  if (role === "owner" && actor !== "owner")
    return { ok: false, error: "permission_denied", reason: "invite an owner" };
  return OK;
}

/** Changing `target`'s role from `current` to `next`; `owners` = owners of the account now. */
export function canChangeRole(actor: Role, current: Role, next: Role, owners: number): TeamCheck {
  if (!MANAGERS.includes(actor)) return { ok: false, error: "permission_denied", reason: "manage the team" };
  if ((current === "owner" || next === "owner") && current !== next && actor !== "owner")
    return { ok: false, error: "permission_denied", reason: "grant or take away the owner role" };
  if (current === "owner" && next !== "owner" && owners <= 1)
    return { ok: false, error: "last_owner", reason: "the account must keep at least one owner" };
  return OK;
}

export function canRemove(actor: Role, target: Role, owners: number): TeamCheck {
  if (!MANAGERS.includes(actor)) return { ok: false, error: "permission_denied", reason: "manage the team" };
  if (target === "owner" && actor !== "owner")
    return { ok: false, error: "permission_denied", reason: "remove an owner" };
  if (target === "owner" && owners <= 1)
    return { ok: false, error: "last_owner", reason: "the account must keep at least one owner" };
  return OK;
}

export type InvitationStatus = "pending" | "accepted" | "revoked" | "expired";

/** A pending invitation past its expiry reads as `expired` (the hourly purge writes it). */
export function effectiveStatus(i: { status: InvitationStatus; expires_at: Date }, now: number): InvitationStatus {
  return i.status === "pending" && i.expires_at.getTime() <= now ? "expired" : i.status;
}

/** Why `email` may not accept the invitation now, or null. */
export function acceptProblem(
  i: { status: InvitationStatus; expires_at: Date; email: string },
  email: string,
  now: number,
): string | null {
  const s = effectiveStatus(i, now);
  if (s !== "pending") return `it is ${s}`;
  if (i.email.trim().toLowerCase() !== email.trim().toLowerCase()) return "it was sent to another email address";
  return null;
}
