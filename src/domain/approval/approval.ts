/**
 * Two-approver rule for settlement destinations (lld/identity.md §5). Pure.
 *
 * `approvals_required` is fixed at creation: 2 when the account has ≥ 2 owner/admin members, else 1.
 * The creator's creation is the first approval. With 2 required, the second approver must be another
 * user than the creator and than every earlier approver (`approver_conflict`); a `reject` disables the
 * destination. The database repeats the rule (primary key `(destination_id, user_id)` and the
 * `destination_approvals_complete` trigger), so a defect here cannot let one user complete a change.
 */

export type Decision = "approve" | "reject";

export interface ApprovalRecord {
  readonly userId: string;
  readonly decision: Decision;
}

export interface ApprovalState {
  readonly status: string;
  readonly required: number;
  readonly createdBy: string;
  readonly approvals: readonly ApprovalRecord[];
}

export type ApprovalOutcome =
  | { readonly ok: true; readonly record: ApprovalRecord; readonly to: "cooling_off" | "pending_approval" | "disabled" }
  | { readonly ok: false; readonly error: "state_conflict" | "approver_conflict"; readonly reason: string };

/** Distinct users who approved, in order. */
export function approvedBy(approvals: readonly ApprovalRecord[]): string[] {
  const out: string[] = [];
  for (const a of approvals) if (a.decision === "approve" && !out.includes(a.userId)) out.push(a.userId);
  return out;
}

export const rejectedBy = (approvals: readonly ApprovalRecord[]): string | null =>
  approvals.find((a) => a.decision === "reject")?.userId ?? null;

/** Enough distinct approvals and no rejection. */
export function isComplete(required: number, approvals: readonly ApprovalRecord[]): boolean {
  return rejectedBy(approvals) === null && approvedBy(approvals).length >= Math.max(1, required);
}

/** Where a successful attestation moves the destination. */
export function afterAttestation(
  required: number,
  approvals: readonly ApprovalRecord[],
): "cooling_off" | "pending_approval" {
  return isComplete(required, approvals) ? "cooling_off" : "pending_approval";
}

/** `POST /v1/settlement_destinations/{id}/approve` by `approver` (an owner/admin with a fresh step-up). */
export function decide(s: ApprovalState, approver: string, decision: Decision): ApprovalOutcome {
  if (s.status !== "pending_approval")
    return { ok: false, error: "state_conflict", reason: `the destination is ${s.status}` };
  if (approver === s.createdBy)
    return { ok: false, error: "approver_conflict", reason: "the creator cannot decide on their own destination" };
  if (s.approvals.some((a) => a.userId === approver))
    return { ok: false, error: "approver_conflict", reason: "this user already decided on the destination" };
  const record = { userId: approver, decision };
  if (decision === "reject") return { ok: true, record, to: "disabled" };
  return {
    ok: true,
    record,
    to: isComplete(s.required, [...s.approvals, record]) ? "cooling_off" : "pending_approval",
  };
}
