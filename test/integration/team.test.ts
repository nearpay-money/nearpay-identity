/**
 * Team members, invitations and multi-account sessions (lld/identity.md §5–§6, spec 0.2.0) through
 * the gateway: roles and the last-owner rule, invitation links for new and existing users, member
 * events, session revocation on removal, account switching and the sign-in landing account.
 */
import { sql } from "@nearpay-internal/db";
import { toUuid } from "@nearpay-internal/ids";
import { sendMessage } from "@nearpay-internal/spec";
import { mintServiceToken } from "@nearpay-internal/testing";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { notificationRecipients } from "../../src/app/internal.js";
import { type Stack, startStack } from "../support/stack.js";
import { as, invite, joinByInvite, mailedToken, signIn, signUp, stepUp, type User } from "../support/users.js";

let s: Stack;
let owner: User;
beforeAll(async () => {
  s = await startStack();
  owner = await signUp(s, "owner@team.test", "Team Shop");
});
afterAll(async () => {
  await s?.stop();
});

const memberEvents = async (accountId: string) =>
  (
    await sql<{ subject: string; payload: { data: { object: Record<string, unknown> } } }>`
      select subject, payload from outbox where account_id = ${toUuid(accountId, "acct")}
        and subject like 'evt.identity.member.%' order by created_at`.execute(s.admin.db)
  ).rows.map((r) => ({ subject: r.subject.replace("evt.identity.member.", ""), ...r.payload.data.object }));

describe("invitations", () => {
  it("a new user joins through the invitation link with the invited role; member.added is emitted", async () => {
    const { invitation } = await invite(s, owner, "dev@team.test", "developer");
    expect(invitation).toMatchObject({
      object: "invitation",
      email: "dev@team.test",
      role: "developer",
      status: "pending",
    });
    expect(invitation.id).toMatch(/^inv_/);
    // the mail names the account and role, and the link carries the token in its fragment only
    const mail = s.notify
      .callsTo(sendMessage)
      .map((c) => c.body as { template: string; variables: Record<string, unknown> })
      .find((m) => m.template === "team.invitation");
    expect(mail?.variables).toMatchObject({
      account_display_name: "Team Shop",
      role: "developer",
      expires_in_minutes: 10_080,
    });

    const token = mailedToken(s, "dev@team.test", "team.invitation");
    const v = await s.gateway("POST", "/v1/auth/magic_links/verify", { body: { token } });
    expect(v.body).toMatchObject({
      purpose: "invite",
      invitation: { account_display_name: "Team Shop", role: "developer" },
    });

    const dev = await joinByInvite(s, owner, "dev2@team.test", "developer");
    expect(dev.accountId).toBe(owner.accountId);
    const me = await s.gateway("GET", "/v1/auth/session", { cookie: dev.cookie });
    expect(me.body).toMatchObject({ role: "developer", account: { id: owner.accountId } });
    expect((await memberEvents(owner.accountId)).at(-1)).toMatchObject({
      subject: "added",
      user_id: dev.userId,
      role: "developer",
      previous_role: null,
      actor_user_id: null,
    });
    const list = await s.gateway("GET", "/v1/account/invitations?status=accepted", { cookie: owner.cookie });
    expect(list.body.data.map((i: { email: string }) => i.email)).toContain("dev2@team.test");
  });

  it("refuses duplicates and existing members (member_exists); only owners invite owners", async () => {
    await invite(s, owner, "dup@team.test", "viewer");
    const again = await s.gateway(
      "POST",
      "/v1/account/invitations",
      as(owner, "test", { email: "DUP@team.test", role: "viewer" }),
    );
    expect(again.status).toBe(409);
    expect(again.body.error.code).toBe("member_exists");
    expect(JSON.stringify(again.body)).not.toContain("dup@team.test");
    const self = await s.gateway(
      "POST",
      "/v1/account/invitations",
      as(owner, "test", { email: owner.email, role: "admin" }),
    );
    expect(self.body.error.code).toBe("member_exists");

    const admin = await joinByInvite(s, owner, "admin@team.test", "admin");
    await stepUp(s, admin);
    const promote = await s.gateway(
      "POST",
      "/v1/account/invitations",
      as(admin, "test", { email: "o2@team.test", role: "owner" }),
    );
    expect(promote.status).toBe(403);
    // developers cannot manage the team at all (route roles)
    const dev = await joinByInvite(s, owner, "dev3@team.test", "developer");
    expect((await s.gateway("GET", "/v1/account/members", { cookie: dev.cookie })).status).toBe(403);
  });

  it("an existing user accepts while signed in; the session switches to the joined account", async () => {
    const other = await signUp(s, "other@team.test", "Other Shop");
    const { token } = await invite(s, owner, "other@team.test", "finance");
    // the invitation link cannot add a passkey to an existing user: sign in and accept instead (link kept)
    const v = await s.gateway("POST", "/v1/auth/magic_links/verify", { body: { token } });
    expect(v.status).toBe(401);
    const wrong = await signUp(s, "wrong@team.test");
    const denied = await s.gateway("POST", "/v1/auth/invitations/accept", as(wrong, "test", { token }));
    expect(denied.body.error).toMatchObject({ code: "invitation_invalid" });
    const r = await s.gateway("POST", "/v1/auth/invitations/accept", as(other, "test", { token }));
    expect(r.status).toBe(200);
    expect(r.body).toMatchObject({ role: "finance", account: { id: owner.accountId }, csrf_token: other.csrf });
    expect(r.headers["set-cookie"]).toBeUndefined();
    // the same cookie now acts for the joined account; step-up was cleared
    expect((await s.gateway("GET", "/v1/account", { cookie: other.cookie })).body.id).toBe(owner.accountId);
    const used = await s.gateway("POST", "/v1/auth/invitations/accept", as(other, "test", { token }));
    expect(used.body.error.code).toBe("invitation_invalid");

    // memberships, most recently used first; switching back
    const ms = await s.gateway("GET", "/v1/auth/accounts", { cookie: other.cookie });
    expect(ms.body.data.map((m: { account: { id: string }; current: boolean }) => [m.account.id, m.current])).toEqual([
      [owner.accountId, true],
      [other.accountId, false],
    ]);
    const sw = await s.gateway("POST", "/v1/auth/session/account", as(other, "test", { account: other.accountId }));
    expect(sw.body).toMatchObject({ role: "owner", account: { id: other.accountId } });
    const notMine = await s.gateway(
      "POST",
      "/v1/auth/session/account",
      as(other, "test", { account: wrong.accountId }),
    );
    expect(notMine.status).toBe(404);
    // sign-in lands on the most recently used account
    const again = await signIn(s, other);
    expect(again.accountId).toBe(other.accountId);
    await s.gateway("POST", "/v1/auth/session/account", as(again, "test", { account: owner.accountId }));
    expect((await signIn(s, other)).accountId).toBe(owner.accountId);
  });

  it("revoked and expired invitations cannot be used", async () => {
    const { invitation, token } = await invite(s, owner, "gone@team.test", "viewer");
    const del = await s.gateway("DELETE", `/v1/account/invitations/${invitation.id}`, as(owner));
    expect(del.status).toBe(204);
    expect((await s.gateway("DELETE", `/v1/account/invitations/${invitation.id}`, as(owner))).body.error.code).toBe(
      "state_conflict",
    );
    expect((await s.gateway("POST", "/v1/auth/magic_links/verify", { body: { token } })).body.error.code).toBe(
      "link_used",
    );

    const late = await invite(s, owner, "late@team.test", "viewer");
    await s.admin.db
      .updateTable("invitations")
      .set({ expires_at: new Date(Date.now() - 1000) })
      .where("id", "=", toUuid(late.invitation.id, "inv"))
      .execute();
    const listed = await s.gateway("GET", "/v1/account/invitations?status=expired", { cookie: owner.cookie });
    expect(listed.body.data.map((i: { id: string }) => i.id)).toContain(late.invitation.id);
    const lateUser = await signUp(s, "late@team.test");
    const acc = await s.gateway("POST", "/v1/auth/invitations/accept", as(lateUser, "test", { token: late.token }));
    expect(acc.body.error.code).toBe("invitation_invalid");
    // a fresh invitation for the same address is possible again
    await invite(s, owner, "late@team.test", "viewer");
  });
});

describe("members", () => {
  it("lists members; owners change roles; the last owner stays; removal ends the member's sessions", async () => {
    const shop = await signUp(s, "boss@members.test", "Members Shop");
    const admin = await joinByInvite(s, shop, "adm@members.test", "admin");
    const list = await s.gateway("GET", "/v1/account/members", { cookie: shop.cookie });
    expect(list.body.data.map((m: { user: { email: string }; role: string }) => [m.user.email, m.role]).sort()).toEqual(
      [
        ["adm@members.test", "admin"],
        ["boss@members.test", "owner"],
      ],
    );
    // spec 0.2.1: a security summary per member (dashboard passkeys, last recovery)
    for (const m of list.body.data) expect(m.security).toEqual({ passkeys: 1, recovered_at: null });

    await stepUp(s, shop);
    const lastOwner = await s.gateway(
      "PATCH",
      `/v1/account/members/${shop.userId}`,
      as(shop, "test", { role: "admin" }),
    );
    expect(lastOwner.status).toBe(409);
    expect(lastOwner.body.error.code).toBe("last_owner");
    const rm = await s.gateway("DELETE", `/v1/account/members/${shop.userId}`, as(shop));
    expect(rm.body.error.code).toBe("last_owner");

    // admins cannot grant owner; owners can, and the role change reaches the member's session at once
    await stepUp(s, admin);
    const selfPromote = await s.gateway(
      "PATCH",
      `/v1/account/members/${admin.userId}`,
      as(admin, "test", { role: "owner" }),
    );
    expect(selfPromote.status).toBe(403);
    const promoted = await s.gateway(
      "PATCH",
      `/v1/account/members/${admin.userId}`,
      as(shop, "test", { role: "owner" }),
    );
    expect(promoted.body).toMatchObject({ object: "member", role: "owner", user: { id: admin.userId } });
    expect((await s.gateway("GET", "/v1/auth/session", { cookie: admin.cookie })).body.role).toBe("owner");
    // now there are two owners: the first one may step down
    const down = await s.gateway("PATCH", `/v1/account/members/${shop.userId}`, as(shop, "test", { role: "admin" }));
    expect(down.body.role).toBe("admin");
    expect((await memberEvents(shop.accountId)).filter((e) => e.subject === "role_changed")).toHaveLength(2);

    // the new owner removes the admin: their session ends at once
    await stepUp(s, admin);
    const removed = await s.gateway("DELETE", `/v1/account/members/${shop.userId}`, as(admin));
    expect(removed.status).toBe(204);
    expect((await s.gateway("GET", "/v1/account", { cookie: shop.cookie })).status).toBe(401);
    expect((await memberEvents(shop.accountId)).at(-1)).toMatchObject({
      subject: "removed",
      user_id: shop.userId,
      actor_user_id: admin.userId,
    });
    // notification recipients follow the team (security: owners + admins)
    const rec = await s.identity.db
      .selectFrom("memberships")
      .select("user_id")
      .where("account_id", "=", toUuid(shop.accountId, "acct"))
      .execute();
    expect(rec).toHaveLength(1);
    // audit: no email addresses in team audit rows
    const audit = await s.admin.db
      .selectFrom("audit_events")
      .select(["action", "details"])
      .where("account_id", "=", toUuid(shop.accountId, "acct"))
      .where("action", "like", "member.%")
      .execute();
    expect(audit.map((a) => a.action)).toEqual(
      expect.arrayContaining(["member.invited", "member.joined", "member.removed"]),
    );
    expect(JSON.stringify(audit)).not.toMatch(/@members\.test/);

    // spec 0.2.1 `?user=`: one member in any role (kind not applied); a member removed in the last
    // 7 days still answers with the role they had (notify mails them); anyone else → empty
    const token = await mintServiceToken("notify");
    const one = (user: string, kind = "billing") =>
      s.direct("GET", `/internal/accounts/${shop.accountId}/notification-recipients?kind=${kind}&user=${user}`, {
        token,
      });
    expect((await one(admin.userId)).body).toEqual({
      recipients: [{ user_id: admin.userId, email: "adm@members.test", role: "owner" }],
    });
    expect((await one(shop.userId)).body).toEqual({
      recipients: [{ user_id: shop.userId, email: "boss@members.test", role: "admin" }],
    });
    const stranger = await signUp(s, "stranger@members.test", "Other Shop");
    expect((await one(stranger.userId)).body).toEqual({ recipients: [] });
    // eight days later (audit rows are append-only: move the clock instead)
    const later = { ...s.identity, now: () => Date.now() + 8 * 86_400_000 };
    expect(await notificationRecipients(later, shop.accountId, "security", shop.userId)).toEqual({ recipients: [] });
    expect((await notificationRecipients(later, shop.accountId, "security", admin.userId)).recipients).toHaveLength(1);
  });
});
