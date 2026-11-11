import { PUBLIC_ROUTES } from "@nearpay-money/spec";
import { describe, expect, it } from "vitest";
import { applyPatch, DEFAULT_SETTINGS, SettingError, withSettingDefaults } from "../../src/domain/account/account.js";
import {
  anonymousAllowed,
  clientIp,
  degraded,
  isConsoleHost,
  isUnsafe,
  publishableAllowed,
  RATE_LIMITS,
  type RouteRef,
  requiresLiveEnabled,
  routeMatcher,
  sessionMode,
  takeToken,
} from "../../src/domain/authz/authz.js";
import {
  approvalsRequired,
  attestationMessage,
  liveEnabled,
  missingRequirements,
  signingStandard,
  transition,
  usdMicrosToCents,
} from "../../src/domain/settlement-destination/destination.js";

describe("destination state machine", () => {
  it("every transition of the table", () => {
    expect(transition("pending_verification", "attest")).toEqual({ ok: true, to: "cooling_off" });
    expect(transition("pending_verification", "attest", { approvalsRequired: 2 })).toEqual({
      ok: true,
      to: "pending_approval",
    });
    expect(transition("pending_approval", "approve")).toEqual({ ok: true, to: "cooling_off" });
    expect(transition("cooling_off", "activate")).toEqual({ ok: true, to: "active" });
    // audit fix: activation re-checks approvals; pending destinations expire
    expect(transition("cooling_off", "require_approval")).toEqual({ ok: true, to: "pending_approval" });
    expect(transition("active", "require_approval")).toEqual({ ok: false, state: "active" });
    for (const from of ["pending_verification", "pending_approval"] as const)
      expect(transition(from, "expire")).toEqual({ ok: true, to: "disabled" });
    for (const from of ["cooling_off", "active", "disabled"] as const)
      expect(transition(from, "expire")).toEqual({ ok: false, state: from });
    expect(transition("active", "set_default")).toEqual({ ok: true, to: "active" });
    // a re-issued challenge keeps the destination waiting for its signature
    expect(transition("pending_verification", "challenge")).toEqual({ ok: true, to: "pending_verification" });
    for (const from of ["pending_verification", "pending_approval", "cooling_off", "active"] as const)
      expect(transition(from, "disable")).toEqual({ ok: true, to: "disabled" });
  });
  it("refuses everything else with the current state", () => {
    for (const from of ["pending_approval", "cooling_off", "active", "disabled"] as const)
      expect(transition(from, "attest")).toEqual({ ok: false, state: from });
    expect(transition("cooling_off", "approve")).toEqual({ ok: false, state: "cooling_off" });
    expect(transition("active", "activate")).toEqual({ ok: false, state: "active" });
    expect(transition("disabled", "disable")).toEqual({ ok: false, state: "disabled" });
    expect(transition("cooling_off", "set_default")).toEqual({ ok: false, state: "cooling_off" });
    for (const from of ["pending_approval", "cooling_off", "active", "disabled"] as const)
      expect(transition(from, "challenge")).toEqual({ ok: false, state: from });
  });
  it("approvals: 2 only with the two-approver rule and ≥ 2 owners/admins", () => {
    expect(approvalsRequired(1, true)).toBe(1);
    expect(approvalsRequired(2, true)).toBe(2);
    expect(approvalsRequired(5, false)).toBe(1);
  });
  it("live mode needs KYB approved, an active live destination and an active account", () => {
    expect(liveEnabled({ kyb_status: "approved", status: "active" }, true)).toBe(true);
    expect(liveEnabled({ kyb_status: "pending", status: "active" }, true)).toBe(false);
    expect(liveEnabled({ kyb_status: "approved", status: "suspended" }, true)).toBe(false);
    expect(liveEnabled({ kyb_status: "approved", status: "active" }, false)).toBe(false);
    expect(missingRequirements({ kyb_status: "pending", status: "suspended" }, false)).toEqual([
      "kyb",
      "destination",
      "account_status",
    ]);
    expect(missingRequirements({ kyb_status: "approved", status: "active" }, true)).toEqual([]);
  });
  it("signing standards per destination", () => {
    expect(signingStandard("chain_address", "evm", "0x52908400098527886e0f7030069857d2e4169ee7")).toBe("eip191");
    expect(signingStandard("intents_account", "near", "0x52908400098527886e0f7030069857d2e4169ee7")).toBe("eip191");
    expect(signingStandard("intents_account", "near", "merchant.near")).toBe("nep413");
    expect(signingStandard("chain_address", "near", "a".repeat(64))).toBe("nep413");
    expect(signingStandard("chain_address", "solana", "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM")).toBe("solana");
    expect(signingStandard("chain_address", "bitcoin", "bc1q")).toBe("bip322");
  });
  it("the exact attestation message (§8.2)", () => {
    expect(
      attestationMessage({
        account: "acct_1",
        livemode: true,
        assetId: "nep141:usdc.near",
        chain: "near:mainnet",
        address: "merchant.near",
        nonceHex: "ab".repeat(32),
        expiresAt: new Date("2026-11-06T10:00:00.000Z"),
      }),
    ).toBe(
      `NearPay settlement destination\nAccount: acct_1\nMode: live\nAsset: nep141:usdc.near\nNetwork: near:mainnet\nAddress: merchant.near\nNonce: ${"ab".repeat(32)}\nExpires: 2026-11-06T10:00:00.000Z`,
    );
  });
  it("rounds minimums up to cents", () => {
    expect(usdMicrosToCents(0)).toBe(0);
    expect(usdMicrosToCents(10_000)).toBe(1);
    expect(usdMicrosToCents(10_001)).toBe(2);
  });
});

describe("account settings", () => {
  const current = {
    display_name: "Acme",
    country: null,
    website: null,
    fee_bearer: "payer" as const,
    settings: DEFAULT_SETTINGS,
  };
  it("detects money-behaviour changes (step-up required)", () => {
    expect(applyPatch(current, { fee_bearer: "merchant" }).moneyChanged).toBe(true);
    expect(applyPatch(current, { settings: { late_payments: true } }).moneyChanged).toBe(true);
    expect(applyPatch(current, { settings: { underpay_tolerance_bps: 10 } }).moneyChanged).toBe(true);
    const r = applyPatch(current, { display_name: "Acme 2", country: "de", settings: { email_receipts: false } });
    expect(r).toMatchObject({ moneyChanged: false, changed: true, next: { display_name: "Acme 2", country: "DE" } });
    expect(applyPatch(current, { fee_bearer: "payer" })).toMatchObject({ changed: false, moneyChanged: false });
  });
  it("merges branding and validates the logo URL", () => {
    const r = applyPatch(current, { settings: { branding: { accent_color: "#112233" } } });
    expect(r.next.settings.branding).toEqual({
      accent_color: "#112233",
      logo_url: null,
      theme: "auto",
      corner_radius: 8,
    });
    const cleared = applyPatch(
      {
        ...current,
        settings: { ...DEFAULT_SETTINGS, branding: { accent_color: "#000000", logo_url: "https://x/l.png" } },
      },
      {
        settings: { branding: { accent_color: null, logo_url: null } },
      },
    );
    expect(cleared.next.settings.branding).toEqual({ accent_color: null, logo_url: null });
    expect(() => applyPatch(current, { settings: { branding: { logo_url: "http://x/l.png" } } })).toThrow(SettingError);
  });
  it("spec 0.2.1: website, theme and corner radius (no step-up; validated; older rows keep no keys)", () => {
    const r = applyPatch(current, {
      website: "https://shop.example.com",
      settings: { branding: { theme: "dark", corner_radius: 0 } },
    });
    expect(r).toMatchObject({ moneyChanged: false, changed: true });
    expect(r.next.website).toBe("https://shop.example.com");
    expect(r.next.settings.branding).toMatchObject({ theme: "dark", corner_radius: 0 });
    expect(applyPatch(r.next, { website: null }).next.website).toBeNull();
    expect(applyPatch(r.next, { settings: { branding: { corner_radius: 24 } } }).next.settings.branding).toMatchObject({
      theme: "dark",
      corner_radius: 24,
    });
    const bad = (p: Parameters<typeof applyPatch>[1], param: string) => {
      try {
        applyPatch(current, p);
        throw new Error("accepted");
      } catch (e) {
        expect(e).toBeInstanceOf(SettingError);
        expect((e as SettingError).param).toBe(param);
      }
    };
    bad({ website: "http://shop.example.com" }, "website");
    bad({ settings: { branding: { theme: "sepia" } } }, "settings[branding][theme]");
    bad({ settings: { branding: { corner_radius: 25 } } }, "settings[branding][corner_radius]");
    bad({ settings: { branding: { corner_radius: 1.5 } } }, "settings[branding][corner_radius]");
    bad({ settings: { branding: { corner_radius: -1 } } }, "settings[branding][corner_radius]");
    // a pre-0.2.1 row: no theme/corner_radius keys until set, defaults filled on read
    const old = { ...current, settings: { ...DEFAULT_SETTINGS, branding: { accent_color: null, logo_url: null } } };
    expect(applyPatch(old, { display_name: "Acme 3" }).next.settings.branding).toEqual({
      accent_color: null,
      logo_url: null,
    });
    expect(withSettingDefaults(old.settings).branding).toEqual({
      accent_color: null,
      logo_url: null,
      theme: "auto",
      corner_radius: 8,
    });
  });
});

describe("gateway rules", () => {
  const match = routeMatcher(PUBLIC_ROUTES as readonly RouteRef[]);
  it("matches spec routes; literal segments win over parameters", () => {
    expect(match("GET", "/v1/account/requirements")?.id).toBe("getAccountRequirements");
    expect(match("GET", "/v1/settlement_destinations/sd_123?expand=x")?.id).toBe("getSettlementDestination");
    expect(match("POST", "/v1/settlement_destinations/sd_123/attest")?.id).toBe("attestSettlementDestination");
    expect(match("DELETE", "/v1/api_keys/key_1")?.id).toBe("revokeApiKey");
    expect(match("GET", "/v1/nope")).toBeNull();
    expect(match("PUT", "/v1/account")).toBeNull();
  });
  it("classifies routes from the contract", () => {
    expect(anonymousAllowed(match("POST", "/v1/auth/signup"))).toBe(true);
    expect(anonymousAllowed(match("GET", "/v1/checkout/sessions/cs_1/public"))).toBe(true);
    expect(anonymousAllowed(match("GET", "/v1/account"))).toBe(false);
    expect(anonymousAllowed(null)).toBe(false);
    const create = PUBLIC_ROUTES.find((r) => r.id === "createCheckoutSession") as RouteRef;
    expect(requiresLiveEnabled(create)).toBe(true);
    expect(requiresLiveEnabled(match("POST", "/v1/settlement_destinations"))).toBe(false);
    expect(requiresLiveEnabled(null)).toBe(false);
    const pkRoute = PUBLIC_ROUTES.find((r) => r.auth.includes("publishable_key")) as RouteRef | undefined;
    if (pkRoute) expect(publishableAllowed(pkRoute)).toBe(true);
    expect(publishableAllowed(match("GET", "/v1/account"))).toBe(false);
    expect(publishableAllowed(null)).toBe(false);
  });
  it("unsafe methods, mode header, console host", () => {
    expect(isUnsafe("GET")).toBe(false);
    expect(isUnsafe("head")).toBe(false);
    expect(isUnsafe("POST")).toBe(true);
    expect(isUnsafe("DELETE")).toBe(true);
    expect(sessionMode("live")).toBe(true);
    expect(sessionMode(" LIVE ")).toBe(true);
    expect(sessionMode("test")).toBe(false);
    expect(sessionMode(undefined)).toBe(false);
    expect(isConsoleHost("ops.nearpay.localhost:443")).toBe(true);
    expect(isConsoleHost("dashboard.nearpay.localhost")).toBe(false);
    expect(isConsoleHost(undefined)).toBe(false);
  });
  it("client IP: CF-Connecting-IP on the server, the first X-Forwarded-For hop locally", () => {
    expect(clientIp("server", { cfConnectingIp: "1.2.3.4", xForwardedFor: "9.9.9.9" })).toBe("1.2.3.4");
    expect(clientIp("local", { cfConnectingIp: "1.2.3.4", xForwardedFor: "9.9.9.9, 10.0.0.1" })).toBe("9.9.9.9");
    expect(clientIp("local", {})).toBeNull();
    // audit finding 2: X-Forwarded-For only for NP_ENV local/test; any other stage reads CF-Connecting-IP
    expect(clientIp("staging", { cfConnectingIp: "1.2.3.4", xForwardedFor: "9.9.9.9" })).toBe("1.2.3.4");
    expect(clientIp("test", { cfConnectingIp: "1.2.3.4", xForwardedFor: "9.9.9.9" })).toBe("9.9.9.9");
    expect(clientIp("local", { xForwardedFor: "<script>" })).toBeNull();
  });
  it("token buckets refill at the rate and cap at the burst", () => {
    const b = { rate: 10, burst: 2 };
    let r = takeToken(undefined, b, 0);
    expect(r.allowed).toBe(true);
    r = takeToken(r.state, b, 0);
    expect(r.allowed).toBe(true);
    r = takeToken(r.state, b, 0);
    expect(r).toMatchObject({ allowed: false, retryAfter: 1 });
    r = takeToken(r.state, b, 100);
    expect(r.allowed).toBe(true);
    expect(takeToken({ tokens: 0, at: 0 }, b, 60_000).state.tokens).toBe(1);
    expect(degraded(RATE_LIMITS.live)).toEqual({ rate: 50, burst: 100 });
    expect(degraded({ rate: 1, burst: 1 })).toEqual({ rate: 0.5, burst: 1 });
    expect(RATE_LIMITS).toEqual({
      live: { rate: 100, burst: 200 },
      test: { rate: 25, burst: 50 },
      anonymous: { rate: 10, burst: 20 },
    });
  });
});
