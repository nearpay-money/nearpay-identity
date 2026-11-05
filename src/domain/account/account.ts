/** Account settings (lld/identity.md §4, §6, §12). Pure. */

export interface Settings {
  late_payments: boolean;
  underpay_tolerance_bps: number;
  session_ttl_default: number;
  email_receipts: boolean;
  branding: { accent_color: string | null; logo_url: string | null };
}

export const DEFAULT_SETTINGS: Settings = {
  late_payments: false,
  underpay_tolerance_bps: 0,
  session_ttl_default: 3600,
  email_receipts: true,
  branding: { accent_color: null, logo_url: null },
};

export interface AccountPatch {
  display_name?: string | undefined;
  country?: string | undefined;
  fee_bearer?: "payer" | "merchant" | undefined;
  settings?:
    | {
        late_payments?: boolean | undefined;
        underpay_tolerance_bps?: number | undefined;
        session_ttl_default?: number | undefined;
        email_receipts?: boolean | undefined;
        branding?: { accent_color?: string | null | undefined; logo_url?: string | null | undefined } | undefined;
      }
    | undefined;
}

export interface AccountFields {
  display_name: string;
  country: string | null;
  fee_bearer: "payer" | "merchant";
  settings: Settings;
}

export class SettingError extends Error {
  constructor(
    message: string,
    readonly param: string,
  ) {
    super(message);
    this.name = "SettingError";
  }
}

/**
 * Applies a patch. Returns the new fields and whether a money-behaviour field changed (those
 * need a fresh step-up, §12: `fee_bearer`, `late_payments`, `underpay_tolerance_bps`).
 */
export function applyPatch(
  current: AccountFields,
  p: AccountPatch,
): { next: AccountFields; moneyChanged: boolean; changed: boolean } {
  const s = p.settings ?? {};
  if (s.branding?.logo_url && !s.branding.logo_url.startsWith("https://"))
    throw new SettingError("logo_url must be an https URL", "settings[branding][logo_url]");
  const next: AccountFields = {
    display_name: p.display_name ?? current.display_name,
    country: p.country === undefined ? current.country : p.country.toUpperCase(),
    fee_bearer: p.fee_bearer ?? current.fee_bearer,
    settings: {
      late_payments: s.late_payments ?? current.settings.late_payments,
      underpay_tolerance_bps: s.underpay_tolerance_bps ?? current.settings.underpay_tolerance_bps,
      session_ttl_default: s.session_ttl_default ?? current.settings.session_ttl_default,
      email_receipts: s.email_receipts ?? current.settings.email_receipts,
      branding: {
        accent_color:
          s.branding?.accent_color === undefined ? current.settings.branding.accent_color : s.branding.accent_color,
        logo_url: s.branding?.logo_url === undefined ? current.settings.branding.logo_url : s.branding.logo_url,
      },
    },
  };
  const moneyChanged =
    next.fee_bearer !== current.fee_bearer ||
    next.settings.late_payments !== current.settings.late_payments ||
    next.settings.underpay_tolerance_bps !== current.settings.underpay_tolerance_bps;
  return { next, moneyChanged, changed: JSON.stringify(next) !== JSON.stringify(current) };
}
