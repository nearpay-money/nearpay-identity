/** Account settings (lld/identity.md §4, §6, §12). Pure. */

export interface Settings {
  late_payments: boolean;
  underpay_tolerance_bps: number;
  session_ttl_default: number;
  email_receipts: boolean;
  branding: { accent_color: string | null; logo_url: string | null; theme?: Theme; corner_radius?: number };
}

/** Spec 0.2.1 checkout appearance: `theme` (closed here, open in the contract) and corner radius 0–24 px. */
export const THEMES = ["auto", "light", "dark"] as const;
export type Theme = (typeof THEMES)[number];
export const DEFAULT_THEME: Theme = "auto";
export const DEFAULT_CORNER_RADIUS = 8;

export const DEFAULT_SETTINGS: Settings = {
  late_payments: false,
  underpay_tolerance_bps: 0,
  session_ttl_default: 3600,
  email_receipts: true,
  branding: { accent_color: null, logo_url: null, theme: DEFAULT_THEME, corner_radius: DEFAULT_CORNER_RADIUS },
};

/** Settings as served: rows written before spec 0.2.1 lack `theme` / `corner_radius`. */
export function withSettingDefaults(s: Settings): Settings {
  return {
    ...s,
    branding: {
      ...s.branding,
      theme: s.branding.theme ?? DEFAULT_THEME,
      corner_radius: s.branding.corner_radius ?? DEFAULT_CORNER_RADIUS,
    },
  };
}

export interface AccountPatch {
  display_name?: string | undefined;
  country?: string | undefined;
  website?: string | null | undefined;
  fee_bearer?: "payer" | "merchant" | undefined;
  settings?:
    | {
        late_payments?: boolean | undefined;
        underpay_tolerance_bps?: number | undefined;
        session_ttl_default?: number | undefined;
        email_receipts?: boolean | undefined;
        branding?:
          | {
              accent_color?: string | null | undefined;
              logo_url?: string | null | undefined;
              theme?: string | undefined;
              corner_radius?: number | undefined;
            }
          | undefined;
      }
    | undefined;
}

export interface AccountFields {
  display_name: string;
  country: string | null;
  website: string | null;
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
  if (p.website && !p.website.startsWith("https://")) throw new SettingError("website must be an https URL", "website");
  const b = s.branding;
  if (b?.theme !== undefined && !(THEMES as readonly string[]).includes(b.theme))
    throw new SettingError("theme must be auto, light or dark", "settings[branding][theme]");
  if (
    b?.corner_radius !== undefined &&
    !(Number.isInteger(b.corner_radius) && b.corner_radius >= 0 && b.corner_radius <= 24)
  )
    throw new SettingError("corner_radius must be an integer from 0 to 24", "settings[branding][corner_radius]");
  const cb = current.settings.branding;
  const next: AccountFields = {
    display_name: p.display_name ?? current.display_name,
    country: p.country === undefined ? current.country : p.country.toUpperCase(),
    website: p.website === undefined ? current.website : p.website,
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
        ...(b?.theme !== undefined || cb.theme !== undefined
          ? { theme: (b?.theme as Theme | undefined) ?? cb.theme }
          : {}),
        ...(b?.corner_radius !== undefined || cb.corner_radius !== undefined
          ? { corner_radius: b?.corner_radius ?? cb.corner_radius }
          : {}),
      },
    },
  };
  const moneyChanged =
    next.fee_bearer !== current.fee_bearer ||
    next.settings.late_payments !== current.settings.late_payments ||
    next.settings.underpay_tolerance_bps !== current.settings.underpay_tolerance_bps;
  return { next, moneyChanged, changed: JSON.stringify(next) !== JSON.stringify(current) };
}
