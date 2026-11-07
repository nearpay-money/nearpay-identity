/**
 * Stage gate (audit finding 2): relaxed developer behaviour — Cloudflare's always-pass Turnstile test
 * secrets, client IPs from `X-Forwarded-For`, a zero cool-off, virtual authenticators, local-only CLI
 * commands, relaxed console checks — only when `NP_ENV` is `local` or `test`. Every other value, known
 * or not, gets the strict (server) behaviour.
 */
export const isDevEnv = (env: string): boolean => env === "local" || env === "test";
