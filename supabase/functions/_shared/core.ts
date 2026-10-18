// Shared Paystack logic for the Edge Functions. Dependencies (DB client, fetch, env) are injected so this file
// can be tested without Paystack or Supabase. Docs: https://paystack.com/docs/payments/accept-payments/
// Rules from the docs that this code follows:
//   * Initialize + verify only from the server (secret key never reaches the browser).
//   * Verify `status` AND `amount` (and currency) before giving value.
//   * Webhooks: check x-paystack-signature = HMAC-SHA512(raw body, secret key) BEFORE processing; reply 200 fast.

export const PAYSTACK_BASE = "https://api.paystack.co";
export const CURRENCIES = new Set(["NGN", "GHS", "ZAR", "KES", "USD"]);
const INTERVALS = /^(day|daily|week|weekly|month|monthly|year|yearly|annual)$/i;
const REF_RE = /^gp_[a-f0-9]{32}$/;

export const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
export const json = (body: unknown, status = 200, extra: Record<string, string> = {}) =>
  new Response(JSON.stringify(body), { status, headers: { ...CORS, "Content-Type": "application/json", ...extra } });

export type Env = { secret: string; appUrl: string; walletCurrency: string; minTopup: number; maxTopup: number };

export function loadEnv(get: (k: string) => string | undefined): { env?: Env; message?: string } {
  const secret = (get("PAYSTACK_SECRET_KEY") || "").trim();
  if (!/^sk_(live|test)_[A-Za-z0-9]+$/.test(secret)) return { message: "PAYSTACK_SECRET_KEY secret is missing or malformed." };
  const appUrl = (get("APP_URL") || "").trim();
  if (!/^https:\/\/[^\s]+$/.test(appUrl) && !/^http:\/\/localhost(:\d+)?(\/|$)/.test(appUrl)) return { message: "APP_URL secret must be the https URL of your app." };
  const walletCurrency = (get("WALLET_CURRENCY") || "NGN").trim().toUpperCase();
  if (!CURRENCIES.has(walletCurrency)) return { message: "WALLET_CURRENCY is not a supported currency." };
  const minTopup = Number(get("MIN_TOPUP") || 100), maxTopup = Number(get("MAX_TOPUP") || 1000000);
  if (!(minTopup > 0) || !(maxTopup >= minTopup)) return { message: "MIN_TOPUP / MAX_TOPUP are invalid." };
  return { env: { secret, appUrl, walletCurrency, minTopup, maxTopup } };
}

export async function hmacSha512Hex(secret: string, data: Uint8Array): Promise<string> {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-512" }, false, ["sign"]);
  const sig = new Uint8Array(await crypto.subtle.sign("HMAC", key, data));
  return [...sig].map((b) => b.toString(16).padStart(2, "0")).join("");
}
export function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}

export type Deps = { admin: any; env: Env; fetchFn?: typeof fetch };

async function ps(deps: Deps, path: string, init: RequestInit = {}): Promise<{ status: number; body: any }> {
  try {
    const r = await (deps.fetchFn || fetch)(PAYSTACK_BASE + path, {
      ...init,
      headers: { Authorization: `Bearer ${deps.env.secret}`, "Content-Type": "application/json", ...(init.headers || {}) },
    });
    let body: any = null;
    try { body = await r.json(); } catch (_) { /* non-JSON */ }
    return { status: r.status, body };
  } catch (_) {
    return { status: 0, body: null };
  }
}

// Resolves the signed-in user from the request's JWT. Fails closed.
export async function authUser(admin: any, req: Request): Promise<{ id: string; email: string } | null> {
  const token = (req.headers.get("Authorization") || "").replace(/^Bearer\s+/i, "");
  if (!token) return null;
  const { data, error } = await admin.auth.getUser(token);
  if (error || !data?.user?.id || !data.user.email) return null;
  const { data: prof } = await admin.from("profiles").select("disabled").eq("id", data.user.id).maybeSingle();
  if (prof?.disabled) return null;
  return { id: data.user.id, email: data.user.email };
}

// ---------- 1. Initialize ----------
export async function initPayment(deps: Deps, user: { id: string; email: string }, body: any): Promise<Response> {
  const { admin, env } = deps;
  let amountMinor = 0, currency = "", planId: string | null = null;
  const purpose = body?.purpose;

  if (purpose === "wallet_topup") {
    const amt = Number(body.amount);
    if (!Number.isFinite(amt) || amt < env.minTopup || amt > env.maxTopup) {
      return json({ error: "bad_amount", message: `Enter an amount between ${env.minTopup} and ${env.maxTopup} ${env.walletCurrency}.` }, 400);
    }
    amountMinor = Math.round(amt * 100);
    if (Math.abs(amt * 100 - amountMinor) > 1e-6) return json({ error: "bad_amount", message: "Use at most 2 decimal places." }, 400);
    currency = env.walletCurrency;
    if (body.currency && String(body.currency).toUpperCase() !== currency) {
      return json({ error: "currency_mismatch", message: `Wallet top-ups are in ${currency}.` }, 400);
    }
  } else if (purpose === "plan") {
    // Price and currency ALWAYS come from the database, never from the browser.
    const { data: plan } = await admin.from("plans").select("*").eq("id", String(body.plan_id ?? "")).eq("active", true).maybeSingle();
    if (!plan) return json({ error: "plan_not_found", message: "That plan is not available." }, 404);
    amountMinor = Math.round(Number(plan.price) * 100);
    currency = String(plan.currency || "").toUpperCase();
    if (!(amountMinor > 0)) return json({ error: "plan_unpriced", message: "This plan has no price set." }, 400);
    if (!CURRENCIES.has(currency)) return json({ error: "plan_currency", message: `Plan currency ${currency || "(none)"} is not supported for payment.` }, 400);
    if (!INTERVALS.test(String(plan.interval || "").trim())) return json({ error: "plan_interval", message: "This plan's billing interval is not supported." }, 400);
    planId = String(plan.id);
  } else {
    return json({ error: "bad_request", message: "Unknown payment purpose." }, 400);
  }

  // Cheap abuse guard: too many unfinished payments in the last hour.
  const since = new Date(Date.now() - 3600_000).toISOString();
  const { count } = await admin.from("payments").select("id", { count: "exact", head: true })
    .eq("user_id", user.id).eq("status", "pending").gte("created_at", since);
  if ((count ?? 0) >= 10) return json({ error: "too_many", message: "Too many unfinished payments. Try again later." }, 429);

  const reference = "gp_" + crypto.randomUUID().replaceAll("-", "");
  const ins = await admin.from("payments").insert({ reference, user_id: user.id, purpose, plan_id: planId, amount_minor: amountMinor, currency, status: "pending" });
  if (ins.error) { console.error("payments insert failed", ins.error.message); return json({ error: "db", message: "Could not start payment." }, 500); }

  const r = await ps(deps, "/transaction/initialize", {
    method: "POST",
    body: JSON.stringify({
      email: user.email, amount: amountMinor, currency, reference, callback_url: deps.env.appUrl,
      metadata: { user_id: user.id, purpose, plan_id: planId, app: "global-play" },
    }),
  });
  const d = r.body?.data;
  if (r.status !== 200 || !r.body?.status || !d?.authorization_url) {
    console.error("paystack initialize failed", r.status, r.body?.message);
    await admin.from("payments").update({ status: "failed", note: "initialize failed" }).eq("reference", reference);
    return json({ error: "paystack", message: "Could not start payment. Please try again." }, 502);
  }
  await admin.from("payments").update({ access_code: d.access_code ?? null }).eq("reference", reference);
  return json({ authorization_url: d.authorization_url, access_code: d.access_code, reference, currency, amount_minor: amountMinor });
}

// ---------- shared: confirm with Paystack, then settle ----------
// Returns { status: 'success'|'pending'|'failed'|'abandoned'|'review'|'unknown' } or { error } when Paystack/DB is unavailable.
export async function confirmAndSettle(deps: Deps, reference: string): Promise<{ status: string } | { error: string }> {
  const r = await ps(deps, `/transaction/verify/${encodeURIComponent(reference)}`);
  if (r.status === 404) return { status: "unknown" };
  if (r.status !== 200 || !r.body?.status || !r.body.data) return { error: "paystack_unavailable" };
  const d = r.body.data;
  if (d.reference !== reference) return { status: "unknown" };

  if (d.status === "success") {
    const { data, error } = await deps.admin.rpc("settle_payment", {
      p_reference: reference, p_amount_minor: d.amount, p_currency: d.currency, p_channel: d.channel ?? null, p_paid_at: d.paid_at ?? null,
    });
    if (error) { console.error("settle_payment failed", error.message); return { error: "db" }; }
    if (data === "credited" || data === "already") return { status: "success" };
    if (data === "unknown") return { status: "unknown" };
    return { status: "review" };            // 'mismatch' | 'review'
  }
  if (d.status === "failed" || d.status === "abandoned") {
    await deps.admin.from("payments").update({ status: d.status }).eq("reference", reference).eq("settled", false);
    return { status: d.status };
  }
  return { status: "pending" };             // ongoing / pending / processing / queued
}

// ---------- 2. Verify (called by the browser after Paystack redirects back) ----------
export async function verifyPayment(deps: Deps, user: { id: string }, body: any): Promise<Response> {
  const reference = String(body?.reference ?? "");
  if (!REF_RE.test(reference)) return json({ error: "bad_reference", message: "Invalid payment reference." }, 400);
  const { data: p } = await deps.admin.from("payments").select("reference,purpose,settled,status").eq("reference", reference).eq("user_id", user.id).maybeSingle();
  if (!p) return json({ error: "not_found", message: "Payment not found." }, 404);          // also covers other users' references
  if (p.settled) return json({ status: "success", purpose: p.purpose });
  const res = await confirmAndSettle(deps, reference);
  if ("error" in res) return json({ error: res.error, message: "Could not confirm the payment yet. Try again in a moment." }, 502);
  return json({ status: res.status, purpose: p.purpose });
}

// ---------- 3. Webhook ----------
export async function handleWebhook(deps: Deps, raw: Uint8Array, signature: string | null): Promise<Response> {
  if (!signature) return new Response("missing signature", { status: 401 });
  const expected = await hmacSha512Hex(deps.env.secret, raw);
  if (!timingSafeEqual(expected, signature.trim().toLowerCase())) return new Response("bad signature", { status: 401 });

  let evt: any;
  try { evt = JSON.parse(new TextDecoder().decode(raw)); } catch (_) { return new Response("ok", { status: 200 }); }
  if (evt?.event !== "charge.success") return new Response("ignored", { status: 200 });
  const ref = String(evt?.data?.reference ?? "");
  if (!REF_RE.test(ref)) return new Response("ignored", { status: 200 });   // not one of our payments

  const res = await confirmAndSettle(deps, ref);                            // never trust the body alone: re-verify with Paystack
  if ("error" in res) return new Response("retry", { status: 500 });        // non-200 => Paystack retries (3 min x4, then hourly for 72h)
  return new Response("ok", { status: 200 });
}
