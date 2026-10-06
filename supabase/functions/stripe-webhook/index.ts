import { createClient } from "npm:@supabase/supabase-js@2";
import catalogDefaults from "../_shared/billing_catalog.json" with { type: "json" };
import { processEvent, verifySignature, stripeReader } from "./core.mjs";

Deno.serve(async (req) => {
  if (req.method !== "POST") return new Response("Method not allowed", { status: 405 });
  const secret = Deno.env.get("STRIPE_WEBHOOK_SECRET");
  const stripeKey = Deno.env.get("STRIPE_SECRET_KEY");
  const url = Deno.env.get("SUPABASE_URL");
  const key = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  if (!secret || !stripeKey || !url || !key) return new Response("Not configured", { status: 503 });
  const body = await req.text();
  if (!await verifySignature(body, req.headers.get("stripe-signature"), secret))
    return new Response("Invalid signature", { status: 400 });
  let event;
  try { event = JSON.parse(body); } catch { return new Response("Invalid JSON", { status: 400 }); }
  const db = createClient(url, key, { auth: { persistSession: false, autoRefreshToken: false } });
  async function rpc(name: string, args: Record<string, unknown>) {
    const { data, error } = await db.rpc(name, args);
    if (error) throw new Error("Billing database operation failed");
    return data;
  }
  const catalog = Object.fromEntries(Object.entries(catalogDefaults).map(([type, entry]) =>
    [type, { ...entry, price: Deno.env.get(`STRIPE_PRICE_${type.toUpperCase()}`) || entry.price }]));
  try {
    const result = await processEvent(event, {
      catalog, liveMode: Deno.env.get("STRIPE_LIVEMODE") === "true",
      stripe: stripeReader(stripeKey),
      store: {
        claim: (user: string, eventId: string) => rpc("billing_claim", { p_user: user, p_event: eventId }),
        release: (user: string, token: string) => rpc("billing_release", { p_user: user, p_token: token }),
        apply: (update: Record<string, unknown>) => rpc("billing_apply", { p_update: update }),
      },
    });
    return Response.json(result);
  } catch {
    return new Response("Billing processing failed; retry or reconcile", { status: 500 });
  }
});
