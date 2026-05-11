import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const supabaseUrl = Deno.env.get("SUPABASE_URL")!;
const supabaseKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const stripeWebhookSecret = Deno.env.get("STRIPE_WEBHOOK_SECRET")!;

serve(async (req) => {
  const body = await req.text();
  const signature = req.headers.get("stripe-signature");

  let event;
  try {
    const { Stripe } = await import("https://esm.sh/stripe@12");
    const stripe = new Stripe(Deno.env.get("STRIPE_SECRET_KEY")!, { apiVersion: "2023-10-16" });
    event = stripe.webhooks.constructEvent(body, signature!, stripeWebhookSecret);
  } catch (err) {
    return new Response(`Webhook error: ${err.message}`, { status: 400 });
  }

  const supabase = createClient(supabaseUrl, supabaseKey);

  if (event.type === "checkout.session.completed") {
    const session = event.data.object;
    const email = session.customer_email || session.metadata?.email;
    const tipo = session.metadata?.tipo;

    if (!email) return new Response("No email", { status: 400 });

    if (tipo === "pro_recurrente") {
      await supabase.from("usuarios").upsert({ email, plan_activo: "Pro" });
    } else if (tipo === "enterprise_recurrente") {
      await supabase.from("usuarios").upsert({ email, plan_activo: "Enterprise" });
    } else if (tipo === "pro_unico") {
      const { data } = await supabase.from("usuarios").select("tokens_pro").eq("email", email).single();
      const tokens = (data?.tokens_pro || 0) + 1;
      await supabase.from("usuarios").upsert({ email, tokens_pro: tokens });
    } else if (tipo === "enterprise_unico") {
      const { data } = await supabase.from("usuarios").select("tokens_ent").eq("email", email).single();
      const tokens = (data?.tokens_ent || 0) + 1;
      await supabase.from("usuarios").upsert({ email, tokens_ent: tokens });
    } else if (tipo === "pdf_unico") {
      // PDF descargado, no necesita actualizar tokens
    }
  }

  if (event.type === "customer.subscription.deleted") {
    const subscription = event.data.object;
    const email = subscription.metadata?.email;
    if (email) {
      await supabase.from("usuarios").update({ plan_activo: "Basic" }).eq("email", email);
    }
  }

  return new Response(JSON.stringify({ received: true }), {
    headers: { "Content-Type": "application/json" },
  });
});