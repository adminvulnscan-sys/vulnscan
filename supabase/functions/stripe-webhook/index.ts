import { createClient } from "npm:@supabase/supabase-js@2";

const supabaseUrl = Deno.env.get("SUPABASE_URL")!;
const supabaseKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const stripeWebhookSecret = Deno.env.get("STRIPE_WEBHOOK_SECRET")!;

async function verifyStripeSignature(body: string, signature: string, secret: string): Promise<boolean> {
  try {
    const parts = signature.split(",").reduce((acc: Record<string, string>, part) => {
      const [key, value] = part.split("=");
      acc[key] = value;
      return acc;
    }, {});

    const timestamp = parts["t"];
    const sig = parts["v1"];
    const payload = `${timestamp}.${body}`;

    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );

    const signatureBytes = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(payload));
    const expectedSig = Array.from(new Uint8Array(signatureBytes)).map(b => b.toString(16).padStart(2, "0")).join("");

    return expectedSig === sig;
  } catch {
    return false;
  }
}

Deno.serve(async (req) => {
  const body = await req.text();
  const signature = req.headers.get("stripe-signature") || "";

  const isValid = await verifyStripeSignature(body, signature, stripeWebhookSecret);
  if (!isValid) {
    return new Response("Invalid signature", { status: 400 });
  }

  const event = JSON.parse(body);
  const supabase = createClient(supabaseUrl, supabaseKey);

  if (event.type === "checkout.session.completed") {
    const session = event.data.object;
    const email = session.customer_email
      || session.metadata?.email
      || session.customer_details?.email;
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
      const { data } = await supabase.from("usuarios").select("tokens_pdf").eq("email", email).single();
      const tokens = (data?.tokens_pdf || 0) + 1;
      await supabase.from("usuarios").upsert({ email, tokens_pdf: tokens });
    }
  }

  if (event.type === "customer.subscription.deleted") {
    const email = event.data.object.metadata?.email;
    if (email) {
      await supabase.from("usuarios").update({ plan_activo: "Basic" }).eq("email", email);
    }
  }

  return new Response(JSON.stringify({ received: true }), {
    headers: { "Content-Type": "application/json" },
  });
});