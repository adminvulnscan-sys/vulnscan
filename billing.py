"""Operaciones de facturación sin interfaz ni asignación local de créditos."""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
from uuid import uuid4
import logging
import time
from urllib.parse import urlencode, urlsplit, urlunsplit


PUBLIC_APP_URL = 'https://vulnscan-kckbqnppvww5b4g8bseevs.streamlit.app/'


def payment_return_url(outcome=None, language='es'):
    """Billing returns to the actual app, independently of the marketing APP_URL."""
    base = os.environ.get('BILLING_RETURN_URL', PUBLIC_APP_URL).strip()
    target = urlsplit(base)
    local_http = target.scheme == 'http' and target.hostname in ('localhost', '127.0.0.1', '::1')
    if (not target.hostname or (target.scheme != 'https' and not local_http)
            or target.username or target.password or target.query or target.fragment
            or '/~/' in target.path or any(c.isspace() for c in base)):
        raise ValueError('Invalid billing return URL')
    # Validate the port as well; malformed values must fail before creating Checkout.
    _ = target.port
    query = {'vista': 'acceso', 'lang': language if language in ('es', 'en') else 'es'}
    if outcome is not None:
        if outcome not in ('exitoso', 'cancelado'):
            raise ValueError('Invalid payment return outcome')
        query['pago'] = outcome
        if outcome == 'exitoso':
            query['session_id'] = '{CHECKOUT_SESSION_ID}'
    return urlunsplit((target.scheme, target.netloc, target.path.rstrip('/') + '/',
                      urlencode(query, safe='{}'), ''))


class CheckoutIntentClosed(Exception):
    """The existing attempt was completed/expired; a new deliberate click may renew it."""


def stripe_idempotency(user_id, intent, payload):
    import hashlib
    encoded = json.dumps([str(user_id), intent, payload], sort_keys=True, separators=(',', ':'))
    return 'vulnscan-' + hashlib.sha256(encoded.encode()).hexdigest()


def effective_plan(client, profile, now=None):
    """Resolve access without changing stored plan, credits or Stripe state."""
    now = time.time() if now is None else now
    plan = "Basic"
    try:
        if (profile.get("plan_activo") in ("Pro", "Enterprise")
                and profile.get("billing_status") == "active"
                and int(profile.get("billing_period_end") or 0) > now):
            plan = profile["plan_activo"]
    except (TypeError, ValueError):
        pass
    try:
        authenticated_user(client, profile.get("email"))
        grant = client.rpc("billing_internal_access", {}).execute().data
        if (isinstance(grant, dict) and grant.get("plan") == "Enterprise"
                and grant.get("source") == "internal_test"
                and "expires_at" in grant
                and (grant["expires_at"] is None or float(grant["expires_at"]) > now)):
            return "Enterprise"
    except Exception as exc:
        # No exception payload, email, UID, credentials or grant details in logs.
        logging.getLogger(__name__).warning("Internal access lookup unavailable: %s", type(exc).__name__)
    return plan


def price_catalog():
    catalog = json.loads((Path(__file__).parent / "supabase/functions/_shared/billing_catalog.json").read_text())
    return {kind: os.getenv("STRIPE_PRICE_" + kind.upper(), item["price"])
            for kind, item in catalog.items()}


def require_public_key(key):
    if not key or key.startswith("sb_secret_"):
        raise ValueError("La interfaz requiere una clave pública Supabase")
    if key.count(".") == 2:
        import base64
        payload = key.split(".")[1]
        role = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))).get("role")
        if role != "anon":
            raise ValueError("La interfaz requiere una clave anon, nunca service_role")
    return key


def session_client(state, factory):
    if "_supabase_client" not in state:
        state["_supabase_client"] = factory()
    return state["_supabase_client"]


def authenticated_user(client, email):
    user = client.auth.get_user().user
    if not user or not user.email or user.email != email:
        raise ValueError("La sesión no corresponde al usuario")
    return user


def refresh_payment_return(client, email, load_profile, restore_scan):
    authenticated_user(client, email)
    load_profile(email)
    restore_scan(email)


def spend_credit(client, credit, operation):
    result = client.rpc("billing_spend", {"p_credit": credit, "p_operation": operation}).execute().data
    if not isinstance(result, dict) or not isinstance(result.get("remaining"), int):
        raise ValueError("No se confirmó el consumo del crédito")
    return result["remaining"]


class ScanBusy(ValueError):
    pass


def pending_scan_credit(state, target, scan_type):
    pending = state.get("_scan_credit_pending")
    if not pending:
        return None
    for credit in ("tokens_pro", "tokens_ent"):
        if tuple(pending["identity"]) == (state.get("email_usuario"), credit, target, scan_type):
            return credit
    return None


def begin_scan(state, client, credit, target, scan_type):
    """Claim the session BEFORE spending; retry an uncertain RPC with the same ID."""
    if state.get("escaneo_en_curso"):
        raise ScanBusy("Ya hay un escaneo en curso")
    state["escaneo_en_curso"] = True
    try:
        identity = (state.get("email_usuario"), credit, target, scan_type)
        pending = state.get("_scan_credit_pending")
        if pending and tuple(pending["identity"]) != identity:
            raise ValueError("Hay un consumo pendiente para otro objetivo; reintenta el anterior")
        if credit:
            if not pending:
                pending = {"identity": identity, "operation": str(uuid4())}
                state["_scan_credit_pending"] = pending
            state[credit] = spend_credit(client, credit, pending["operation"])
    except BaseException:
        state["escaneo_en_curso"] = False
        raise


def finish_scan(state, completed=False):
    state["escaneo_en_curso"] = False
    if completed:
        state.pop("_scan_credit_pending", None)


def customer_portal(stripe, client, email, return_url, idempotency_key=None):
    user = authenticated_user(client, email)
    rows = client.table("usuarios").select("stripe_customer_id").eq("email", user.email).execute().data
    if not rows or not rows[0].get("stripe_customer_id"):
        raise ValueError("No hay un cliente Stripe vinculado")
    params = dict(customer=rows[0]["stripe_customer_id"], return_url=return_url)
    if idempotency_key:
        params['idempotency_key'] = stripe_idempotency(user.id, idempotency_key, params)
    return stripe.billing_portal.Session.create(**params).url


def change_subscription(stripe, client, email, cancel):
    user = authenticated_user(client, email)
    rows = client.table("usuarios").select(
        "stripe_subscription_id,stripe_customer_id"
    ).eq("email", user.email).execute().data
    if not rows or not rows[0].get("stripe_subscription_id"):
        raise ValueError("No hay una suscripción Stripe vinculada")
    row = rows[0]
    sub = stripe.Subscription.retrieve(row["stripe_subscription_id"])
    if (not row.get("stripe_customer_id")
            or sub.get("customer") != row["stripe_customer_id"]
            or sub.get("metadata", {}).get("user_id") != str(user.id)):
        raise ValueError("No se pudo verificar la titularidad")
    if sub.get("status") not in ("active", "trialing", "past_due"):
        raise ValueError("La suscripción no permite este cambio")
    updated = stripe.Subscription.modify(sub["id"], cancel_at_period_end=bool(cancel))
    if updated.get("cancel_at_period_end") is not bool(cancel):
        raise ValueError("Stripe no confirmó el cambio")
    period = updated.get("current_period_end")
    if not period:
        period = next((item.get("current_period_end") for item in
                       updated.get("items", {}).get("data", [])
                       if item.get("current_period_end")), None)
    return {
        "cancelacion_pendiente": bool(updated["cancel_at_period_end"]),
        "fecha_vencimiento": datetime.fromtimestamp(period, timezone.utc).strftime(
            "%d/%m/%Y") if period else "Pendiente de sincronizar",
    }


def clear_account_state(state):
    """Solo datos de la cuenta al salir; conserva idioma y preferencias visuales."""
    keys = (
        "_supabase_client", "sb_access_token", "sb_refresh_token", "email_usuario",
        "usuario_autenticado", "datos_cliente_cargados", "plan_activo",
        "fecha_vencimiento", "cancelacion_pendiente", "api_key_real",
        "api_key_configurada", "webhook_url", "tokens_pro", "tokens_ent", "tokens_pdf",
        "reporte_pdf_desbloqueado", "token_pdf_descontado", "historial_escaneos",
        "dominios_verificados", "escaneos_realizados", "objetivos_mes_data",
        "historial_dominios_list", "trial_pro_usada", "fecha_inicio_trial",
        "scheduler_activo", "scheduler_passive_on", "scheduler_pro_on",
        "scheduler_enterprise_on", "scheduler_freq_passive", "scheduler_freq_pro",
        "scheduler_freq_enterprise", "resultados_actuales", "dominio_actual",
        "nivel_escaneo_guardado", "dominio_rapido", "escaneo_actual_id",
        "escaneo_actual_fecha", "escaneo_actual_riesgo", "pdf_descarga_habilitada",
        "billing_status", "billing_period_end",
        "escaneo_en_curso", "_scan_credit_pending",
    )
    for key in keys:
        state.pop(key, None)
    for key in list(state):
        if key.startswith('_stripe_redirect_'):
            state.pop(key, None)
