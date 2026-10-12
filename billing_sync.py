"""Read-only billing observation; no Stripe client or entitlement writes."""
import time
import re
from billing import authenticated_user, effective_plan

FIELDS = ('plan_activo', 'billing_status', 'billing_period_end', 'fecha_vencimiento',
          'cancelacion_pendiente', 'tokens_pro', 'tokens_ent', 'tokens_pdf')


def start_wait(state, email, checkout=None, now=None):
    now = time.time() if now is None else now
    if checkout is not None and not re.fullmatch(r'cs_[A-Za-z0-9_]{1,252}', checkout):
        raise ValueError('Invalid Checkout identifier')
    old = state.get('_billing_wait')
    if old and old['email'] == email and old['checkout'] == checkout and old['deadline'] > now:
        return  # Re-rendering/double clicks do not extend the wait indefinitely.
    state['_billing_wait'] = {'email': email, 'checkout': checkout, 'deadline': now + 120}
    state['_billing_sync_status'] = 'processing'
    state.pop('_billing_last_poll', None)


def poll(state, client, now=None):
    now = time.time() if now is None else now
    email = state.get('email_usuario')
    if not state.get('usuario_autenticado') or not email:
        return False
    pending = state.get('_billing_wait')
    if pending and pending['email'] != email:
        state.pop('_billing_wait', None)
        state.pop('_billing_sync_status', None)
        pending = None
    active = pending and pending['deadline'] > now
    interval = 5 if active else 30
    if now - state.get('_billing_last_poll', float('-inf')) < interval:
        return False
    state['_billing_last_poll'] = now
    before_status = state.get('_billing_sync_status')
    if pending and not active:
        state['_billing_sync_status'] = 'timeout'
        state.pop('_billing_wait', None)
    try:
        authenticated_user(client, email)
        result = client.rpc('billing_sync_status', {
            'p_checkout': pending['checkout'] if active else None}).execute().data
        if not isinstance(result, dict) or not isinstance(result.get('profile'), dict):
            raise ValueError('Invalid server snapshot')
        profile = result['profile']
        if profile.get('email') != email or any(k not in profile for k in FIELDS):
            raise ValueError('Invalid profile identity or fields')
        profile = dict(profile)
        profile['plan_activo'] = effective_plan(client, profile, now=now)
        values = {k: profile[k] for k in FIELDS}
        # Keep an independently confirmed cancellation during webhook delivery.
        confirmed = state.get('_renewal_confirmed')
        if confirmed and confirmed['email'] == email and confirmed['expires'] > now:
            if (profile['cancelacion_pendiente'] == confirmed['cancelacion_pendiente']
                    and profile['fecha_vencimiento'] == confirmed['fecha_vencimiento']):
                state.pop('_renewal_confirmed', None)
            else:
                for key in ('cancelacion_pendiente', 'fecha_vencimiento'):
                    values[key] = confirmed[key]
        changed = any(state.get(k) != v for k, v in values.items())
        state.update(values)
        state['_credit_row'] = {k: profile[k] for k in ('email','tokens_pro','tokens_ent','tokens_pdf')}
        if active and pending['checkout'] and result.get('checkout_applied') is True:
            state['_billing_sync_status'] = 'confirmed'
            state['_billing_notice_until'] = now + 20
            state.pop('_billing_wait', None)
        elif active and pending['checkout'] is None and changed:
            # A profile change is not proof of a particular purchase.
            state['_billing_sync_status'] = 'updated'
            state['_billing_notice_until'] = now + 20
            state.pop('_billing_wait', None)
        elif not pending and before_status == 'unavailable':
            state.pop('_billing_sync_status', None)
        return changed or state.get('_billing_sync_status') != before_status
    except Exception:
        # Never expose SDK/SQL errors, account identifiers or secret values.
        state['_billing_sync_status'] = 'unavailable' if not pending else (
            'processing' if active else 'timeout')
        return state.get('_billing_sync_status') != before_status


def monitor(ui, client):
    @ui.fragment(run_every='5s')
    def render():
        if poll(ui.session_state, client):
            ui.rerun(scope='app')
        status = ui.session_state.get('_billing_sync_status')
        if status in ('confirmed', 'updated') and time.time() > ui.session_state.get('_billing_notice_until', 0):
            ui.session_state.pop('_billing_sync_status', None)
            ui.session_state.pop('_billing_notice_until', None)
            status = None
        english = ui.session_state.get('_vs_lang') == 'en'
        messages = {
            'processing': ('Procesando. Esperando la confirmación del servidor…', 'Processing. Waiting for server confirmation…'),
            'confirmed': ('Compra confirmada por el servidor. Datos actualizados.', 'Purchase confirmed by the server. Account updated.'),
            'updated': ('Datos de facturación actualizados desde el servidor.', 'Billing details updated from the server.'),
            'timeout': ('La confirmación está tardando. No repitas la compra; el saldo se actualizará cuando llegue al servidor.', 'Confirmation is taking longer. Do not repeat the purchase; your balance will update when the server receives it.'),
            'unavailable': ('No se puede comprobar la facturación ahora. No se ha confirmado ninguna compra.', 'Billing cannot be checked right now. No purchase has been confirmed.'),
        }
        if status in messages:
            show = ui.success if status in ('confirmed', 'updated') else ui.info
            show(messages[status][english])
    render()
