"""One-click external Stripe tab, opened during the actual user gesture."""
import hashlib
from pathlib import Path
from uuid import UUID, uuid4
from urllib.parse import urlsplit

import streamlit as st
from billing import CheckoutIntentClosed

_bridge = st.components.v2.component(
    'vulnscan_stripe_navigation',
    js=Path(__file__).with_suffix('.mjs').read_text(encoding='utf-8'),
)


def intent_bridge(**kwargs):
    return _bridge(**kwargs)


def stripe_action(ui, *, label, key, scope, create, on_error, **options):
    """No Stripe call on rendering; retries use the browser's stable attempt ID."""
    scope_hash = hashlib.sha256(scope.encode()).hexdigest()
    pending_key = '_stripe_redirect_' + key
    pending = ui.session_state.pop(pending_key, {})
    bridge_key = 'stripe_bridge_' + key
    known_intent = ui.session_state.get(bridge_key, {}).get('intent')
    result = intent_bridge(key=bridge_key,
        data={'scope': scope_hash, 'button_key': key, 'known_intent': known_intent,
              'language': ui.session_state.get('_vs_lang', 'es'), **pending}, height=0,
        on_intent_change=lambda: None, on_redirect_error_change=lambda: None)
    if getattr(result, 'redirect_error', False):
        ui.error('No se pudo abrir Stripe. Permite las ventanas emergentes de esta web y vuelve a pulsar el mismo botón.'
                 if ui.session_state.get('_vs_lang', 'es') != 'en' else
                 'Could not open Stripe. Allow pop-ups for this website and click the same button again.')
    intent = pending.get('rotate') or getattr(result, 'intent', None)
    try:
        intent = str(UUID(intent))
    except (ValueError, TypeError, AttributeError):
        intent = None
    disabled = bool(options.pop('disabled', False)) or intent is None
    if not ui.button(label, key=key, disabled=disabled, **options):
        return
    try:
        rotated = None
        try:
            url = create('vs-' + scope_hash + '-' + intent)
        except CheckoutIntentClosed:
            # An intentionally new purchase after the previous one completed/expired.
            rotated = str(uuid4())
            # Persist BEFORE retrying so an uncertain response keeps the same new key.
            ui.session_state[pending_key] = {'rotate': rotated}
            url = create('vs-' + scope_hash + '-' + rotated)
        target = urlsplit(url)
        if (target.scheme != 'https' or target.hostname not in ('checkout.stripe.com', 'billing.stripe.com')
                or target.username or target.password or target.port):
            raise ValueError('Unapproved Stripe destination')
        ui.session_state[pending_key] = {'url': url, 'navigation': str(uuid4())}
        if rotated:
            ui.session_state[pending_key]['rotate'] = rotated
        ui.rerun()
    except Exception as error:
        on_error(error)
        # Deliver failure to the already-mounted bridge without hiding the error.
        intent_bridge(key='stripe_failure_' + key,
            data={'scope': scope_hash, 'failed': True}, height=0,
            on_intent_change=lambda: None, on_redirect_error_change=lambda: None)
