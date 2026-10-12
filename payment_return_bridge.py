"""Reconnect the navigation to the existing tab, never transfer authentication."""
from pathlib import Path
import streamlit as st

_bridge = st.components.v2.component('vulnscan_payment_return',
    js=Path(__file__).with_suffix('.mjs').read_text(encoding='utf-8'))


def listen(ui, checkout, role):
    return _bridge(key='billing_return_' + role,
        data={'checkout': checkout, 'role': role}, height=0,
        on_returned_change=lambda: None,
        on_resumed_change=lambda: None,
        on_unavailable_change=lambda: None)


def show_return(ui, checkout):
    result = listen(ui, checkout, 'return')
    english = ui.session_state.get('_vs_lang') == 'en'
    if getattr(result, 'unavailable', False):
        ui.info('The original session could not be reached. Sign in to continue.' if english else
                'No se ha podido recuperar la pestaña original. Inicia sesión para continuar.')
        return  # Normal authenticated login; Checkout proves no identity.
    if getattr(result, 'resumed', False):
        ui.info('Continue in your original VulnScan tab. You can close this tab.' if english else
                'Continúa en tu pestaña original de VulnScan. Puedes cerrar esta pestaña.')
    else:
        ui.info('Returning to your open VulnScan session…' if english else
                'Volviendo a tu sesión abierta de VulnScan…')
    ui.stop()
