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
    if getattr(result, 'unavailable', False):
        return  # Normal authenticated login; Checkout proves no identity.
    if getattr(result, 'resumed', False):
        ui.stop()
        return
    # The creator closes the returning popup before app startup where possible.
    # The backup notification never renders a message or claims authentication.
    ui.stop()
