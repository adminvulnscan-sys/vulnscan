"""Supported private Streamlit language picker; public landing is unchanged."""
from pathlib import Path
import streamlit.components.v1 as components

_picker = components.declare_component("vulnscan_panel_language", path=str(Path(__file__).parent / "panel_language"))

def language_picker(language):
    return _picker(language=language, default=None, key="panel_language")
