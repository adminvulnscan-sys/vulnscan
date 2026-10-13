"""Temporary replacement for app.py during the scan-reservation migration.

Publish this file's content as app.py only for the maintenance release.
Do not overwrite the pending full app.py in the local working tree.
After deployment, REBOOT the existing Streamlit app before installing SQL.
"""
import streamlit as st

st.set_page_config(page_title="VulnScan · Mantenimiento", page_icon="🛡️")
st.title("VulnScan")
st.info("Mantenimiento breve. Estamos actualizando la gestión de escaneos. "
        "Vuelve en unos minutos. / Brief maintenance. Please return shortly.")
st.stop()
