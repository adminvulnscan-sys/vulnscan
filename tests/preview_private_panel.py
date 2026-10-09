"""Isolated preview of actual private section bodies. No .env/auth startup.

Run: python -m streamlit run tests/preview_private_panel.py
All remote reads/writes and scanning are replaced or blocked.
"""
import ast
import base64
import hashlib
import json
import os
from pathlib import Path
import random
import re
import sys
import time
from datetime import datetime
from types import SimpleNamespace
from unittest.mock import patch
from contextlib import ExitStack
import streamlit as st
from fpdf import FPDF
import requests

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from billing import *
from stripe_navigation import stripe_action
import stripe_navigation
if st.query_params.get("real_bridge") != "1":
    stripe_navigation.intent_bridge = lambda **kwargs: SimpleNamespace(
        intent="00000000-0000-4000-8000-000000000099", redirect_error=False)


def blocked(*args, **kwargs):
    raise RuntimeError("Vista aislada: operaciones externas bloqueadas")


class Query:
    def __init__(self, table):
        self.name = table

    def __getattr__(self, method):
        if method in ("insert", "update", "delete", "upsert"):
            return blocked
        if method == "select":
            def select(fields):
                self.fields=fields
                return self
            return select
        return lambda *args, **kwargs: self

    def execute(self):
        if st.session_state.get("preview_schema_missing") and "stripe_customer_id" in getattr(self,"fields",""):
            raise SchemaError()
        return SimpleNamespace(data=[profile] if self.name == "usuarios" else [])


class SchemaError(Exception):
    code="42703"
    def __str__(self): return "column usuarios.stripe_customer_id does not exist; private-token-never-log"

def fake_checkout(**kwargs):
    st.session_state["preview_checkouts"] = st.session_state.get("preview_checkouts",0)+1
    return SimpleNamespace(url="https://checkout.stripe.com/mock-checkout")

class Client:
    auth = SimpleNamespace(get_user=lambda: SimpleNamespace(user=SimpleNamespace(email="cliente@example.invalid", id="00000000-0000-0000-0000-000000000001")), sign_out=lambda: None)
    table = staticmethod(lambda name: Query(name))
    rpc = staticmethod(blocked)


st.set_page_config(layout="wide")
st.caption("Vista local aislada · datos ficticios · servicios externos bloqueados")
plan = st.selectbox("Cuenta de prueba", ("Basic", "Pro", "Enterprise", "Administrador"))
saved = st.checkbox("Mostrar análisis guardado ficticio", value=True)
st.checkbox("Simular esquema sin columnas Stripe", key="preview_schema_missing")
actual_plan = "Enterprise" if plan == "Administrador" else plan
profile = dict(email="cliente@example.invalid", plan_activo=actual_plan, tokens_pro=2, tokens_ent=1, tokens_pdf=1,
               billing_status="active", billing_period_end=int(time.time())+3600,
               objetivos_mes_json=json.dumps({"mes":datetime.now().strftime("%Y-%m"),"dominios":["guardado.example.invalid"]}))
state = st.session_state
state.update(usuario_autenticado=True, email_usuario="cliente@example.invalid", plan_activo=actual_plan,
             tokens_pro=2,tokens_ent=1,tokens_pdf=1, dominios_verificados=[],
             historial_dominios_list=["guardado.example.invalid"], historial_escaneos=[],
             objetivos_mes_data=json.loads(profile["objetivos_mes_json"]), billing_status="active",
             billing_period_end=profile["billing_period_end"], fecha_vencimiento="No disponible")
if saved:
    state.update(resultados_actuales=["[MEDIO] Cabecera CSP ausente", "[INFO] HTTPS disponible"],
                 dominio_actual="guardado.example.invalid", nivel_escaneo_guardado="Rápido (Passive)",
                 escaneo_actual_fecha="07/10/2026",escaneo_actual_id="preview-report")
else:
    state.pop("resultados_actuales", None)
source = (ROOT / "app.py").read_text(encoding="utf-8")
tree = ast.parse(source)
namespace = dict(globals(), __file__=str(ROOT / "app.py"), supabase=Client(),
                 stripe=SimpleNamespace(checkout=SimpleNamespace(Session=SimpleNamespace(create=fake_checkout))), STRIPE_PRICES=price_catalog(), _VS_TRANSLATIONS={})
definitions = [node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.ClassDef))]
exec(compile(ast.Module(body=definitions, type_ignores=[]), str(ROOT / "app.py"), "exec"), namespace)
namespace.update(escanear_objetivo_real=blocked, comprobar_archivo_servidor=blocked,
                 restaurar_ultimo_escaneo_supabase=lambda *args: False,
                 _descargar_pdf_seguro=lambda **kwargs: st.download_button(**kwargs))
# Load actual translations, use actual Checkout code with fake Stripe/Supabase.
for node in tree.body:
    if isinstance(node,ast.Assign) and any(isinstance(t,ast.Name) and t.id=="_VS_TRANSLATIONS" for t in node.targets):
        exec(compile(ast.Module(body=[node],type_ignores=[]),"translations","exec"),namespace)
    if isinstance(node,ast.Expr) and isinstance(node.value,ast.Call) and ast.unparse(node.value.func)=="_VS_TRANSLATIONS.update":
        exec(compile(ast.Module(body=[node],type_ignores=[]),"translations","exec"),namespace)
namespace["_aplicar_fila_usuario_a_sesion"](profile)
private_source = source[source.index('with st.sidebar:\n    if st.button("Cerrar Sesión"):'):]
picker_source = source[source.index('# The private picker'):source.index('# Traducimos únicamente métodos')]
st.session_state.setdefault("_vs_lang","es")
with ExitStack() as patches:
    patches.enter_context(patch("requests.sessions.Session.request",side_effect=blocked))
    for name in ("markdown","write","button","link_button","text_input","text_area","checkbox","radio","selectbox","multiselect","slider","number_input","tabs","expander","caption","subheader","header","title","success","warning","error","info","toast","spinner","status","download_button","form_submit_button","metric"):
        patches.enter_context(patch.object(st,name,namespace["_vs_wrap_streamlit_method"](getattr(st,name))))
    exec(compile(picker_source,str(ROOT / "app.py"),"exec"),namespace)
    exec(compile(private_source,str(ROOT / "app.py"),"exec"),namespace)
