"""Public presentation. No database, payment, environment or scanner imports."""
import base64
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def plan_limits():
    """Read the existing quota function without importing/executing the app."""
    import ast
    tree = ast.parse((ROOT / "app.py").read_text(encoding="utf-8-sig"))
    function = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                    and node.name == "limite_objetivos_unicos_plan")
    limits = {}
    for node in function.body:
        if isinstance(node, ast.If) and isinstance(node.test, ast.Compare):
            limits[ast.literal_eval(node.test.comparators[0])] = ast.literal_eval(node.body[0].value)
        elif isinstance(node, ast.Return):
            limits["Basic"] = ast.literal_eval(node.value)
    if set(limits) != {"Basic", "Pro", "Enterprise"}:
        raise ValueError("Unrecognized plan quota configuration")
    return limits


def document(language="es", app_path="/"):
    folder = ROOT / "landing"
    translations = json.loads((folder / "translations.json").read_text(encoding="utf-8"))
    language = language if language in translations else "es"
    content = (folder / "index.html").read_text(encoding="utf-8")
    from html import escape
    content = content.replace('href="?', 'href="' + escape(app_path, quote=True) + '?')
    demo = json.loads((folder / "demo.json").read_text(encoding="utf-8"))
    critical, medium = demo["critical_count"], demo["medium_count"]
    score = max(5, min(100, 100 - critical * 15 - medium * 7))
    limits = plan_limits()
    values = {"critical_count": critical, "medium_count": medium, "demo_score": score,
              "demo_risk": translations[language]["optimal" if score >= 80 else "moderate" if score >= 50 else "critical_label"],
              "basic_quota": limits["Basic"], "pro_quota": limits["Pro"],
              "finding_scale_max":demo["finding_scale_max"],
              "critical_width": min(100, critical / demo["finding_scale_max"] * 100),
              "medium_width": min(100, medium / demo["finding_scale_max"] * 100)}
    for key, value in translations[language].items():
        content = content.replace("{{" + key + "}}", escape(value, quote=True))
    for key, value in values.items():
        content = content.replace("{{" + key + "}}", str(value))
    logo = base64.b64encode((ROOT / "logo.png.png").read_bytes()).decode("ascii")
    hero_logo = base64.b64encode((ROOT / "assets" / "vulnscan-logo-clean.png").read_bytes()).decode("ascii")
    result = (content.replace("{{lang}}", language)
            .replace("{{logo}}", "data:image/png;base64," + logo)
            .replace("{{hero_logo}}", "data:image/png;base64," + hero_logo)
            .replace("{{css}}", (folder / "style.css").read_text(encoding="utf-8"))
            .replace("{{js}}", (folder / "motion.js").read_text(encoding="utf-8")))
    import re
    unresolved = sorted(set(re.findall(r"\{\{([A-Za-z_][A-Za-z0-9_]*)\}\}", result)))
    if unresolved:
        raise ValueError("Unresolved landing template: " + ", ".join(unresolved))
    return result


def public_entry(st):
    # Existing authenticated sessions and external payment/legal returns keep their path.
    if (st.session_state.get("usuario_autenticado") or st.session_state.get("sb_access_token")
            or st.query_params.get("vista") == "acceso"
            or st.query_params.get("pago") or st.query_params.get("terms")):
        return
    language = st.query_params.get("lang", st.session_state.get("_vs_lang", "es"))
    language = language if language in ("es", "en") else "es"
    st.session_state["_vs_lang"] = language
    st.set_page_config(page_title="VulnScan · Security intelligence", layout="wide")
    st.markdown("""<style>
    [data-testid="stHeader"], [data-testid="stSidebar"] {display:none}
    .block-container {padding:0!important;max-width:none!important}
    [data-testid="stAppViewContainer"] {background:#080f1b}
    iframe {height:100dvh!important;display:block}
    </style>""", unsafe_allow_html=True)
    import streamlit.components.v1 as components
    from urllib.parse import urlsplit
    app_path = urlsplit(st.context.url or "/").path or "/"
    presentation = components.declare_component("vulnscan_public_v2", path=str(ROOT / "landing" / "component"))
    selected = presentation(documents={lang: document(lang, app_path) for lang in ("es", "en")},
                            language=language, default=language, key="vulnscan_public")
    if selected in ("es", "en") and selected != language:
        st.session_state["_vs_lang"] = selected
        st.query_params["lang"] = selected
        st.rerun()
    st.stop()
