import os
import json
import socket
import requests
from datetime import datetime, timezone, timedelta
from supabase import create_client
from dotenv import load_dotenv

load_dotenv()

# --- Conexión a Supabase ---
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_SERVICE_KEY")  # Service role key, no anon
supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

def debe_escanear_hoy(ultimo_escaneo_fecha, frecuencia_dias):
    """Comprueba si toca escaneo hoy según la frecuencia configurada."""
    if not ultimo_escaneo_fecha or frecuencia_dias == 0:
        return False
    try:
        ultimo = datetime.fromisoformat(ultimo_escaneo_fecha).replace(tzinfo=timezone.utc)
        dias_desde_ultimo = (datetime.now(timezone.utc) - ultimo).days
        return dias_desde_ultimo >= frecuencia_dias
    except Exception:
        return True  # Si no hay fecha, escanear

from motores import _motor_basic_pasivo, _motor_pro_activo, _motor_enterprise_owasp
    """Motor Basic pasivo — DNS, SSL, cabeceras."""
    resultados = []
    try:
        infos = socket.getaddrinfo(dominio, None, type=socket.SOCK_STREAM)
        ips = list(set([x[4][0] for x in infos]))
        resultados.append(f"DNS: {', '.join(ips[:3])}")
    except Exception as e:
        resultados.append(f"DNS error: {e}")

    try:
        r = requests.get(f"https://{dominio}", timeout=5)
        headers = {k.lower(): v for k, v in r.headers.items()}
        if "strict-transport-security" not in headers:
            resultados.append("⚠️ Falta HSTS")
        if "content-security-policy" not in headers:
            resultados.append("⚠️ Falta CSP")
        if "x-frame-options" not in headers:
            resultados.append("⚠️ Falta X-Frame-Options")
    except Exception as e:
        resultados.append(f"HTTP error: {e}")

    return resultados

def enviar_webhook(webhook_url, dominio, resultados, tipo_escaneo):
    """Envía alerta al webhook del cliente."""
    if not webhook_url:
        return
    vulnerabilidades = [r for r in resultados if "⚠️" in r or "🚨" in r]
    if not vulnerabilidades:
        return
    payload = {
        "evento": "escaneo_automatico",
        "dominio": dominio,
        "tipo_escaneo": tipo_escaneo,
        "fecha": datetime.now().strftime("%d/%m/%Y %H:%M"),
        "vulnerabilidades_encontradas": len(vulnerabilidades),
        "detalle": vulnerabilidades
    }
    try:
        requests.post(webhook_url, json=payload, timeout=5)
        print(f"[Webhook] Alerta enviada a {webhook_url} para {dominio}")
    except Exception as e:
        print(f"[Webhook] Error enviando a {webhook_url}: {e}")

def guardar_escaneo_supabase(email, dominio, tipo, resultados):
    """Guarda el escaneo en la tabla escaneos."""
    try:
        supabase.table("escaneos").insert({
            "email_cliente": email,
            "dominio": dominio,
            "tipo": tipo,
            "fecha": datetime.now().strftime("%d/%m/%Y"),
            "riesgo": "Medio",
            "resultados_json": json.dumps(resultados)
        }).execute()
        print(f"[Supabase] Escaneo guardado para {email} - {dominio}")
    except Exception as e:
        print(f"[Supabase] Error guardando escaneo: {e}")

def main():
    print(f"[Scheduler] Iniciando {datetime.now().strftime('%d/%m/%Y %H:%M')}")

    # Obtener todos los usuarios con scheduler activo
    usuarios = supabase.table("usuarios").select("*").eq("scheduler_activo", True).execute()

    if not usuarios.data:
        print("[Scheduler] No hay usuarios con scheduler activo.")
        return

    for usuario in usuarios.data:
        email = usuario.get("email")
        webhook_url = usuario.get("webhook_url", "")
        plan = usuario.get("plan_activo", "Basic")

        print(f"[Scheduler] Procesando usuario: {email} (Plan: {plan})")

        # Obtener dominios verificados del usuario
        dominios = supabase.table("activos_verificados").select("dominio").eq("email_cliente", email).execute()
        if not dominios.data:
            print(f"[Scheduler] {email} no tiene dominios verificados.")
            continue

        # Obtener último escaneo por dominio
        for activo in dominios.data:
            dominio = activo["dominio"]

            ultimo = supabase.table("escaneos").select("fecha").eq("email_cliente", email).eq("dominio", dominio).order("id", desc=True).limit(1).execute()
            ultima_fecha = ultimo.data[0]["fecha"] if ultimo.data else None

            # Escaneo Basic
            if usuario.get("scheduler_passive_on") and usuario.get("scheduler_freq_passive", 0) > 0:
                if debe_escanear_hoy(ultima_fecha, usuario.get("scheduler_freq_passive", 7)):
                    print(f"[Scheduler] Ejecutando Basic para {dominio}")
                    resultados = _motor_basic_pasivo(dominio)
                    guardar_escaneo_supabase(email, dominio, "Rapido (Passive)", resultados)
                    enviar_webhook(webhook_url, dominio, resultados, "Rapido (Passive)")

if __name__ == "__main__":
    main()
    from motores import _motor_basic_pasivo, _motor_pro_activo, _motor_enterprise_owasp
    """Motor Pro activo — puertos, fuzzing, tecnologías, CVE."""
    resultados = _motor_basic_pasivo(dominio)
    
    # Mapeo de puertos
    puertos = {80: "HTTP", 443: "HTTPS", 8080: "HTTP-Alt", 8443: "HTTPS-Alt"}
    for puerto, desc in puertos.items():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.5)
            if s.connect_ex((dominio, puerto)) == 0:
                resultados.append(f"🟢 Puerto {puerto} abierto: {desc}")
            s.close()
        except Exception:
            pass

    # Fuzzing básico
    rutas = ["/admin", "/login", "/wp-admin", "/.env", "/api", "/backup"]
    for ruta in rutas:
        try:
            r = requests.head(f"https://{dominio}{ruta}", timeout=2, allow_redirects=True)
            if r.status_code in (200, 301, 302, 401, 403):
                resultados.append(f"📂 Directorio encontrado ({r.status_code}): {ruta}")
        except Exception:
            pass

    # Detección de tecnologías
    try:
        r = requests.get(f"https://{dominio}", timeout=5)
        html = r.text.lower()
        if "wp-content" in html:
            resultados.append("🛠️ Tecnología detectada: WordPress")
        if "nginx" in r.headers.get("server", "").lower():
            resultados.append("🛠️ Servidor: Nginx")
        if "apache" in r.headers.get("server", "").lower():
            resultados.append("🛠️ Servidor: Apache")
    except Exception:
        pass

    return resultados


from motores import _motor_basic_pasivo, _motor_pro_activo, _motor_enterprise_owasp
    """Motor Enterprise OWASP — WAF, SQLi, XSS, SSRF."""
    resultados = ejecutar_motor_pro(dominio)  # Incluye todo el Pro

    headers_pro = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
    base = f"https://{dominio}"

    # WAF detection
    try:
        r = requests.get(base, params={"id": "1' OR '1'='1"}, timeout=5, headers=headers_pro)
        if r.status_code in (403, 406, 429):
            resultados.append("🛡️ WAF detectado y activo.")
        else:
            resultados.append("🚨 WAF ausente — vulnerable a ataques automatizados.")
    except Exception:
        pass

    # XSS básico
    try:
        payload = "<script>alert('xss')</script>"
        r = requests.get(base, params={"q": payload}, timeout=5, headers=headers_pro)
        if payload.lower() in r.text.lower():
            resultados.append("🚨 XSS reflejado detectado.")
        else:
            resultados.append("✅ No se detectó XSS reflejado.")
    except Exception:
        pass

    # SSRF básico
    try:
        r = requests.get(base, params={"url": "http://127.0.0.1"}, timeout=5, headers=headers_pro)
        if r.status_code == 200 and "localhost" in r.text.lower():
            resultados.append("🚨 SSRF detectado — el servidor hace peticiones internas.")
        else:
            resultados.append("✅ No se detectó SSRF.")
    except Exception:
        pass

    return resultados