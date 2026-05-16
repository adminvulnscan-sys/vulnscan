import os
import json
from datetime import datetime, timezone
from supabase import create_client
from dotenv import load_dotenv
import requests
from motores import _motor_basic_pasivo, _motor_pro_activo, _motor_enterprise_owasp

load_dotenv()

# --- Conexión a Supabase ---
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

def debe_escanear_hoy(ultimo_escaneo_fecha, frecuencia_dias):
    if not ultimo_escaneo_fecha or frecuencia_dias == 0:
        return True
    try:
        # Intentar ambos formatos de fecha
        try:
            ultimo = datetime.strptime(ultimo_escaneo_fecha, "%d/%m/%Y").replace(tzinfo=timezone.utc)
        except ValueError:
            ultimo = datetime.fromisoformat(ultimo_escaneo_fecha).replace(tzinfo=timezone.utc)
        dias_desde_ultimo = (datetime.now(timezone.utc) - ultimo).days
        return dias_desde_ultimo >= frecuencia_dias
    except Exception:
        return True

def enviar_webhook(webhook_url, dominio, resultados, tipo_escaneo):
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

    usuarios = supabase.table("usuarios").select("*").eq("scheduler_activo", True).execute()

    if not usuarios.data:
        print("[Scheduler] No hay usuarios con scheduler activo.")
        return

    for usuario in usuarios.data:
        email = usuario.get("email")
        webhook_url = usuario.get("webhook_url", "")
        
        # 1. Blindaje del plan (Forzamos a que empiece en mayúscula y sin espacios)
        plan_crudo = usuario.get("plan_activo") or "Basic"
        plan = str(plan_crudo).strip().capitalize()

        # 2. Blindaje de las frecuencias (Convertimos NULL a 0 de forma segura)
        freq_passive = int(usuario.get("scheduler_freq_passive") or 0)
        freq_pro = int(usuario.get("scheduler_freq_pro") or 0)
        freq_ent = int(usuario.get("scheduler_freq_enterprise") or 0)

        # 3. Blindaje de los toggles booleanos
        on_passive = bool(usuario.get("scheduler_passive_on"))
        on_pro = bool(usuario.get("scheduler_pro_on"))
        on_ent = bool(usuario.get("scheduler_enterprise_on"))

        print(f"[Scheduler] Procesando usuario: {email} (Plan detectado: {plan})")

        dominios = supabase.table("activos_verificados").select("dominio").eq("email_cliente", email).execute()
        if not dominios.data:
            print(f"[Scheduler] {email} no tiene dominios verificados.")
            continue

        for activo in dominios.data:
            dominio = activo["dominio"]

            # Obtener última fecha por tipo de escaneo
            def get_ultima_fecha(tipo):
                try:
                    r = supabase.table("escaneos").select("fecha").eq("email_cliente", email).eq("dominio", dominio).eq("tipo", tipo).order("id", desc=True).limit(1).execute()
                    return r.data[0]["fecha"] if r.data else None
                except Exception:
                    return None

            # --- Escaneo Basic ---
            print(f"  [DEBUG] BASIC -> on_passive={on_passive}, freq_passive={freq_passive}")
            if on_passive and freq_passive > 0:
                ultima = get_ultima_fecha("Rapido (Passive)")
                if debe_escanear_hoy(ultima, freq_passive):
                    print(f"[Scheduler] Ejecutando Basic para {dominio}")
                    resultados = _motor_basic_pasivo(dominio)
                    guardar_escaneo_supabase(email, dominio, "Rapido (Passive)", resultados)
                else:
                    print(f"    -> Saltando BASIC: No han pasado los dias necesarios desde {ultima}")

            # --- Escaneo Pro ---
            print(f"  [DEBUG] PRO -> plan={plan}, on_pro={on_pro}, freq_pro={freq_pro}")
            if plan in ["Pro", "Enterprise"] and on_pro and freq_pro > 0:
                ultima = get_ultima_fecha("Profundo (Active)")
                if debe_escanear_hoy(ultima, freq_pro):
                    print(f"[Scheduler] Ejecutando Pro para {dominio}")
                    resultados = _motor_pro_activo(dominio, True)
                    guardar_escaneo_supabase(email, dominio, "Profundo (Active)", resultados)
                else:
                    print(f"    -> Saltando PRO: No han pasado los dias necesarios desde {ultima}")
            else:
                print("    -> Saltando PRO por requisitos (Plan bajo, toggle apagado o freq 0)")

            # --- Escaneo Enterprise ---
            print(f"  [DEBUG] ENT -> plan={plan}, on_ent={on_ent}, freq_ent={freq_ent}")
            if plan == "Enterprise" and on_ent and freq_ent > 0:
                ultima = get_ultima_fecha("Auditoria Completa (OWASP)")
                if debe_escanear_hoy(ultima, freq_ent):
                    print(f"[Scheduler] Ejecutando Enterprise para {dominio}")
                    resultados = _motor_enterprise_owasp(dominio)
                    guardar_escaneo_supabase(email, dominio, "Auditoria Completa (OWASP)", resultados)
                else:
                    print(f"    -> Saltando ENT: No han pasado los dias necesarios desde {ultima}")
            else:
                print("    -> Saltando ENT por requisitos (Plan bajo, toggle apagado o freq 0)")

if __name__ == "__main__":
    main()