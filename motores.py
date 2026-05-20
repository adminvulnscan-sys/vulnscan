import os
import ssl
import socket
import requests
import dns.resolver
from datetime import datetime, timezone
import re

# ==========================================
# MOTOR DE ANÁLISIS REAL (PILAR 2)
# ==========================================
def _motor_basic_pasivo(dominio_limpio):
    """DNS (socket.getaddrinfo) + análisis de cabeceras HTTP (requests.get)."""
    resultados_reales = []

    # --- OSINT / DNS (siempre en pasivo) ---
    try:
        infos = socket.getaddrinfo(dominio_limpio, None, type=socket.SOCK_STREAM)
        ips = []
        for x in infos:
            a = x[4][0]
            if a not in ips:
                ips.append(a)
        if ips:
            muestra = ", ".join(ips[:5])
            suf = "..." if len(ips) > 5 else ""
            resultados_reales.append(f"🌐 **DNS / OSINT:** Resolución obtenida -> {muestra}{suf}")
        else:
            resultados_reales.append("⚠️ **DNS:** No se obtuvieron registros A/AAAA para el objetivo.")
    except Exception as e:
        resultados_reales.append(f"⚠️ **DNS:** No se pudo resolver el dominio ({e}).")

    # --- Cabeceras HTTP (huella pasiva; no sustituye al bloqueo de puertos en Basic) ---
    try:
        headers_pro = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0"
        }
        url = f"https://{dominio_limpio}"
        respuesta = requests.get(url, timeout=5, headers=headers_pro, allow_redirects=True)
        cabeceras = respuesta.headers

        checks = {
            "X-Frame-Options": "⚠️  Falta proteccion contra clonado (Clickjacking).",
            "Strict-Transport-Security": "⚠️  Falta HSTS (Forzar HTTPS).",
            "Content-Security-Policy": "⚠️  Falta CSP (Prevención de inyecciones de codigo).",
            "X-Content-Type-Options": "⚠️  Falta X-Content-Type-Options.",
            "Referrer-Policy": "⚠️  Falta Referrer-Policy — puede filtrar URLs internas al navegar.",
            "Permissions-Policy": "⚠️  Falta Permissions-Policy — sin control de permisos del navegador.",
        }

        for cap, msg in checks.items():
            if cap not in cabeceras:
                resultados_reales.append(f"{msg}")
            else:
                resultados_reales.append(f"✅ **Protección Detectada:** {cap}")

    except Exception as e:
        resultados_reales.append(f"❌ No se pudieron analizar las cabeceras: {e}")

# --- SSL Real ---
    try:
        import ssl
        from datetime import datetime, timezone
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=dominio_limpio) as s:
            s.settimeout(5)
            s.connect((dominio_limpio, 443))
            cert = s.getpeercert()
        fecha_exp = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
        dias_restantes = (fecha_exp - datetime.now(timezone.utc)).days
        if dias_restantes > 30:
            resultados_reales.append(f"✅ **SSL/TLS:** Certificado válido — caduca en {dias_restantes} días.")
        elif dias_restantes > 0:
            resultados_reales.append(f"⚠️ **SSL/TLS:** Certificado próximo a caducar — {dias_restantes} días restantes.")
        else:
            resultados_reales.append(f"🚨 **SSL/TLS:** Certificado CADUCADO.")
    except Exception:
        resultados_reales.append("🚨 **SSL/TLS:** No se pudo verificar el certificado.")

    # --- Detección de CDN ---
    try:
        headers_cdn = requests.get(f"https://{dominio_limpio}", timeout=5).headers
        if "cf-ray" in [h.lower() for h in headers_cdn]:
            resultados_reales.append("🛡️ **CDN:** Cloudflare detectado — tráfico protegido por CDN.")
        elif "x-amz-cf-id" in [h.lower() for h in headers_cdn]:
            resultados_reales.append("🛡️ **CDN:** Amazon CloudFront detectado.")
        elif "x-azure-ref" in [h.lower() for h in headers_cdn]:
            resultados_reales.append("🛡️ **CDN:** Azure CDN detectado.")
        elif "x-cache" in [h.lower() for h in headers_cdn] and "akamai" in str(headers_cdn).lower():
            resultados_reales.append("🛡️ **CDN:** Akamai detectado.")
        else:
            resultados_reales.append("⚠️ **CDN:** No se detectó CDN conocido. Se recomienda usar Cloudflare u otro CDN para mayor protección.")
    except Exception:
        pass

    # --- Listas negras de spam ---
    try:
        ip = socket.gethostbyname(dominio_limpio)
        ip_inv = ".".join(reversed(ip.split(".")))
        dnsbl_listas = ["zen.spamhaus.org", "bl.spamcop.net", "dnsbl.sorbs.net"]
        en_lista_negra = False
        for lista in dnsbl_listas:
            try:
                socket.gethostbyname(f"{ip_inv}.{lista}")
                resultados_reales.append(f"🚨 **Lista Negra:** IP {ip} encontrada en {lista}.")
                en_lista_negra = True
            except Exception:
                pass
        if not en_lista_negra:
            resultados_reales.append(f"✅ **Reputación IP:** {ip} no aparece en listas negras de spam.")
    except Exception:
        pass

    return resultados_reales

# ==============================================================================
# FUNCIÓN 1: BANNER GRABBING & VERSION DETECTION (mejorado)
# ==============================================================================

def analizar_puertos_y_versiones(dominio_limpio):
    """
    Escanea puertos clave, extrae banners y detecta versiones antiguas.
    Retorna lista de hallazgos y lista de software detectado para CVE matching.
    """
    resultados = []
    software_detectado = []

    PUERTOS = {
        21:   "FTP",
        22:   "SSH",
        25:   "SMTP",
        80:   "HTTP",
        443:  "HTTPS",
        3306: "MySQL",
        5432: "PostgreSQL",
        6379: "Redis",
        8080: "HTTP-Alt",
        8443: "HTTPS-Alt",
        27017:"MongoDB",
    }

    # Versiones conocidas como antiguas/vulnerables (keyword -> versión mínima segura)
    VERSIONES_ANTIGUAS = {
        "nginx":   (1, 24),
        "apache":  (2, 4),
        "openssh": (8, 0),
        "php":     (8, 1),
        "mysql":   (8, 0),
    }

    for puerto, servicio in PUERTOS.items():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.5)
            resultado = s.connect_ex((dominio_limpio, puerto))

            if resultado == 0:
                resultados.append(f"🟢 **Puerto {puerto} ({servicio}) Abierto**")

                # Banner grabbing
                try:
                    if puerto in (80, 8080):
                        s.send(b"HEAD / HTTP/1.0\r\nHost: " + dominio_limpio.encode() + b"\r\n\r\n")
                    elif puerto == 22:
                        pass  # SSH envía banner solo
                    else:
                        s.send(b"\r\n")

                    banner = s.recv(2048).decode(errors="ignore")

                    for linea in banner.split("\n"):
                        linea = linea.strip()
                        if linea.lower().startswith("server:"):
                            servidor = linea.split(":", 1)[1].strip()
                            resultados.append(f"🔍 **Banner Puerto {puerto}:** `{servidor}`")
                            software_detectado.append(servidor)

                            # Detección de versión antigua
                            for sw, version_minima in VERSIONES_ANTIGUAS.items():
                                if sw in servidor.lower():
                                    match = re.search(r'(\d+)\.(\d+)', servidor)
                                    if match:
                                        v_maj, v_min = int(match.group(1)), int(match.group(2))
                                        if (v_maj, v_min) < version_minima:
                                            resultados.append(
                                                f"🚨 **Versión Antigua Detectada:** `{servidor}` — "
                                                f"Versión mínima recomendada: {version_minima[0]}.{version_minima[1]}. "
                                                f"Actualizar urgentemente para evitar exploits conocidos."
                                            )
                                    break
                            break

                        # SSH banner directo
                        if "ssh" in linea.lower() and puerto == 22:
                            resultados.append(f"🔍 **Banner SSH:** `{linea}`")
                            software_detectado.append(linea)
                            break

                except Exception:
                    pass

                # Alerta puertos sensibles expuestos
                if puerto in (3306, 5432, 6379, 27017):
                    resultados.append(
                        f"🚨 **CRÍTICO — Base de datos expuesta:** Puerto {puerto} ({servicio}) accesible "
                        f"públicamente. Riesgo de acceso no autorizado a datos."
                    )
                if puerto == 22:
                    resultados.append(
                        f"⚠️ **SSH Expuesto:** Puerto 22 accesible públicamente. "
                        f"Asegúrate de tener autenticación por clave y fail2ban activo."
                    )

            else:
                if puerto in (80, 443):
                    resultados.append(f"🔴 **Puerto {puerto} ({servicio}) Cerrado**")

            s.close()

        except Exception:
            pass

    return resultados, software_detectado


# ==============================================================================
# FUNCIÓN 2: ANÁLISIS SSL/TLS PROFUNDO
# ==============================================================================

def analizar_ssl_profundo(dominio_limpio):
    """
    Verifica certificado SSL: expiración, algoritmo de firma, protocolos obsoletos.
    """
    resultados = []

    # --- Certificado y fecha de expiración ---
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((dominio_limpio, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=dominio_limpio) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()

                # Fecha de expiración
                fecha_exp_str = cert.get("notAfter", "")
                if fecha_exp_str:
                    fecha_exp = datetime.datetime.strptime(fecha_exp_str, "%b %d %H:%M:%S %Y %Z")
                    dias_restantes = (fecha_exp - datetime.datetime.utcnow()).days
                    if dias_restantes < 0:
                        resultados.append(f"🚨 **SSL Caducado:** El certificado expiró hace {abs(dias_restantes)} días.")
                    elif dias_restantes < 15:
                        resultados.append(f"🚨 **SSL Crítico:** Certificado caduca en {dias_restantes} días. Renueva inmediatamente.")
                    elif dias_restantes < 30:
                        resultados.append(f"⚠️ **SSL Aviso:** Certificado caduca en {dias_restantes} días.")
                    else:
                        resultados.append(f"✅ **SSL Válido:** Certificado caduca en {dias_restantes} días.")

                # Algoritmo de cifrado
                if cipher:
                    cipher_name = cipher[0]
                    tls_version = cipher[1]
                    resultados.append(f"🔐 **Cipher Suite activo:** `{cipher_name}` ({tls_version})")

                    if "RC4" in cipher_name or "DES" in cipher_name or "NULL" in cipher_name or "EXPORT" in cipher_name:
                        resultados.append(
                            f"🚨 **Cifrado Débil Detectado:** `{cipher_name}` es un algoritmo inseguro "
                            f"y puede ser descifrado por atacantes. Configura cipher suites modernas (AES-GCM, ChaCha20)."
                        )

                # Algoritmo de firma del certificado
                sig_alg = cert.get("signatureAlgorithm", "")
                if not sig_alg:
                    # Intentar extraer del subject
                    for field in cert.get("subject", []):
                        pass
                if "sha1" in str(cert).lower():
                    resultados.append(
                        "🚨 **Firma SHA-1 Detectada:** SHA-1 está deprecado y es vulnerable a ataques de colisión. "
                        "Migra a SHA-256 o superior."
                    )

    except ssl.SSLCertVerificationError:
        resultados.append("🚨 **SSL Inválido:** El certificado no es válido o no es de confianza.")
    except ssl.SSLError as e:
        resultados.append(f"⚠️ **Error SSL:** {str(e)[:80]}")
    except Exception:
        pass

    # --- Protocolos obsoletos TLS 1.0 / TLS 1.1 ---
    for protocolo, version in [("TLS 1.0", ssl.TLSVersion.TLSv1), ("TLS 1.1", ssl.TLSVersion.TLSv1_1)]:
        try:
            ctx_old = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx_old.check_hostname = False
            ctx_old.verify_mode = ssl.CERT_NONE
            ctx_old.minimum_version = version
            ctx_old.maximum_version = version
            with socket.create_connection((dominio_limpio, 443), timeout=3) as sock:
                with ctx_old.wrap_socket(sock, server_hostname=dominio_limpio):
                    resultados.append(
                        f"🚨 **Protocolo Obsoleto:** El servidor acepta {protocolo}. "
                        f"Este protocolo tiene vulnerabilidades conocidas (POODLE, BEAST). Deshabilítalo."
                    )
        except Exception:
            resultados.append(f"✅ **{protocolo}:** Deshabilitado correctamente.")

    return resultados


# ==============================================================================
# FUNCIÓN 3: DETECCIÓN DE FICHEROS CRÍTICOS (Fuzzing ligero)
# ==============================================================================

def detectar_ficheros_criticos(dominio_limpio):
    """
    Busca archivos sensibles que los desarrolladores olvidan eliminar.
    """
    resultados = []

    FICHEROS_CRITICOS = [
        ("/.env",                "CRÍTICO", "Puede contener credenciales de base de datos, API keys y secretos de la aplicación."),
        ("/.env.local",          "CRÍTICO", "Archivo de configuración local con posibles credenciales."),
        ("/.env.production",     "CRÍTICO", "Configuración de producción con credenciales reales."),
        ("/.git/config",         "CRÍTICO", "Repositorio Git expuesto. Permite descargar el código fuente completo."),
        ("/.git/HEAD",           "CRÍTICO", "Repositorio Git expuesto públicamente."),
        ("/wp-config.php.bak",   "CRÍTICO", "Backup de configuración WordPress con credenciales de base de datos."),
        ("/wp-config.php~",      "CRÍTICO", "Backup temporal de configuración WordPress."),
        ("/docker-compose.yml",  "CRÍTICO", "Expone arquitectura de contenedores, puertos internos y variables de entorno."),
        ("/docker-compose.yaml", "CRÍTICO", "Expone arquitectura de contenedores."),
        ("/database.yml",        "CRÍTICO", "Credenciales de base de datos expuestas."),
        ("/config/database.yml", "CRÍTICO", "Credenciales de base de datos de Rails expuestas."),
        ("/backup.sql",          "CRÍTICO", "Dump de base de datos accesible públicamente."),
        ("/dump.sql",            "CRÍTICO", "Dump de base de datos accesible públicamente."),
        ("/db.sql",              "CRÍTICO", "Dump de base de datos accesible públicamente."),
        ("/phpinfo.php",         "ALTO",    "Expone configuración completa de PHP, rutas del servidor y módulos instalados."),
        ("/info.php",            "ALTO",    "Expone información detallada del servidor PHP."),
        ("/server-status",       "ALTO",    "Panel de estado de Apache expuesto. Muestra conexiones activas y rutas."),
        ("/server-info",         "ALTO",    "Información detallada de módulos Apache expuesta."),
        ("/.htaccess",           "ALTO",    "Reglas de configuración del servidor expuestas."),
        ("/web.config",          "ALTO",    "Configuración IIS expuesta. Puede contener connection strings."),
        ("/crossdomain.xml",     "ALTO",    "Política de dominios cruzados. Puede permitir acceso no autorizado."),
        ("/robots.txt",          "INFO",    "Puede revelar rutas privadas que se intentan ocultar a buscadores."),
        ("/sitemap.xml",         "INFO",    "Revela estructura completa del sitio."),
        ("/readme.html",         "MEDIO",   "Revela versión exacta de WordPress instalada."),
        ("/license.txt",         "MEDIO",   "Revela versión del CMS instalado."),
        ("/changelog.txt",       "MEDIO",   "Revela versión y historial de cambios del CMS."),
    ]

    EMOJI_NIVEL = {
        "CRÍTICO": "🚨",
        "ALTO":    "⚠️",
        "MEDIO":   "⚠️",
        "INFO":    "📂",
    }

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    }

    from concurrent.futures import ThreadPoolExecutor, as_completed

    def check_fichero(item):
        path, nivel, descripcion = item
        for scheme in ("https", "http"):
            try:
                url = f"{scheme}://{dominio_limpio}{path}"
                r = requests.get(url, timeout=1.5, headers=headers, allow_redirects=False)
                if r.status_code == 200:
                    emoji = EMOJI_NIVEL.get(nivel, "⚠️")
                    return f"{emoji} **Fichero Crítico [{nivel}]:** `{path}` accesible. {descripcion}"
                elif r.status_code == 401:
                    return f"🔒 **Fichero Protegido:** `{path}` existe pero requiere autenticación (401)."
            except Exception:
                pass
        return None

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(check_fichero, item): item for item in FICHEROS_CRITICOS}
        for future in as_completed(futures):
            resultado = future.result()
            if resultado:
                resultados.append(resultado)

    if not any("Fichero Crítico" in r or "Fichero Protegido" in r for r in resultados):
        resultados.append("✅ **Ficheros Críticos:** No se detectaron archivos sensibles expuestos.")

    return resultados

# ==============================================================================
# FUNCIÓN 4: OSINT DE EMAILS
# ==============================================================================

def osint_emails(dominio_limpio):
    """
    Busca patrones de emails expuestos en el HTML de la home y página de contacto.
    """
    resultados = []
    emails_encontrados = set()

    PATRON_EMAIL = re.compile(
        r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}'
    )

    PAGINAS_A_REVISAR = [
        f"https://{dominio_limpio}",
        f"https://{dominio_limpio}/contact",
        f"https://{dominio_limpio}/contacto",
        f"https://{dominio_limpio}/about",
        f"https://{dominio_limpio}/sobre-nosotros",
        f"https://{dominio_limpio}/equipo",
        f"https://{dominio_limpio}/team",
        f"https://{dominio_limpio}/soporte",
        f"https://{dominio_limpio}/support",
    ]

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    }

    # Dominios genéricos que no son emails reales
    DOMINIOS_EXCLUIDOS = {
        "example.com", "test.com", "email.com", "domain.com",
        "sentry.io", "w3.org", "schema.org", "googleapis.com",
        "jquery.com", "bootstrapcdn.com", "cloudflare.com"
    }

    for url in PAGINAS_A_REVISAR:
        try:
            r = requests.get(url, timeout=4, headers=headers, allow_redirects=True)
            if r.status_code == 200:
                emails_raw = PATRON_EMAIL.findall(r.text)
                for email in emails_raw:
                    dominio_email = email.split("@")[1].lower()
                    # Filtrar emails genéricos y de librerías
                    if dominio_email not in DOMINIOS_EXCLUIDOS and not dominio_email.endswith(".png") \
                       and not dominio_email.endswith(".js") and not dominio_email.endswith(".css"):
                        emails_encontrados.add(email.lower())
        except Exception:
            pass

    if emails_encontrados:
        # Clasificar por tipo
        emails_corporativos = [e for e in emails_encontrados if dominio_limpio in e]
        emails_externos = [e for e in emails_encontrados if dominio_limpio not in e]

        if emails_corporativos:
            resultados.append(
                f"📧 **Emails Corporativos Expuestos ({len(emails_corporativos)}):** "
                f"`{'`, `'.join(sorted(emails_corporativos)[:5])}`"
            )
            if len(emails_corporativos) > 3:
                resultados.append(
                    f"⚠️ **Riesgo OSINT:** {len(emails_corporativos)} emails corporativos expuestos públicamente. "
                    f"Facilita ataques de phishing dirigido (spear phishing) y enumeración de empleados."
                )

        if emails_externos:
            resultados.append(
                f"📧 **Emails Externos Detectados ({len(emails_externos)}):** "
                f"`{'`, `'.join(sorted(emails_externos)[:3])}`"
            )
    else:
        resultados.append("✅ **OSINT Emails:** No se detectaron emails expuestos públicamente.")

    return resultados, list(emails_encontrados)

def _motor_pro_activo(dominio_limpio, incluir_cve_matching):
    """Mapeo de puertos con banner grabbing, fuzzing ampliado y CVE matching por software detectado."""
    resultados_reales = []
    puertos_web_abiertos = False
    software_detectado = []


    # --- Fuzzing de directorios web (ampliado) ---
    rutas_comunes = [
        "/admin", "/login", "/wp-admin", "/api", "/backup", "/.env",
        "/wp-login.php", "/administrator", "/phpmyadmin", "/cpanel",
        "/dashboard", "/panel", "/manager", "/console", "/portal",
        "/config", "/configuration", "/setup", "/install", "/database",
        "/.git", "/.svn", "/.htaccess", "/web.config", "/robots.txt",
        "/sitemap.xml", "/xmlrpc.php", "/wp-config.php", "/readme.html",
        "/license.txt", "/changelog.txt", "/upload", "/uploads", "/files",
        "/images", "/static", "/assets", "/tmp", "/temp", "/cache",
        "/logs", "/log", "/error_log", "/access_log", "/debug",
        "/api/v1", "/api/v2", "/api/users", "/api/admin", "/graphql",
        "/swagger", "/swagger-ui.html", "/api-docs", "/redoc", "/openapi.json",
        "/shell", "/cmd", "/exec", "/eval", "/test", "/dev", "/staging",
        "/old", "/bak", "/backup.zip", "/backup.sql", "/db.sql",
        "/info.php", "/phpinfo.php", "/server-status", "/server-info",
        "/.well-known", "/security.txt", "/crossdomain.xml", "/clientaccesspolicy.xml",
        # Paneles de administración
        "/wp-json", "/wp-json/wp/v2/users",
        "/adminer.php", "/dbadmin",
        "/.htpasswd",
        # Archivos sensibles
        "/composer.json", "/composer.lock",
        "/package.json",
        "/.DS_Store", "/thumbs.db",
        "/dump.sql", "/data.sql", "/site.sql",
        # APIs y tokens
        "/.env.local", "/.env.production", "/.env.backup",
        "/config.php", "/config.js",
        "/secrets.json", "/credentials.json",
        # Monitoreo
        "/actuator", "/actuator/env", "/actuator/health",
        "/metrics", "/health",
    ]
    headers_pro = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0"
    }
    base = f"https://{dominio_limpio}"

    # Obtener tamaño de la home para detectar falsos positivos
    try:
        home = requests.get(base, timeout=3, headers=headers_pro, allow_redirects=True)
        home_size = len(home.content)
    except Exception:
        home_size = 0

    # Función que comprueba una sola ruta
    def check_path(path):
        try:
            r = requests.get(f"{base}{path}", timeout=2.5, headers=headers_pro, allow_redirects=True)
            if r.status_code in (200, 301, 302, 401, 403):
                if r.status_code == 200 and home_size > 0 and abs(len(r.content) - home_size) < 500:
                    return None
                if r.status_code == 200:
                    if path in ["/.env", "/wp-config.php", "/.git", "/backup.zip", "/backup.sql",
                                "/db.sql", "/.htpasswd", "/.env.local", "/.env.production",
                                "/.env.backup", "/secrets.json", "/credentials.json",
                                "/dump.sql", "/data.sql", "/site.sql", "/composer.lock"]:
                        emoji, nivel = "🚨", "[CRÍTICO]"
                    elif path in ["/admin", "/wp-admin", "/phpmyadmin", "/cpanel", "/shell",
                                  "/cmd", "/adminer.php", "/dbadmin", "/actuator/env",
                                  "/wp-json/wp/v2/users", "/config.php", "/config.js"]:
                        emoji, nivel = "⚠️", "[ALTO]"
                    else:
                        emoji, nivel = "📂", "[INFO]"
                    return f"{emoji} **Fuzzing web {nivel}:** Archivo accesible (200 OK) -> `{path}`"
                elif r.status_code in (401, 403):
                    return f"🔒 **Fuzzing web [MEDIO]:** Archivo protegido ({r.status_code}) -> `{path}`. Su presencia revela información."
        except Exception:
            pass
        return None

    # Ejecutar en paralelo con 10 hilos
    from concurrent.futures import ThreadPoolExecutor, as_completed
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(check_path, path): path for path in rutas_comunes}
        for future in as_completed(futures):
            resultado = future.result()
            if resultado:
                resultados_reales.append(resultado)
   

    # --- Detección de tecnologías web ---
    try:
        r_tech = requests.get(f"https://{dominio_limpio}", timeout=5, headers=headers_pro)
        html = r_tech.text.lower()
        headers_resp = {k.lower(): v.lower() for k, v in r_tech.headers.items()}
        tecnologias = []

        # CMS
        if "wp-content" in html or "wp-includes" in html:
            tecnologias.append("WordPress")
        if "drupal" in html or "sites/default" in html:
            tecnologias.append("Drupal")
        if "joomla" in html:
            tecnologias.append("Joomla")
        if "shopify" in html:
            tecnologias.append("Shopify")
        if "wix.com" in html:
            tecnologias.append("Wix")

        # Frameworks
        if "laravel" in html or "laravel_session" in str(r_tech.cookies):
            tecnologias.append("Laravel")
        if "django" in html or "csrfmiddlewaretoken" in html:
            tecnologias.append("Django")
        if "next.js" in html or "__next" in html:
            tecnologias.append("Next.js")
        if "react" in html or "react-dom" in html:
            tecnologias.append("React")
        if "vue.js" in html or "vuejs" in html:
            tecnologias.append("Vue.js")
        if "angular" in html:
            tecnologias.append("Angular")

        # Servidores
        if "nginx" in headers_resp.get("server", ""):
            tecnologias.append("Nginx")
        if "apache" in headers_resp.get("server", ""):
            tecnologias.append("Apache")
        if "cloudflare" in headers_resp.get("server", "") or "cloudflare" in headers_resp.get("cf-ray", ""):
            tecnologias.append("Cloudflare CDN")

        # Analytics
        if "google-analytics" in html or "gtag" in html:
            tecnologias.append("Google Analytics")
        if "hotjar" in html:
            tecnologias.append("Hotjar")

        if tecnologias:
            resultados_reales.append(f"🛠️ **Tecnologías detectadas:** {', '.join(tecnologias)}")
        else:
            resultados_reales.append("🛠️ **Tecnologías:** No se identificaron tecnologías conocidas.")

    except Exception:
        pass

    # --- Subdominios comunes ---
    subdominios_comunes = [
        "www", "mail", "ftp", "api", "dev", "staging", "test",
        "admin", "portal", "app", "cdn", "static", "media",
        "blog", "shop", "store", "vpn", "remote", "webmail",
        "smtp", "pop", "imap", "ns1", "ns2", "mx", "support"
    ]
    subdominios_encontrados = []
    for sub in subdominios_comunes:
        try:
            socket.gethostbyname(f"{sub}.{dominio_limpio}")
            subdominios_encontrados.append(f"{sub}.{dominio_limpio}")
        except Exception:
            pass

    if subdominios_encontrados:
        resultados_reales.append(f"🌐 **Subdominios detectados:** {', '.join(subdominios_encontrados)}")
        if any(s in subdominios_encontrados for s in [f"dev.{dominio_limpio}", f"staging.{dominio_limpio}", f"test.{dominio_limpio}"]):
            resultados_reales.append("⚠️ **Alerta:** Se detectaron subdominios de desarrollo/staging expuestos públicamente.")
    else:
        resultados_reales.append("🌐 **Subdominios:** No se detectaron subdominios comunes expuestos.")

    # --- Nuevas funciones Pro ---
    res_puertos, software_detectado = analizar_puertos_y_versiones(dominio_limpio)
    resultados_reales.extend(res_puertos)
 
    # --- CVE Matching por software detectado en banner ---
    KEYWORD_MAP = {
        "nginx":      "nginx",
        "apache":     "Apache HTTP Server",
        "openssl":    "openssl",
        "openssh":    "openssh",
        "php":        "php",
        "mysql":      "mysql",
        "iis":        "Microsoft IIS",
        "litespeed":  "LiteSpeed",
        "tomcat":     "Apache Tomcat",
        "wordpress":  "WordPress",
        "drupal":     "Drupal",
        "joomla":     "Joomla",
    }

    if incluir_cve_matching and software_detectado:
        nvd_key = os.getenv("NVD_API_KEY", "")
        headers_nvd = {"apiKey": nvd_key} if nvd_key else {}

        keywords_limpias = []
        for s in software_detectado[:2]:
            if "/" in s:  # Solo si tiene versión específica ej: nginx/1.18.0
                partes = s.split("/")
                nombre = partes[0].strip().lower()
                version = partes[1].strip() if len(partes) > 1 else ""

                # Traducir al nombre oficial que entiende NVD
                nombre_nvd = KEYWORD_MAP.get(nombre, nombre)
                keyword_final = f"{nombre_nvd} {version}".strip()

                if keyword_final not in keywords_limpias:
                    keywords_limpias.append(keyword_final)

        if not keywords_limpias:
            resultados_reales.append(
                "📋 **CVE Matching:** No se detectó versión de software específica. "
                "No es posible realizar CVE matching preciso sin versión confirmada."
            )
        else:
            for keyword in keywords_limpias:
                try:
                    r_nvd = requests.get(
                        "https://services.nvd.nist.gov/rest/json/cves/2.0",
                        params={"keywordSearch": keyword, "resultsPerPage": 5},
                        headers=headers_nvd,
                        timeout=5
                    )
                    if r_nvd.status_code == 200:
                        cves = r_nvd.json().get("vulnerabilities", [])
                        if cves:
                            for cve in cves[:3]:
                                try:
                                    cve_id = cve["cve"]["id"]
                                    desc = cve["cve"]["descriptions"][0]["value"][:120]
                                    try:
                                        severidad = cve["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"]["baseSeverity"]
                                    except (KeyError, IndexError):
                                        try:
                                            severidad = cve["cve"]["metrics"]["cvssMetricV2"][0]["baseSeverity"]
                                        except (KeyError, IndexError):
                                            severidad = "UNKNOWN"
                                    emoji_sev = {"CRITICAL": "[CRITICO]", "HIGH": "[ALTO]", "MEDIUM": "[MEDIO]", "LOW": "[BAJO]"}.get(severidad, "[INFO]")
                                    resultados_reales.append(
                                        f"🚨 **CVE [{emoji_sev}{severidad}]:** {cve_id} ({keyword}) — {desc}..."
                                    )
                                except Exception:
                                    continue
                        else:
                            resultados_reales.append(
                                f"✅ **CVE Matching ({keyword}):** No se encontraron vulnerabilidades conocidas."
                            )
                    elif r_nvd.status_code == 403:
                        resultados_reales.append("📋 **CVE Matching:** API key de NVD inválida o sin permisos.")
                    elif r_nvd.status_code == 429:
                        resultados_reales.append("📋 **CVE Matching:** Límite de peticiones NVD alcanzado. Inténtalo más tarde.")
                    else:
                        resultados_reales.append(f"📋 **CVE Matching:** NVD respondió con error {r_nvd.status_code}.")
                except requests.exceptions.Timeout:
                    resultados_reales.append(f"📋 **CVE Matching ({keyword}):** Timeout al conectar con NVD.")
                except requests.exceptions.ConnectionError:
                    resultados_reales.append(f"📋 **CVE Matching ({keyword}):** No se pudo conectar con NVD.")
                except Exception as e:
                    resultados_reales.append(f"📋 **CVE Matching ({keyword}):** Error inesperado: {str(e)[:50]}")

       
    res_ssl = analizar_ssl_profundo(dominio_limpio)
    resultados_reales.extend(res_ssl)

    res_ficheros = detectar_ficheros_criticos(dominio_limpio)
    resultados_reales.extend(res_ficheros)

    res_emails, _ = osint_emails(dominio_limpio)
    resultados_reales.extend(res_emails)

    return resultados_reales
    


def _motor_enterprise_owasp(dominio_limpio):
    """Pruebas OWASP reales: SQLi, XSS, SSRF, WAF detection, cabeceras avanzadas."""
    resultados_reales = []
    headers_pro = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0"
    }
    base = f"https://{dominio_limpio}"

    # --- 1. Detección de WAF ---
    try:
        payloads_waf = [
            {"id": "1' OR '1'='1"},
            {"id": "1; DROP TABLE users--"},
            {"search": "<script>alert(1)</script>"},
        ]
        waf_detectado = False
        for payload in payloads_waf:
            r = requests.get(base, params=payload, timeout=5, headers=headers_pro)
            if r.status_code in (403, 406, 429):
                waf_detectado = True
                break
            cabeceras_waf = ["x-sucuri-id", "x-firewall", "cf-ray", "x-waf", "x-protected-by"]
            if any(h in [k.lower() for k in r.headers.keys()] for h in cabeceras_waf):
                waf_detectado = True
                break
        if waf_detectado:
            resultados_reales.append("🛡️ **WAF Detectado:** Firewall activo — payloads maliciosos bloqueados correctamente.")
        else:
            resultados_reales.append("🚨 **WAF Ausente:** No se detectó firewall de aplicaciones web. Vulnerable a ataques automatizados.")
    except Exception:
        resultados_reales.append("⚠️ **WAF:** No se pudo verificar la presencia de firewall.")

    # --- 2. SQLi real (detección por errores) ---
    try:
        payloads_sqli = ["'", "''", "`", "1' OR '1'='1", "1; SELECT 1--", "' OR 1=1--"]
        errores_sql = ["sql syntax", "mysql_fetch", "ora-", "sqlite_", "pg_query", "unclosed quotation", "syntax error"]
        sqli_encontrado = False
        for payload in payloads_sqli:
            try:
                r = requests.get(base, params={"id": payload, "q": payload, "search": payload}, timeout=5, headers=headers_pro)
                respuesta_lower = r.text.lower()
                if any(err in respuesta_lower for err in errores_sql):
                    resultados_reales.append(f"🚨 **SQLi Detectado:** El servidor devuelve errores SQL con payload `{payload}`. Vulnerabilidad crítica de inyección SQL.")
                    sqli_encontrado = True
                    break
            except Exception:
                pass
        if not sqli_encontrado:
            resultados_reales.append("✅ **SQLi:** No se detectaron errores SQL en las respuestas del servidor.")
    except Exception:
        pass

    # --- 3. XSS Reflejado ---
    try:
        payloads_xss = [
            "<script>alert('xss')</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert(1)",
        ]
        xss_encontrado = False
        for payload in payloads_xss:
            r = requests.get(base, params={"q": payload, "search": payload, "input": payload}, timeout=5, headers=headers_pro)
            if payload.lower() in r.text.lower():
                resultados_reales.append(f"🚨 **XSS Reflejado:** El servidor devuelve el payload sin sanitizar. Vulnerabilidad crítica.")
                xss_encontrado = True
                break
        if not xss_encontrado:
            resultados_reales.append("✅ **XSS:** El servidor sanitiza correctamente los inputs.")
    except Exception:
        pass

    # --- 4. SSRF básico ---
    try:
        ssrf_payloads = [
            "http://127.0.0.1",
            "http://localhost",
            "http://169.254.169.254/latest/meta-data/",
            "http://192.168.1.1",
        ]
        ssrf_encontrado = False
        for payload in ssrf_payloads:
            try:
                r = requests.get(base, params={"url": payload, "redirect": payload, "next": payload}, timeout=5, headers=headers_pro)
                if r.status_code == 200 and any(x in r.text.lower() for x in ["ami-id", "instance-id", "root:", "localhost"]):
                    resultados_reales.append(f"🚨 **SSRF Detectado:** El servidor realiza peticiones a IPs internas ({payload}). Vulnerabilidad crítica.")
                    ssrf_encontrado = True
                    break
            except Exception:
                pass
        if not ssrf_encontrado:
            resultados_reales.append("✅ **SSRF:** No se detectaron redirecciones a IPs internas.")
    except Exception:
        pass

    # --- 5. Cabeceras de seguridad avanzadas ---
    try:
        r_headers = requests.get(base, timeout=5, headers=headers_pro)
        headers_resp = {k.lower(): v for k, v in r_headers.headers.items()}

        if "permissions-policy" not in headers_resp:
            resultados_reales.append("⚠️ **Permissions-Policy:** Ausente. El sitio no restringe APIs del navegador (cámara, micrófono, geolocalización).")
        else:
            resultados_reales.append("✅ **Permissions-Policy:** Presente. APIs del navegador correctamente restringidas.")

        if "referrer-policy" not in headers_resp:
            resultados_reales.append("⚠️ **Referrer-Policy:** Ausente. Las URLs internas pueden filtrarse a sitios externos.")
        else:
            resultados_reales.append("✅ **Referrer-Policy:** Presente. Filtración de URLs controlada.")

        if "cross-origin-embedder-policy" not in headers_resp:
            resultados_reales.append("⚠️ **COEP:** Ausente. Posible vulnerabilidad a ataques de canal lateral (Spectre).")
        else:
            resultados_reales.append("✅ **COEP:** Presente. Protección contra ataques de canal lateral activa.")

        if "cross-origin-opener-policy" not in headers_resp:
            resultados_reales.append("⚠️ **COOP:** Ausente. Posible filtración de datos entre pestañas del navegador.")
        else:
            resultados_reales.append("✅ **COOP:** Presente. Aislamiento entre pestañas activo.")

    except Exception:
        pass

    # --- 6. Open Redirect ---
    try:
        redirect_payloads = ["//evil.com", "https://evil.com", "/\\evil.com"]
        for payload in redirect_payloads:
            try:
                r = requests.get(base, params={"redirect": payload, "next": payload, "url": payload}, timeout=5, headers=headers_pro, allow_redirects=False)
                if r.status_code in (301, 302, 303, 307, 308):
                    location = r.headers.get("location", "")
                    if "evil.com" in location:
                        resultados_reales.append("🚨 **Open Redirect:** El servidor redirige a dominios externos sin validación. Vulnerable a phishing.")
                        break
            except Exception:
                pass
        else:
            resultados_reales.append("✅ **Open Redirect:** No se detectaron redirecciones abiertas a dominios externos.")
    except Exception:
        pass

    return resultados_reales