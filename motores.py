import os
import ssl
import socket
import requests
import dns.resolver
from datetime import datetime, timezone
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

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
                if puerto == 21:
                    resultados.append(f"⚠️ **Puerto {puerto} ({servicio}) Abierto** — FTP es un protocolo inseguro. Se recomienda deshabilitar o reemplazar por SFTP.")
                else:
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
    """
    Motor Enterprise - Pruebas activas reales de seguridad.
    Cubre: WAF, SQLi, XSS, APIs, Cookies, Fugas, Subdomain Takeover,
           Métodos HTTP, Rate Limiting, Cabeceras avanzadas, CORS.
    """
    resultados = []
    headers_base = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "es-ES,es;q=0.8,en-US;q=0.5",
    }
    base = f"https://{dominio_limpio}"
 
    # =========================================================================
    # 1. WAF DETECTION + IDENTIFICACION DE PROVEEDOR
    # =========================================================================
    try:
        r = requests.get(base, timeout=6, headers=headers_base)
        headers_resp = {k.lower(): v for k, v in r.headers.items()}
 
        waf_detectado = False
        waf_nombre = ""
 
        # Identificacion por cabeceras especificas de cada proveedor
        if "cf-ray" in headers_resp or "cf-cache-status" in headers_resp or "cf-request-id" in headers_resp or "cloudflare" in headers_resp.get("server", "").lower():
            waf_detectado = True
            waf_nombre = "Cloudflare"
        elif "x-sucuri-id" in headers_resp or "x-sucuri-cache" in headers_resp:
            waf_detectado = True
            waf_nombre = "Sucuri"
        elif "x-akamai-transformed" in headers_resp or "akamai-grn" in headers_resp or "x-check-cacheable" in headers_resp:
            waf_detectado = True
            waf_nombre = "Akamai"
        elif "x-iinfo" in headers_resp or "x-cdn" in headers_resp and "imperva" in headers_resp.get("x-cdn", "").lower():
            waf_detectado = True
            waf_nombre = "Imperva Incapsula"
        elif "x-protected-by" in headers_resp:
            waf_detectado = True
            waf_nombre = headers_resp.get("x-protected-by", "WAF desconocido")
        elif "x-waf" in headers_resp or "x-firewall" in headers_resp:
            waf_detectado = True
            waf_nombre = "Firewall generico"
        elif "server" in headers_resp and "mod_security" in headers_resp.get("server", "").lower():
            waf_detectado = True
            waf_nombre = "ModSecurity"
        elif "cloudflare" in headers_resp.get("via", "").lower():
            waf_detectado = True
            waf_nombre = "Cloudflare"
        elif headers_resp.get("via", ""):
            waf_detectado = True
            via_value = headers_resp.get("via", "")
            if "google" in via_value.lower():
                waf_nombre = "Google CDN/Proxy"
            elif "cloudflare" in via_value.lower():
                waf_nombre = "Cloudflare"
            else:
                waf_nombre = f"CDN/Proxy ({via_value})"
        elif "h3" in headers_resp.get("alt-svc", "").lower():
            waf_detectado = True
            waf_nombre = "CDN con HTTP/3"

        # Deteccion por cookies de Cloudflare
        if not waf_detectado:
            cookies_str = str(r.cookies.get_dict())
            if "__cfduid" in cookies_str or "cf_clearance" in cookies_str or "cf-ray" in cookies_str:
                waf_detectado = True
                waf_nombre = "Cloudflare"
 
        # Verificacion adicional con payload malicioso
        if not waf_detectado:
            try:
                r_test = requests.get(
                    base,
                    params={"id": "1' OR '1'='1", "q": "<script>alert(1)</script>"},
                    timeout=5,
                    headers=headers_base
                )
                if r_test.status_code in (403, 406, 429, 503):
                    waf_detectado = True
                    waf_nombre = "WAF sin identificar (bloquea payloads)"
            except Exception:
                pass
 
        if waf_detectado:
            resultados.append(f"✅ **WAF Detectado ({waf_nombre}):** Firewall activo protegiendo la aplicacion contra ataques automatizados.")
        else:
            tiene_indicio = (
                headers_resp.get("via", "") or
                headers_resp.get("alt-svc", "") or
                headers_resp.get("x-cache", "") or
                headers_resp.get("x-served-by", "")
            )
            if tiene_indicio:
                resultados.append("⚠️ **WAF No Detectado:** No se pudo confirmar la presencia de un firewall conocido, aunque se detectaron indicios de CDN o proxy. Verificar manualmente.")
            else:
                resultados.append("🚨 **WAF Ausente:** No se detecto ningun firewall ni CDN. La web esta expuesta a ataques automatizados sin proteccion.")
 
    except Exception:
        resultados.append("⚠️ **WAF:** No se pudo verificar la presencia de firewall de aplicaciones web.")
 
    # =========================================================================
    # 2. METODOS HTTP PELIGROSOS
    # =========================================================================
    try:
        metodos_peligrosos_encontrados = []
 
        # Test OPTIONS en raiz
        try:
            r_opt = requests.options(base, timeout=5, headers=headers_base)
            allow_header = r_opt.headers.get("Allow", "") + " " + r_opt.headers.get("Public", "")
            for metodo in ["PUT", "DELETE", "TRACE", "CONNECT", "PATCH", "MOVE", "COPY"]:
                if metodo in allow_header.upper():
                    metodos_peligrosos_encontrados.append(metodo)
        except Exception:
            pass
 
        # Verificacion directa de TRACE (puede revelar cabeceras internas)
        try:
            r_trace = requests.request("TRACE", base, timeout=4, headers=headers_base)
            if r_trace.status_code == 200 and "TRACE" in r_trace.text.upper():
                if "TRACE" not in metodos_peligrosos_encontrados:
                    metodos_peligrosos_encontrados.append("TRACE")
        except Exception:
            pass
 
        # Verificacion directa de PUT
        try:
            r_put = requests.put(base + "/vulnscan_test.txt", data="vulnscan_test", timeout=4, headers=headers_base)
            if r_put.status_code in (200, 201, 204):
                # Verificar que realmente se subio haciendo GET
                r_check = requests.get(base + "/vulnscan_test.txt", timeout=3, headers=headers_base)
                if r_check.status_code == 200 and "vulnscan_test" in r_check.text:
                    if "PUT" not in metodos_peligrosos_encontrados:
                        metodos_peligrosos_encontrados.append("PUT (CONFIRMADO - subida de archivos posible)")
        except Exception:
            pass
 
        if metodos_peligrosos_encontrados:
            resultados.append(f"🚨 **Metodos HTTP Peligrosos Habilitados:** {', '.join(metodos_peligrosos_encontrados)}. Permiten modificar, eliminar o leer datos del servidor de forma no autorizada.")
        else:
            resultados.append("✅ **Metodos HTTP:** Solo metodos seguros habilitados. PUT, DELETE y TRACE correctamente deshabilitados.")
 
    except Exception:
        pass
 
    # =========================================================================
    # 3. ANALISIS DE COOKIES Y SESION
    # =========================================================================
    print("[ENTERPRISE] Iniciando seccion 3 - Cookies...")
    try:
        r_cookies = requests.get(base, timeout=5, headers=headers_base)
        
        cookies_inseguras = []
        cookies_seguras = []
 
        # Analizar cabecera Set-Cookie raw (mas fiable que el objeto cookie)
        set_cookie_headers = r_cookies.raw.headers.getlist("Set-Cookie") if hasattr(r_cookies.raw.headers, 'getlist') else []
        if not set_cookie_headers:
            # Fallback: buscar en headers normales
            all_headers = r_cookies.headers
            set_cookie_raw = all_headers.get("Set-Cookie", "")
            if set_cookie_raw:
                set_cookie_headers = [set_cookie_raw]
 
        # Tambien analizar desde el objeto cookies
        for cookie in r_cookies.cookies:
            nombre = cookie.name
            problemas = []
            flags_ok = []
 
            if not cookie.secure:
                problemas.append("sin flag Secure (transmitida en HTTP)")
            else:
                flags_ok.append("Secure")
 
            # Verificar HttpOnly desde cabecera raw
            cookie_raw_str = " ".join(set_cookie_headers)
            if f"{nombre}" in cookie_raw_str:
                if "httponly" not in cookie_raw_str.lower():
                    problemas.append("sin flag HttpOnly (accesible via JavaScript)")
                else:
                    flags_ok.append("HttpOnly")
                if "samesite" not in cookie_raw_str.lower():
                    problemas.append("sin SameSite (vulnerable a CSRF)")
                else:
                    flags_ok.append("SameSite")
 
            if problemas:
                cookies_inseguras.append(f"`{nombre}`: {', '.join(problemas)}")
            else:
                cookies_seguras.append(nombre)
 
        if cookies_inseguras:
            for c in cookies_inseguras[:5]:
                resultados.append(f"⚠️ **Cookie Insegura:** {c}. Vulnerable a robo de sesion mediante XSS o intercepcion en red.")
        elif cookies_seguras:
            resultados.append(f"✅ **Cookies:** {len(cookies_seguras)} cookie(s) con flags de seguridad correctamente configurados.")
        else:
            resultados.append("✅ **Cookies:** No se detectaron cookies de sesion en la respuesta inicial.")
 
    except Exception:
        resultados.append("⚠️ **Cookies:** No se pudo analizar la configuracion de cookies.")
 
    # =========================================================================
    # 4. APIS EXPUESTAS + CORS + DATOS SIN AUTENTICACION
    # =========================================================================
    print("[ENTERPRISE] Iniciando seccion 4 - APIs...")
    try:
        endpoints_api = [
            # APIs REST comunes
            "/api", "/api/v1", "/api/v2", "/api/v3", "/api/v4",
            "/api/users", "/api/user", "/api/admin", "/api/config",
            "/api/settings", "/api/data", "/api/export", "/api/list",
            "/api/v1/users", "/api/v1/admin", "/api/v1/config",
            "/api/v1/health", "/api/v1/status", "/api/v1/info",
            "/api/v2/users", "/api/v2/admin",
            # GraphQL
            "/graphql", "/graphiql", "/graphql/console", "/graphql/playground",
            # Documentacion expuesta
            "/swagger", "/swagger-ui", "/swagger-ui.html", "/swagger-ui/index.html",
            "/api-docs", "/api-docs/", "/openapi.json", "/openapi.yaml",
            "/redoc", "/redoc/", "/docs", "/documentation",
            # Herramientas de desarrollo
            "/actuator", "/actuator/env", "/actuator/health", "/actuator/info",
            "/actuator/beans", "/actuator/mappings", "/actuator/metrics",
            "/health", "/healthz", "/status", "/ping", "/info",
            "/metrics", "/prometheus",
            # Webhooks y integraciones
            "/webhook", "/webhooks", "/callback", "/notify",
            # Admin APIs
            "/admin/api", "/admin/api/v1", "/manage/api",
            # APIs de autenticacion
            "/auth", "/auth/token", "/auth/login", "/oauth", "/oauth/token",
            "/token", "/login", "/authenticate",
            # APIs de datos sensibles
            "/api/keys", "/api/tokens", "/api/secrets",
            "/api/credentials", "/api/passwords",
            # Debug y desarrollo
            "/debug", "/dev", "/test", "/testing",
            "/__debug__", "/_debug", "/trace",
            # Servicios comunes
            "/rest", "/rest/v1", "/rest/v2",
            "/service", "/services", "/ws", "/wsdl",
            # Wordpress REST API
            "/wp-json", "/wp-json/wp/v2", "/wp-json/wp/v2/users",
            "/wp-json/wp/v2/posts", "/wp-json/wp/v2/pages",
        ]
 
        apis_expuestas = []
        apis_con_datos = []
        apis_cors_mal = []
 
        def check_api(endpoint):
            try:
                # Cabeceras con Origin para test CORS
                h = {**headers_base, "Origin": "https://evil.com"}
                r = requests.get(base + endpoint, timeout=1, headers=h, allow_redirects=False)
 
                if r.status_code == 200:
                    content_type = r.headers.get("Content-Type", "").lower()
                    content_length = len(r.content)
 
                    # Verificar si devuelve datos reales (JSON con contenido)
                    datos_reales = False
                    if "json" in content_type and content_length > 50:
                        try:
                            data = r.json()
                            # Buscar datos sensibles en la respuesta
                            data_str = str(data).lower()
                            if any(k in data_str for k in ["email", "password", "user", "token", "key", "secret", "admin", "role", "id"]):
                                datos_reales = True
                        except Exception:
                            pass
 
                    # Verificar CORS mal configurado
                    acao = r.headers.get("Access-Control-Allow-Origin", "")
                    if acao == "*" or acao == "https://evil.com":
                        apis_cors_mal.append(f"{endpoint} (CORS: {acao})")
 
                    return endpoint, r.status_code, datos_reales, content_length
 
                elif r.status_code == 401:
                    return endpoint, 401, False, 0
                elif r.status_code == 403:
                    return endpoint, 403, False, 0
 
            except Exception:
                pass
            return None
 
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(check_api, ep): ep for ep in endpoints_api}
            for future in as_completed(futures, timeout=12):
                resultado = future.result()
                if resultado:
                    endpoint, status, datos_reales, size = resultado
                    if status == 200:
                        if datos_reales:
                            apis_con_datos.append(endpoint)
                        else:
                            apis_expuestas.append(endpoint)
                    elif status in (401, 403):
                        pass  # Protegida, no reportar
 
        if apis_con_datos:
            for ep in apis_con_datos[:5]:
                resultados.append(f"🚨 **API Expuesta con Datos Reales:** `{ep}` accesible publicamente y devuelve datos sensibles sin autenticacion.")
 
        if apis_expuestas:
            if len(apis_expuestas) <= 3:
                for ep in apis_expuestas:
                    resultados.append(f"⚠️ **API Endpoint Expuesto:** `{ep}` accesible sin autenticacion.")
            else:
                resultados.append(f"⚠️ **APIs Expuestas ({len(apis_expuestas)}):** Endpoints accesibles sin autenticacion: {', '.join(apis_expuestas[:5])}")
 
        if apis_cors_mal:
            for ep in apis_cors_mal[:3]:
                resultados.append(f"🚨 **CORS Mal Configurado:** `{ep}` permite peticiones desde cualquier dominio externo. Cualquier web puede leer los datos de esta API.")
 
        if not apis_con_datos and not apis_expuestas and not apis_cors_mal:
            resultados.append("✅ **APIs:** No se detectaron endpoints de API expuestos publicamente sin autenticacion.")
 
    except Exception:
        pass
 
    # =========================================================================
    # 5. FUGAS EN CODIGO FUENTE (HTML + JS EXTERNOS)
    # =========================================================================
    print("[ENTERPRISE] Iniciando seccion 5 - Fugas codigo...")
    try:
        paginas_a_analizar = []
 
        # Obtener HTML principal
        try:
            r_home = requests.get(base, timeout=6, headers=headers_base)
            if r_home.status_code == 200:
                paginas_a_analizar.append(("HTML Principal", r_home.text))
 
                # Extraer URLs de scripts JS externos
                scripts = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', r_home.text, re.IGNORECASE)
                js_externos = []
                for src in scripts[:10]:  # Max 10 JS externos
                    if src.startswith("http"):
                        js_externos.append(src)
                    elif src.startswith("/"):
                        js_externos.append(base + src)
 
                # Descargar JS externos en paralelo
                def fetch_js(url):
                    try:
                        r = requests.get(url, timeout=4, headers=headers_base)
                        if r.status_code == 200:
                            return (url, r.text)
                    except Exception:
                        pass
                    return None
 
                with ThreadPoolExecutor(max_workers=8) as executor:
                    futures_js = {executor.submit(fetch_js, url): url for url in js_externos}
                    for future in as_completed(futures_js, timeout=15):
                        res = future.result()
                        if res:
                            paginas_a_analizar.append((f"JS: {res[0][:60]}", res[1]))
 
        except Exception:
            pass
 
        # Patrones de fugas a buscar
        patrones_fugas = [
            # API Keys y tokens
            (r'(?i)(api[_\-]?key|apikey)\s*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})', "API Key expuesta"),
            (r'(?i)(access[_\-]?token|auth[_\-]?token)\s*[=:]\s*["\']?([A-Za-z0-9_\-\.]{20,})', "Token de acceso expuesto"),
            (r'(?i)(secret[_\-]?key|client[_\-]?secret)\s*[=:]\s*["\']?([A-Za-z0-9_\-]{16,})', "Clave secreta expuesta"),
            (r'(?i)bearer\s+([A-Za-z0-9_\-\.]{20,})', "Bearer token expuesto"),
            # Credenciales
            (r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']([^"\']{6,})["\']', "Contrasena hardcodeada"),
            (r'(?i)(username|user|login)\s*[=:]\s*["\']([^"\']{3,})["\']', "Usuario hardcodeado"),
            # Servicios cloud
            (r'AKIA[0-9A-Z]{16}', "AWS Access Key expuesta"),
            (r'(?i)aws[_\-]?secret\s*[=:]\s*["\']?([A-Za-z0-9/+=]{40})', "AWS Secret Key expuesta"),
            (r'AIza[0-9A-Za-z\-_]{35}', "Google API Key expuesta"),
            (r'(?i)mongodb(\+srv)?://[^\s"\'<>]+', "Cadena de conexion MongoDB expuesta"),
            (r'(?i)postgres(ql)?://[^\s"\'<>]+', "Cadena de conexion PostgreSQL expuesta"),
            (r'(?i)mysql://[^\s"\'<>]+', "Cadena de conexion MySQL expuesta"),
            # Rutas internas
            (r'/var/www/[^\s"\'<>]+', "Ruta interna del servidor expuesta"),
            (r'C:\\[^\s"\'<>]{10,}', "Ruta Windows del servidor expuesta"),
            (r'/home/[a-z]+/[^\s"\'<>]+', "Ruta home del servidor expuesta"),
            # Comentarios con info sensible
            (r'<!--\s*(todo|fixme|hack|bug|password|credentials|secret|key)[^-]*-->', "Comentario HTML con informacion sensible"),
            (r'//\s*(todo|fixme|hack)\s*:.*?(password|secret|key|token|credential)', "Comentario JS con informacion sensible"),
            # Emails corporativos
            (r'[a-zA-Z0-9._%+\-]+@' + re.escape(dominio_limpio), "Email corporativo expuesto en codigo"),
            # IPs internas
            (r'(?:192\.168\.|10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.)\d+\.\d+', "IP interna expuesta"),
            (r'localhost:\d+', "Referencia a localhost expuesta"),
            (r'127\.0\.0\.1:\d+', "Referencia a localhost expuesta"),
        ]
 
        fugas_encontradas = {}
 
        for nombre_pagina, contenido in paginas_a_analizar:
            for patron, tipo_fuga in patrones_fugas:
                matches = re.findall(patron, contenido)
                if matches:
                    # Filtrar falsos positivos comunes
                    for match in matches:
                        valor = match if isinstance(match, str) else match[-1]
                        # Excluir valores de ejemplo/placeholder
                        if any(excl in valor.lower() for excl in ["example", "placeholder", "your-", "xxx", "test", "demo", "sample", "xxxx"]):
                            continue
                        if tipo_fuga not in fugas_encontradas:
                            fugas_encontradas[tipo_fuga] = nombre_pagina
 
        for tipo_fuga, ubicacion in fugas_encontradas.items():
            if "AWS Access Key" in tipo_fuga or "Secret" in tipo_fuga or "MongoDB" in tipo_fuga or "PostgreSQL" in tipo_fuga or "MySQL" in tipo_fuga:
                resultados.append(f"🚨 **Fuga Critica [{tipo_fuga}]:** Detectado en {ubicacion}. Credenciales expuestas publicamente — acceso inmediato posible.")
            else:
                resultados.append(f"⚠️ **Fuga en Codigo [{tipo_fuga}]:** Detectado en {ubicacion}. Informacion sensible accesible publicamente.")
 
        if not fugas_encontradas:
            resultados.append("✅ **Codigo Fuente:** No se detectaron fugas de credenciales, tokens ni informacion sensible en HTML y JavaScript.")
 
    except Exception:
        resultados.append("⚠️ **Fugas en Codigo:** No se pudo analizar el codigo fuente.")
 
    # =========================================================================
    # 6. SQLi ACTIVO MEJORADO
    # =========================================================================
    print("[ENTERPRISE] Iniciando seccion 6 - SQLi...")
    try:
        payloads_sqli = [
            ("'", "comilla simple"),
            ("''", "doble comilla"),
            ("1' OR '1'='1", "OR classico"),
            ("1; SELECT 1--", "stacked query"),
            ("' OR 1=1--", "OR booleano"),
            ("1 UNION SELECT NULL--", "UNION based"),
            ("1 AND SLEEP(0)--", "time based (safe)"),
            ("' AND '1'='1", "AND booleano"),
            (") OR ('1'='1", "parentesis injection"),
            ("1'; WAITFOR DELAY '0:0:0'--", "MSSQL time based (safe)"),
        ]
 
        errores_sql = [
            "sql syntax", "mysql_fetch", "ora-", "sqlite_", "pg_query",
            "unclosed quotation", "syntax error", "microsoft ole db",
            "odbc driver", "jdbc", "sql server", "mysql error",
            "division by zero", "supplied argument is not a valid mysql",
            "warning: mysql", "invalid query", "sql command not properly ended",
            "quoted string not properly terminated", "sqlstate",
            "you have an error in your sql", "mysql_num_rows",
            "pg_exec", "supplied argument is not a valid postgresql",
        ]
 
        parametros_comunes = [
            {"id": None}, {"q": None}, {"search": None}, {"query": None},
            {"user": None}, {"username": None}, {"email": None},
            {"page": None}, {"cat": None}, {"category": None},
            {"item": None}, {"product": None}, {"pid": None},
        ]
 
        sqli_encontrado = False
        sqli_detalles = []
 
        for payload, nombre_payload in payloads_sqli:
            if sqli_encontrado:
                break
            for params_template in parametros_comunes[:3]:
                try:
                    params = {k: payload for k in params_template}
                    r = requests.get(base, params=params, timeout=3, headers=headers_base)
                    respuesta_lower = r.text.lower()
 
                    for error in errores_sql:
                        if error in respuesta_lower:
                            sqli_detalles.append(f"payload `{nombre_payload}` en parametro `{list(params.keys())[0]}`")
                            sqli_encontrado = True
                            break
 
                    if sqli_encontrado:
                        break
                except Exception:
                    pass
 
        if sqli_encontrado:
            resultados.append(f"🚨 **SQLi Detectado:** El servidor expone errores SQL con {sqli_detalles[0]}. Un atacante puede extraer toda la base de datos.")
        else:
            resultados.append("✅ **SQLi:** No se detectaron errores SQL en las respuestas del servidor.")
 
    except Exception:
        pass
 
    # =========================================================================
    # 7. XSS REFLEJADO MEJORADO
    # =========================================================================
    print("[ENTERPRISE] Iniciando seccion 7 - XSS...")
    try:
        payloads_xss = [
            '<script>alert("xss")</script>',
            '<img src=x onerror=alert(1)>',
            "'><script>alert(1)</script>",
            '<svg onload=alert(1)>',
            '"><img src=x onerror=alert(1)>',
            "javascript:alert(1)",
            '<body onload=alert(1)>',
        ]

        xss_encontrado = False
        xss_detalles = []
        parametros_xss = ["q", "search", "query", "s", "input", "text", "name", "comment", "message"]

        for payload in payloads_xss:
            if xss_encontrado:
                break
            try:
                params = {p: payload for p in parametros_xss[:4]}
                r = requests.get(base, params=params, timeout=5, headers=headers_base)
                contenido = r.text
                payload_escapado_1 = payload.replace("<", "&lt;").replace(">", "&gt;")
                payload_escapado_2 = payload.replace('"', "&quot;").replace("'", "&#39;")
                if payload.lower() in contenido.lower():
                    if payload_escapado_1.lower() not in contenido.lower() and payload_escapado_2.lower() not in contenido.lower():
                        xss_encontrado = True
                        xss_detalles.append(payload[:40])
            except Exception:
                pass

        if xss_encontrado:
            resultados.append(f"🚨 **XSS Reflejado Confirmado:** El servidor devuelve el payload sin sanitizar: `{xss_detalles[0][:40]}`. Un atacante puede robar sesiones de usuarios.")
        else:
            resultados.append("✅ **XSS:** No se detecto reflexion de payloads sin sanitizar en los parametros analizados.")

    except Exception:
        pass
 
    # =========================================================================
    # 8. SUBDOMAIN TAKEOVER
    # =========================================================================
    print("[ENTERPRISE] Iniciando seccion 8 - Subdomain Takeover...")
    try:
        # Lista ampliada de subdominios a verificar
        subdominios_test = [
            "www", "mail", "ftp", "api", "dev", "staging", "test", "admin",
            "portal", "app", "cdn", "static", "blog", "shop", "vpn",
            "webmail", "support", "docs", "beta", "sandbox"
        ]
        
 
        # Servicios vulnerables a subdomain takeover
        servicios_takeover = {
            "github.io": "GitHub Pages",
            "herokuapp.com": "Heroku",
            "azurewebsites.net": "Azure",
            "cloudfront.net": "AWS CloudFront",
            "s3.amazonaws.com": "AWS S3",
            "netlify.app": "Netlify",
            "vercel.app": "Vercel",
            "surge.sh": "Surge",
            "ghost.io": "Ghost",
            "tumblr.com": "Tumblr",
            "wordpress.com": "WordPress.com",
            "shopify.com": "Shopify",
            "squarespace.com": "Squarespace",
            "wixsite.com": "Wix",
            "fastly.net": "Fastly",
            "pantheonsite.io": "Pantheon",
            "helpscoutdocs.com": "HelpScout",
            "zendesk.com": "Zendesk",
            "freshdesk.com": "Freshdesk",
            "unbounce.com": "Unbounce",
            "hubspot.com": "HubSpot",
            "wpengine.com": "WP Engine",
            "agilecrm.com": "Agile CRM",
            "bitbucket.io": "Bitbucket",
        }
 
        # Mensajes de error que indican takeover posible
        mensajes_takeover = [
            "there isn't a github pages site here",
            "no such app",
            "heroku | no such app",
            "the specified bucket does not exist",
            "nosuchdomain",
            "this domain is not configured",
            "page not found - fastly error",
            "project not found",
            "repository not found",
            "this site can't be reached",
            "no se puede acceder",
        ]
 
        takeover_vulnerables = []
        takeover_sospechosos = []
 
        def check_takeover(sub):
            subdominio = f"{sub}.{dominio_limpio}"
            try:
                # Resolver CNAME
                try:
                    respuestas_cname = dns.resolver.resolve(subdominio, "CNAME", lifetime=2)
                    for resp in respuestas_cname:
                        cname_target = str(resp.target).lower().rstrip(".")
                        for servicio_url, servicio_nombre in servicios_takeover.items():
                            if servicio_url in cname_target:
                                # Verificar si el servicio esta reclamado
                                try:
                                    r_check = requests.get(
                                        f"https://{subdominio}",
                                        timeout=2,
                                        headers=headers_base,
                                        allow_redirects=True
                                    )
                                    contenido_lower = r_check.text.lower()
                                    for msg in mensajes_takeover:
                                        if msg in contenido_lower:
                                            return ("VULNERABLE", subdominio, cname_target, servicio_nombre)
                                    if r_check.status_code in (404, 410):
                                        return ("SOSPECHOSO", subdominio, cname_target, servicio_nombre)
                                except Exception:
                                    return ("SOSPECHOSO", subdominio, cname_target, servicio_nombre)
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                    pass
 
                # Verificar A record
                try:
                    dns.resolver.resolve(subdominio, "A")
                except Exception:
                    pass
 
            except Exception:
                pass
            return None
 
        with ThreadPoolExecutor(max_workers=30) as executor:
            futures_td = {executor.submit(check_takeover, sub): sub for sub in subdominios_test}
            for future in as_completed(futures_td, timeout=15):
                res = future.result()
                if res:
                    tipo, sub, cname, servicio = res
                    if tipo == "VULNERABLE":
                        takeover_vulnerables.append((sub, cname, servicio))
                    elif tipo == "SOSPECHOSO":
                        takeover_sospechosos.append((sub, cname, servicio))
 
        if takeover_vulnerables:
            for sub, cname, servicio in takeover_vulnerables:
                resultados.append(f"🚨 **Subdomain Takeover CONFIRMADO [{sub}]:** Apunta a {servicio} ({cname}) que no esta reclamado. Un atacante puede tomar control de este subdominio y servir contenido fraudulento bajo tu dominio.")
        if takeover_sospechosos:
            for sub, cname, servicio in takeover_sospechosos[:3]:
                resultados.append(f"⚠️ **Subdomain Takeover Posible [{sub}]:** Apunta a {servicio} ({cname}). Verificar si el servicio sigue activo y reclamado.")
        if not takeover_vulnerables and not takeover_sospechosos:
            resultados.append("✅ **Subdomain Takeover:** No se detectaron subdominios vulnerables a toma de control entre los 70+ subdominios analizados.")
 
    except Exception:
        resultados.append("⚠️ **Subdomain Takeover:** No se pudo verificar los subdominios.")
 
    # =========================================================================
    # 9. RATE LIMITING (proteccion contra fuerza bruta)
    # =========================================================================
    print("[ENTERPRISE] Iniciando seccion 9 - Rate Limiting...")
    try:
        endpoints_rl = [
            "/login", "/api/login", "/api/auth", "/wp-login.php",
            "/admin/login", "/auth/login", "/signin", "/api/signin",
            "/api/v1/login", "/api/v1/auth",
        ]
 
        rate_limit_detectado = False
        endpoint_probado = None
 
        # Primero verificar que endpoint existe
        endpoint_activo = None
        for ep in endpoints_rl:
            try:
                r_check = requests.get(base + ep, timeout=3, headers=headers_base, allow_redirects=False)
                if r_check.status_code in (200, 405):  # 405 = Method Not Allowed (existe pero no GET)
                    endpoint_activo = ep
                    break
            except Exception:
                pass
 
        if endpoint_activo:
            endpoint_probado = endpoint_activo
            # Enviar 20 peticiones rapidas y ver si bloquea
            for i in range(10):
                try:
                    r_rl = requests.post(
                        base + endpoint_activo,
                        data={"username": f"test{i}@test.com", "password": "wrongpassword123"},
                        timeout=2,
                        headers=headers_base,
                        allow_redirects=False
                    )
                    if r_rl.status_code in (429, 503):
                        rate_limit_detectado = True
                        break
                    # Verificar cabeceras de rate limit
                    if any(h in r_rl.headers for h in ["X-RateLimit-Limit", "X-RateLimit-Remaining", "Retry-After", "RateLimit-Limit"]):
                        rate_limit_detectado = True
                        break
                except Exception:
                    break
        else:
            # Probar en la raiz
            endpoint_probado = "/"
            for i in range(15):
                try:
                    r_rl = requests.get(base, timeout=2, headers=headers_base)
                    if r_rl.status_code == 429:
                        rate_limit_detectado = True
                        break
                except Exception:
                    break
 
        if rate_limit_detectado:
            resultados.append(f"✅ **Rate Limiting:** El servidor detecta y bloquea peticiones excesivas en `{endpoint_probado}`. Protegido contra ataques de fuerza bruta.")
        else:
            if endpoint_probado and endpoint_probado != "/":
                resultados.append(f"⚠️ **Rate Limiting Ausente:** El endpoint `{endpoint_probado}` no bloquea multiples intentos de acceso. Vulnerable a ataques de fuerza bruta de credenciales.")
            else:
                resultados.append("⚠️ **Rate Limiting:** No se detecto proteccion activa contra peticiones excesivas. Posible vulnerabilidad a fuerza bruta.")
 
    except Exception:
        resultados.append("⚠️ **Rate Limiting:** No se pudo verificar la proteccion contra fuerza bruta.")
 
    # =========================================================================
    # 10. CABECERAS DE SEGURIDAD AVANZADAS
    # =========================================================================
    print("[ENTERPRISE] Iniciando seccion 10 - Cabeceras...")
    try:
        r_headers = requests.get(base, timeout=6, headers=headers_base)
        headers_resp = {k.lower(): v for k, v in r_headers.headers.items()}
 
        checks_cabeceras = [
            (
                "cross-origin-embedder-policy",
                "⚠️ **COEP Ausente:** Posible vulnerabilidad a ataques de canal lateral tipo Spectre que pueden leer memoria del navegador.",
                "✅ **COEP:** Proteccion contra ataques de canal lateral activa."
            ),
            (
                "cross-origin-opener-policy",
                "⚠️ **COOP Ausente:** Posible filtracion de datos entre pestanas del navegador mediante ataques de ventana cruzada.",
                "✅ **COOP:** Aislamiento entre pestanas activo."
            ),
            (
                "cross-origin-resource-policy",
                "⚠️ **CORP Ausente:** Los recursos del servidor pueden ser cargados por sitios externos sin restriccion.",
                "✅ **CORP:** Politica de recursos entre origenes correctamente configurada."
            ),
        ]
 
        for cabecera, msg_fallo, msg_ok in checks_cabeceras:
            if cabecera not in headers_resp:
                resultados.append(msg_fallo)
            else:
                resultados.append(msg_ok)
 
        # Verificar CSP si existe y analizarlo
        csp = headers_resp.get("content-security-policy", "")
        if csp:
            csp_lower = csp.lower()
            if "unsafe-inline" in csp_lower:
                resultados.append("⚠️ **CSP Debil:** La directiva 'unsafe-inline' anula la proteccion XSS del CSP. Revisar y endurecer la politica.")
            elif "unsafe-eval" in csp_lower:
                resultados.append("⚠️ **CSP Debil:** La directiva 'unsafe-eval' permite ejecucion de codigo dinamico. Revisar y endurecer la politica.")
            else:
                resultados.append("✅ **CSP:** Content Security Policy presente y sin directivas peligrosas detectadas.")
    except Exception:
        pass
 
    return resultados