import os
import ssl
import socket
import requests
import dns.resolver
from datetime import datetime, timezone

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
            resultados_reales.append(f"🌐 **DNS / OSINT:** Resolución obtenida → {muestra}{suf}")
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
        respuesta = requests.get(url, timeout=5, headers=headers_pro)
        cabeceras = respuesta.headers

        checks = {
            "X-Frame-Options": "⚠️  Falta proteccion contra clonado (Clickjacking).",
            "Strict-Transport-Security": "⚠️  Falta HSTS (Forzar HTTPS).",
            "Content-Security-Policy": "⚠️  Falta CSP (Prevención de inyecciones de codigo).",
            "X-Content-Type-Options": "⚠️  Falta X-Content-Type-Options.",
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


def _motor_pro_activo(dominio_limpio, incluir_cve_matching):
    """Mapeo de puertos con banner grabbing, fuzzing ampliado y CVE matching por software detectado."""
    resultados_reales = []
    puertos_web_abiertos = False
    software_detectado = []

    # --- Mapeo de puertos + Banner Grabbing ---
    puertos_clave = {80: "HTTP (Sin cifrar)", 443: "HTTPS (Seguro)"}
    for puerto, desc in puertos_clave.items():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.5)
            if s.connect_ex((dominio_limpio, puerto)) == 0:
                puertos_web_abiertos = True
                resultados_reales.append(f"🟢 **Puerto {puerto} Abierto:** {desc}")
                # Banner Grabbing
                try:
                    s.send(b"HEAD / HTTP/1.0\r\nHost: " + dominio_limpio.encode() + b"\r\n\r\n")
                    banner = s.recv(1024).decode(errors="ignore")
                    # Extraer servidor del banner
                    for linea in banner.split("\n"):
                        if linea.lower().startswith("server:"):
                            servidor = linea.split(":", 1)[1].strip()
                            resultados_reales.append(f"🔍 **Banner Puerto {puerto}:** {servidor}")
                            software_detectado.append(servidor)
                            break
                except Exception:
                    pass
            else:
                resultados_reales.append(f"🔴 **Puerto {puerto} Cerrado:** {desc}")
            s.close()
        except Exception:
            pass

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
        "/.well-known", "/security.txt", "/crossdomain.xml", "/clientaccesspolicy.xml"
    ]
    headers_pro = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0"
    }
    base = f"https://{dominio_limpio}"
    for path in rutas_comunes:
        try:
            r = requests.head(f"{base}{path}", timeout=2.5, headers=headers_pro, allow_redirects=True)
            if r.status_code in (200, 301, 302, 401, 403):
                # Clasificar por severidad
                if path in ["/.env", "/wp-config.php", "/.git", "/backup.zip", "/backup.sql", "/db.sql"]:
                    emoji = "🚨"
                elif path in ["/admin", "/wp-admin", "/phpmyadmin", "/cpanel", "/shell", "/cmd"]:
                    emoji = "⚠️"
                else:
                    emoji = "📂"
                resultados_reales.append(
                    f"{emoji} **Fuzzing web:** Respuesta ({r.status_code}) → `{path}`"
                )
        except Exception:
            pass

    # --- CVE Matching por software detectado en banner ---
    if incluir_cve_matching and puertos_web_abiertos:
        keywords = software_detectado if software_detectado else [dominio_limpio]
        for keyword in keywords[:2]:  # Máximo 2 búsquedas para no saturar la API
            try:
                nvd_key = os.getenv("NVD_API_KEY", "")
                headers_nvd = {"apiKey": nvd_key} if nvd_key else {}
                r_nvd = requests.get(
                    "https://services.nvd.nist.gov/rest/json/cves/2.0",
                    params={"keywordSearch": keyword, "resultsPerPage": 5},
                    headers=headers_nvd,
                    timeout=10
                )
                if r_nvd.status_code == 200:
                    cves = r_nvd.json().get("vulnerabilities", [])
                    if cves:
                        for cve in cves[:3]:
                            cve_id = cve["cve"]["id"]
                            desc = cve["cve"]["descriptions"][0]["value"][:120]
                            # Extraer severidad CVSS si existe
                            try:
                                severidad = cve["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"]["baseSeverity"]
                            except Exception:
                                severidad = "UNKNOWN"
                            emoji_sev = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(severidad, "⚪")
                            resultados_reales.append(
                                f"🚨 **CVE [{emoji_sev}{severidad}]:** {cve_id} ({keyword}) — {desc}..."
                            )
                    else:
                        resultados_reales.append(f"📋 **CVE Matching ({keyword}):** No se encontraron CVEs conocidos.")
                else:
                    resultados_reales.append("📋 **CVE Matching:** No se pudo conectar con NVD/MITRE.")
            except Exception as e:
                resultados_reales.append(f"📋 **CVE Matching:** Error al consultar NVD: {str(e)[:50]}")

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