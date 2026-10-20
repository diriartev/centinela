#!/usr/bin/env python3
"""Centinela · web señuelo + gateway de sensores web (honeypot HTTP).

- Sitio principal (tu dominio / www): web y portal falsos de una empresa ficticia (marca configurable).
- Subdominios (blog., api., vpn., sso.): se reenvían a sensores de T-Pot (Wordpot, Honeyaml,
  CitrixHoneypot, Log4Pot), cada uno aislado en su propia red con este gateway.
- Rutas desconocidas del sitio principal: se consultan a h0neytr4p (trampas de CVEs).
- TODO queda registrado aquí en JSON (una línea por evento) con la IP real del atacante
  (CF-Connecting-IP), las cabeceras, el cuerpo y si usó algún honeytoken.
Solo librería estándar de Python.
"""
import hashlib, html, http.client, json, os, random, re, secrets, ssl, time
from datetime import datetime, timezone
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs, unquote_plus

LOG = os.environ.get("DECOY_LOG", "/log/decoy.json")
MUESTRAS = os.environ.get("DECOY_MUESTRAS", "/log/muestras")
APP = os.path.dirname(os.path.abspath(__file__))
PLANTILLAS = os.path.join(APP, "pages")
SENSORES = json.loads(os.environ.get("SENSORES", "{}"))          # {"blog.dominio": {"nombre": "wordpot", "url": "http://ip:80"}}
TRAMPAS_CVE = json.loads(os.environ.get("TRAMPAS_CVE", "null"))  # {"nombre": "h0neytr4p", "url": "https://ip:443"}
MAX_BODY = 2 * 1024 * 1024      # lo máximo que se acepta/reenvía
MAX_LOG_BODY = 4096             # lo que se guarda en el log
MAX_RESP = 4 * 1024 * 1024
SALTO = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailers",
         "transfer-encoding", "upgrade", "content-length", "server", "date"}
NO_LOG_CABECERAS = {"cookie", "host", "referer", "origin", "cf-ray", "cf-visitor", "cdn-loop", "cf-ipcountry",
                    "cf-connecting-ip", "x-forwarded-for", "x-forwarded-proto", "accept", "accept-language",
                    "accept-encoding", "connection", "content-length", "cf-warp-tag-id", "user-agent"}
SSL_SENSOR = ssl.create_default_context()
SSL_SENSOR.check_hostname = False
SSL_SENSOR.verify_mode = ssl.CERT_NONE   # los sensores usan certificados autofirmados dentro de su red aislada
try:
    HT_VALORES = json.load(open(os.path.join(APP, "honeytokens.json")))   # lo crea scripts/regenerar-honeytokens.py
except Exception:
    HT_VALORES = {}
HONEYTOKENS = {v: k for k, v in HT_VALORES.items() if len(v) >= 8}
# Marca y dominio del señuelo: variables del despliegue (decoy_marca, cf_dominio), nunca fijas en el código
MARCA = os.environ.get("DECOY_MARCA", "Example Services")
DOMINIO = os.environ.get("DECOY_DOMINIO", "example.com")
SLUG = re.sub(r"[^a-z0-9]+", "-", MARCA.lower()).strip("-") or "empresa"


def personalizar(t):
    t = (t.replace("__MARCA__", MARCA).replace("__DOMINIO__", DOMINIO).replace("__SLUG__", SLUG)
          .replace("__ANIO__", str(datetime.now(timezone.utc).year)))
    return re.sub(r"__HT:([a-z-]+)__", lambda m: HT_VALORES.get(m.group(1), ""), t)

# Portadas creíbles para humanos delante de sensores muy minimalistas (el resto de rutas va al sensor)
PORTADAS = {
    "citrixhoneypot": {"pagina": "netscaler", "rutas": {"/", "/vpn/index.html", "/logon/LogonPoint/index.html", "/vpn/tmindex.html"},
                       "login": {"/cgi/login", "/p/u/doAuthentication.do"}},
    # Log4Pot responde HTML como "text/json": portada propia, pero el sensor recibe igual una copia
    # de la petición (espejo) para que detecte y desofusque los payloads de Log4Shell.
    "log4pot": {"pagina": "sap", "rutas": {"/", "/irj/portal", "/irj/portal/", "/nwa", "/sap/bc/gui/sap/its/webgui"},
                "login": {"/irj/portal", "/j_security_check"}, "espejo": True},
}

TRAMPAS = [  # (patrón de ruta, nombre de la trampa, página/respuesta)
    (r"^/(wp-login\.php|wp-admin/?.*|xmlrpc\.php)$", "wordpress", "wp"),
    (r"^/(phpmyadmin|pma|phpMyAdmin|myadmin)(/.*)?$", "phpmyadmin", "pma"),
    (r"^/\.env(\..*)?$", "dotenv", "env"),
    (r"^/\.git/(config|HEAD)$", "git", "git"),
    (r"^/(actuator|actuator/.*)$", "springboot", "actuator"),
    (r"^/(server-status|server-info)$", "apache-status", "status"),
    (r"^/(backup|db|dump|site|www)\.(zip|sql|tar\.gz|bak)$", "backup", "backup"),
    (r"^/(admin|administrator|cpanel|manager/html|console)(/.*)?$", "admin-panel", "login"),
    (r"^/api/v1/.*$", "api", "api"),
]


def ahora():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def registrar(evento):
    evento["timestamp"] = ahora()
    with open(LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(evento, ensure_ascii=False) + "\n")


def pagina(nombre, **vars_):
    try:
        t = open(os.path.join(PLANTILLAS, nombre + ".html"), encoding="utf-8").read()
    except FileNotFoundError:
        t = open(os.path.join(PLANTILLAS, "404.html"), encoding="utf-8").read()
    for k, v in vars_.items():
        t = t.replace("{{" + k + "}}", html.escape(str(v)))
    return personalizar(t)


def decodificar(texto):
    # Los atacantes codifican sus payloads (%24%7Bjndi…, %2e%2e/): se decodifica dos veces
    t = texto
    for _ in range(2):
        try:
            n = unquote_plus(t)
        except Exception:
            break
        if n == t:
            break
        t = n
    return t


def parece_muestra(cuerpo: bytes, tipo: str) -> bool:
    # Archivos que vale la pena guardar: binarios ELF/PE, scripts y subidas de archivos
    if len(cuerpo) < 64:
        return False
    cabeza = cuerpo[:4096]
    return (cabeza.startswith((b"\x7fELF", b"MZ", b"#!", b"PK\x03\x04")) or b"<?php" in cabeza
            or b"filename=" in cabeza or b"base64_decode" in cabeza or "octet-stream" in tipo)


class Señuelo(BaseHTTPRequestHandler):
    server_version = "nginx/1.24.0"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    def version_string(self):
        return "nginx/1.24.0"

    def log_message(self, *a):
        pass

    def _ip(self):
        return (self.headers.get("CF-Connecting-IP") or self.headers.get("X-Forwarded-For", "").split(",")[0].strip()
                or self.client_address[0])

    def _leer_cuerpo(self) -> bytes:
        if "chunked" in (self.headers.get("Transfer-Encoding") or "").lower():
            datos = b""
            while len(datos) <= MAX_BODY:
                linea = self.rfile.readline(64)
                try:
                    n = int(linea.split(b";")[0].strip() or b"0", 16)
                except ValueError:
                    break
                if n == 0:
                    self.rfile.readline(8)
                    break
                datos += self.rfile.read(min(n, MAX_BODY + 1 - len(datos)))
                self.rfile.readline(8)
            return datos[:MAX_BODY]
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            n = 0
        return self.rfile.read(min(n, MAX_BODY)) if n > 0 else b""

    def _responder(self, codigo, contenido, tipo="text/html; charset=utf-8", extra=None):
        datos = personalizar(contenido).encode("utf-8") if isinstance(contenido, str) else contenido
        self.send_response(codigo)
        if tipo:
            self.send_header("Content-Type", tipo)
        self.send_header("Content-Length", str(len(datos)))
        hay = {k.lower() for k, _ in (extra or [])}
        if "x-content-type-options" not in hay:
            self.send_header("X-Content-Type-Options", "nosniff")
        for k, v in (extra or []):
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(datos)
        return codigo

    def _sensor(self, destino, cuerpo, ip):
        """Reenvía la petición tal cual al sensor y devuelve (código, cabeceras, contenido)."""
        u = urlparse(destino)
        if u.scheme == "https":
            con = http.client.HTTPSConnection(u.hostname, u.port or 443, timeout=20, context=SSL_SENSOR)
        else:
            con = http.client.HTTPConnection(u.hostname, u.port or 80, timeout=20)
        cab = {k: v for k, v in self.headers.items() if k.lower() not in SALTO and not k.lower().startswith("cf-access")}
        cab.update({"X-Forwarded-For": ip, "X-Real-IP": ip, "CF-Connecting-IP": ip, "Connection": "close"})
        if cuerpo:
            cab["Content-Length"] = str(len(cuerpo))
        try:
            con.request(self.command, self.path if self.path.startswith("/") else "/", body=cuerpo or None, headers=cab)
            r = con.getresponse()
            datos = r.read(MAX_RESP)
            cabeceras = [(k, v) for k, v in r.getheaders() if k.lower() not in SALTO]
            return r.status, cabeceras, datos
        finally:
            con.close()

    def _manejar(self):
        url = urlparse(self.path)
        ruta = url.path or "/"
        host = (self.headers.get("Host") or "").split(":")[0].lower()
        ip = self._ip()
        tipo_cuerpo = self.headers.get("Content-Type") or ""
        cuerpo_b = self._leer_cuerpo() if self.command in ("POST", "PUT", "PATCH", "DELETE") else b""
        cuerpo = cuerpo_b.decode("utf-8", "replace")
        url_dec = decodificar(self.path)
        ruta_dec = decodificar(ruta)

        # Honeytokens: ¿usó alguno de los secretos falsos que dejamos expuestos?
        honeytoken = None
        if HONEYTOKENS:
            revisar = " ".join([self.path, url_dec, cuerpo[:65536]] + [v for k, v in self.headers.items()])
            for valor, nombre in HONEYTOKENS.items():
                if valor in revisar:
                    honeytoken = nombre
                    break

        # Credenciales enviadas en formularios o JSON
        usuario = clave = None
        if cuerpo:
            campos = parse_qs(cuerpo)
            for k in ("username", "user", "email", "log", "pma_username", "login", "login_name", "j_username", "uid"):
                if campos.get(k): usuario = campos[k][0][:200]; break
            for k in ("password", "pass", "pwd", "pma_password", "passwd", "passwd1", "j_password"):
                if campos.get(k): clave = campos[k][0][:200]; break
            if not usuario and cuerpo.strip().startswith("{"):
                try:
                    j = json.loads(cuerpo)
                    if isinstance(j, dict):
                        usuario = str(j.get("username") or j.get("email") or j.get("user") or "")[:200] or None
                        clave = str(j.get("password") or j.get("pass") or "")[:200] or None
                except Exception:
                    pass

        # Muestras (scripts, binarios, archivos subidos): se guardan por hash para analizarlas
        muestra = None
        if cuerpo_b and parece_muestra(cuerpo_b, tipo_cuerpo):
            muestra = hashlib.sha256(cuerpo_b).hexdigest()
            try:
                os.makedirs(MUESTRAS, exist_ok=True)
                destino = os.path.join(MUESTRAS, muestra + ".bin")
                if not os.path.exists(destino):
                    with open(destino, "wb") as f:
                        f.write(cuerpo_b)
            except OSError:
                pass

        trampa = sensor = None
        time.sleep(random.uniform(0.05, 0.2))  # latencia realista

        portada = PORTADAS.get(SENSORES.get(host, {}).get("nombre"))
        if portada and ((self.command in ("GET", "HEAD") and ruta in portada["rutas"]) or (self.command == "POST" and ruta in portada["login"])):
            sensor = SENSORES[host]["nombre"]
            trampa = "portal-login" if self.command == "POST" else "portal"
            if portada.get("espejo"):
                try:
                    self._sensor(SENSORES[host]["url"], cuerpo_b, ip)
                except Exception:
                    pass
            codigo = self._responder(200, pagina(portada["pagina"], error="Incorrect credentials. Try again." if self.command == "POST" else ""))
        elif host in SENSORES:
            sensor = SENSORES[host]["nombre"]
            try:
                codigo, cab, datos = self._sensor(SENSORES[host]["url"], cuerpo_b, ip)
                codigo = self._responder(codigo, datos, None, cab)
            except Exception:
                codigo = self._responder(502, pagina("404"))
        else:
            vista = None
            for patron, nombre, v in TRAMPAS:
                if re.match(patron, ruta):
                    trampa, vista = nombre, v
                    break
            if ruta in ("/", "/index.html"):
                codigo = self._responder(200, pagina("index"))
            elif ruta == "/robots.txt":
                codigo = self._responder(200, "User-agent: *\nDisallow: /admin/\nDisallow: /api/v1/\nDisallow: /respaldos/\n"
                                         "Disallow: /.env\nSitemap: https://__DOMINIO__/sitemap.xml\n", "text/plain")
            elif ruta == "/sitemap.xml":
                urls = ["https://__DOMINIO__/", "https://__DOMINIO__/portal", "https://blog.__DOMINIO__/",
                        "https://api.__DOMINIO__/"]
                codigo = self._responder(200, '<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
                                         + "".join(f"<url><loc>{u}</loc></url>" for u in urls) + "</urlset>\n", "application/xml")
            elif ruta == "/favicon.ico":
                codigo = self._responder(204, b"", None)
            elif ruta in ("/login", "/portal", "/portal/login") or vista in ("login", "wp", "pma"):
                pag = {"wp": "wp", "pma": "pma"}.get(vista, "login")
                trampa = trampa or ("portal-login" if self.command == "POST" else "portal")
                codigo = self._responder(200, pagina(pag, error="Usuario o contraseña incorrectos." if self.command == "POST" else ""))
            elif vista == "env":
                codigo = self._responder(200, pagina("env_txt"), "text/plain")
            elif vista == "git":
                codigo = self._responder(200, "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n\tlogallrefupdates = true\n"
                                         "[remote \"origin\"]\n\turl = git@git.__SLUG__.internal:web/sitio.git\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n"
                                         "[branch \"main\"]\n\tremote = origin\n\tmerge = refs/heads/main\n", "text/plain")
            elif vista == "actuator":
                codigo = self._responder(200, json.dumps({"activeProfiles": ["prod"], "propertySources": [{"name": "systemEnvironment", "properties": {
                    "DB_HOST": {"value": "db-01.__SLUG__.internal"}, "DB_PASSWORD": {"value": "******"}, "APP_API_URL": {"value": "https://api.__DOMINIO__/v1"}}}]}),
                    "application/json")
            elif vista == "status":
                codigo = self._responder(403, pagina("403"))
            elif vista == "backup":
                codigo = self._responder(200, b"PK\x03\x04" + secrets.token_bytes(512), "application/zip")
            elif vista == "api":
                codigo = self._responder(401, json.dumps({"error": "unauthorized", "message": "Missing or invalid API token",
                                                          "docs": "https://api.__DOMINIO__/"}), "application/json")
            else:
                # Ruta desconocida: ¿coincide con alguna trampa de CVE de h0neytr4p?
                codigo = None
                if TRAMPAS_CVE:
                    try:
                        c, cab, datos = self._sensor(TRAMPAS_CVE["url"], cuerpo_b, ip)
                        if c != 404 and datos:
                            sensor = TRAMPAS_CVE["nombre"]
                            codigo = self._responder(c, datos, None, cab)
                    except Exception:
                        pass
                if codigo is None:
                    codigo = self._responder(404, pagina("404"))

        # El chequeo de salud del propio contenedor no es un ataque: no se registra
        if self.client_address[0] == "127.0.0.1" and not self.headers.get("CF-Connecting-IP"):
            return
        cabeceras = {k.lower(): v[:512] for k, v in list(self.headers.items())[:40] if k.lower() not in NO_LOG_CABECERAS}
        registrar({
            "src_ip": ip,
            "method": self.command,
            "path": ruta[:1024],
            "url": self.path[:2048],
            "url_decoded": url_dec[:2048],
            "path_decoded": ruta_dec[:1024],
            "status": codigo,
            "user_agent": (self.headers.get("User-Agent") or "")[:512],
            "referer": (self.headers.get("Referer") or "")[:512],
            "host": host[:200],
            "headers": cabeceras or None,
            "cf_country": self.headers.get("CF-IPCountry"),
            "cf_ray": self.headers.get("CF-Ray"),
            "sensor": sensor or "web",
            "trap": trampa,
            "username": usuario,
            "password": clave,
            "honeytoken": honeytoken,
            "body": cuerpo[:MAX_LOG_BODY] if cuerpo else None,
            "body_decoded": (decodificar(cuerpo)[:MAX_LOG_BODY] if cuerpo and ("%" in cuerpo or "+" in cuerpo) else None),
            "body_bytes": len(cuerpo_b) or None,
            "muestra_sha256": muestra,
            "eventid": ("web.honeytoken" if honeytoken else "web.credenciales" if clave else
                        "web.trampa" if trampa else "web.sensor" if sensor else "web.visita"),
        })

    do_GET = do_POST = do_HEAD = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = _manejar


if __name__ == "__main__":
    ThreadingHTTPServer.daemon_threads = True
    ThreadingHTTPServer.request_queue_size = 64
    srv = ThreadingHTTPServer(("0.0.0.0", 8080), Señuelo)
    srv.serve_forever()
