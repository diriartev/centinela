#!/usr/bin/env python3
"""Centinela · Centro de mando (backend).
Solo lectura: consulta Elasticsearch con un usuario de solo lectura y el estado
de los contenedores que escribe el host en /status/estado.json.
Detrás de Cloudflare Access; además valida el correo que inyecta Access.
"""
import json, os, ssl, base64, time, urllib.request, urllib.error
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

ES = os.environ.get("ES_URL", "https://10.213.252.10:9200")
AUTH = "Basic " + base64.b64encode(f"centinela_panel:{os.environ['ES_PASSWORD']}".encode()).decode()
CTX = ssl.create_default_context(cafile="/certs/ca.crt")
CTX.check_hostname = False   # se valida la CA propia; el certificado es por IP interna
PERMITIDOS = {e.strip().lower() for e in os.environ.get("CORREOS_PERMITIDOS", "").split(",") if e.strip()}
ESTATICOS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
RANGOS = {"1h": "now-1h", "24h": "now-24h", "7d": "now-7d", "30d": "now-30d"}
INTERVALO = {"1h": "2m", "24h": "30m", "7d": "3h", "30d": "12h"}
TIPOS = {".html": "text/html; charset=utf-8", ".js": "application/javascript", ".css": "text/css", ".png": "image/png", ".svg": "image/svg+xml", ".ico": "image/x-icon"}
CACHE = {}

def es(ruta, cuerpo=None):
    clave = ruta + json.dumps(cuerpo, sort_keys=True)
    if clave in CACHE and CACHE[clave][0] > time.time():
        return CACHE[clave][1]
    req = urllib.request.Request(ES + ruta, data=json.dumps(cuerpo).encode() if cuerpo is not None else None,
                                 headers={"Authorization": AUTH, "Content-Type": "application/json"},
                                 method="POST" if cuerpo is not None else "GET")
    try:
        with urllib.request.urlopen(req, context=CTX, timeout=15) as r:
            datos = json.loads(r.read())
    except urllib.error.HTTPError as e:
        if e.code == 404:
            datos = {}
        else:
            raise
    CACHE[clave] = (time.time() + 5, datos)
    return datos

def filtro(rango):
    return {"range": {"@timestamp": {"gte": RANGOS.get(rango, "now-24h")}}}

def resumen(rango):
    r = es("/honeypot-events/_search", {"size": 0, "track_total_hits": True, "query": filtro(rango), "aggs": {
        "ips": {"cardinality": {"field": "source.ip"}},
        "paises": {"cardinality": {"field": "source.geo.country_iso_code"}},
        "creds": {"filter": {"exists": {"field": "honeypot.password"}}},
        "cmds": {"filter": {"exists": {"field": "honeypot.command"}}},
        "graves": {"filter": {"range": {"event.severity": {"gte": 3}}}},
        "criticos": {"filter": {"range": {"event.severity": {"gte": 4}}}},
        "tokens": {"filter": {"exists": {"field": "honeypot.honeytoken"}}},
        "sev": {"terms": {"field": "event.severity", "size": 5}},
        "sensor": {"terms": {"field": "honeypot.sensor", "size": 20}, "aggs": {"ultimo": {"max": {"field": "@timestamp"}}}},
        "hp": {"terms": {"field": "honeypot.type", "size": 20}, "aggs": {"ultimo": {"max": {"field": "@timestamp"}}}}}})
    a = r.get("aggregations", {})
    return {"eventos": r.get("hits", {}).get("total", {}).get("value", 0), "ips": a.get("ips", {}).get("value", 0),
            "paises": a.get("paises", {}).get("value", 0), "credenciales": a.get("creds", {}).get("doc_count", 0),
            "comandos": a.get("cmds", {}).get("doc_count", 0), "graves": a.get("graves", {}).get("doc_count", 0),
            "criticos": a.get("criticos", {}).get("doc_count", 0), "honeytokens": a.get("tokens", {}).get("doc_count", 0),
            "por_severidad": {str(b["key"]): b["doc_count"] for b in a.get("sev", {}).get("buckets", [])},
            "por_sensor": [{"tipo": b["key"], "eventos": b["doc_count"], "ultimo": b["ultimo"].get("value_as_string")} for b in a.get("sensor", {}).get("buckets", [])],
            "por_honeypot": [{"tipo": b["key"], "eventos": b["doc_count"], "ultimo": b["ultimo"].get("value_as_string")} for b in a.get("hp", {}).get("buckets", [])]}

def serie(rango):
    r = es("/honeypot-events/_search", {"size": 0, "query": filtro(rango), "aggs": {"t": {"date_histogram": {
        "field": "@timestamp", "fixed_interval": INTERVALO.get(rango, "30m"), "min_doc_count": 0,
        "extended_bounds": {"min": RANGOS.get(rango, "now-24h"), "max": "now"}}, "aggs": {"hp": {"terms": {"field": "honeypot.type", "size": 20}}}}}})
    out = []
    for b in r.get("aggregations", {}).get("t", {}).get("buckets", []):
        out.append({"t": b["key_as_string"], **{x["key"]: x["doc_count"] for x in b["hp"]["buckets"]}})
    return out

def mapa(rango):
    r = es("/honeypot-events/_search", {"size": 0, "query": {"bool": {"filter": [filtro(rango), {"exists": {"field": "source.geo.location"}}]}},
        "aggs": {"g": {"geotile_grid": {"field": "source.geo.location", "precision": 6, "size": 800},
                       "aggs": {"c": {"geo_centroid": {"field": "source.geo.location"}}, "pais": {"terms": {"field": "source.geo.country_name", "size": 1}},
                                "ciudad": {"terms": {"field": "source.geo.city_name", "size": 1}}, "ips": {"cardinality": {"field": "source.ip"}},
                                "sev": {"max": {"field": "event.severity"}}}}}})
    puntos = []
    for b in r.get("aggregations", {}).get("g", {}).get("buckets", []):
        loc = b["c"].get("location")
        if not loc: continue
        puntos.append({"tile": b["key"], "lat": loc["lat"], "lon": loc["lon"], "n": b["doc_count"], "ips": b["ips"]["value"],
                       "pais": (b["pais"]["buckets"] or [{"key": "?"}])[0]["key"], "ciudad": (b["ciudad"]["buckets"] or [{"key": ""}])[0]["key"],
                       "sev": int(b["sev"].get("value") or 0)})
    return puntos

CAMPOS = {"ips": "source.ip", "paises": "source.geo.country_name", "asn": "source.as.organization.name", "usuarios": "user.name",
          "claves": "honeypot.password", "comandos": "honeypot.command.keyword", "puertos": "destination.port", "rutas": "url.path",
          "trampas": "honeypot.trap", "acciones": "event.action", "ataques": "ataque.nombre", "tecnicas": "threat.technique.id",
          "sensores": "honeypot.sensor", "categorias": "ataque.categoria"}

def top(campo, rango, n=10):
    f = CAMPOS.get(campo)
    if not f: return []
    r = es("/honeypot-events/_search", {"size": 0, "query": filtro(rango), "aggs": {"t": {"terms": {"field": f, "size": min(int(n), 50)}}}})
    return [{"valor": b["key"], "n": b["doc_count"]} for b in r.get("aggregations", {}).get("t", {}).get("buckets", [])]

def feed(n=40):
    r = es("/honeypot-events/_search", {"size": min(int(n), 100), "sort": [{"@timestamp": "desc"}], "_source": [
        "@timestamp", "honeypot.type", "honeypot.trap", "honeypot.command", "honeypot.password", "source.ip", "source.geo.country_name",
        "source.geo.country_iso_code", "source.geo.city_name", "source.as.organization.name", "destination.port", "user.name", "event.action", "url.path", "http.request.method",
        "honeypot.sensor", "honeypot.honeytoken", "url.domain", "ataque.nombre", "ataque.severidad", "ataque.cve", "threat.technique.id"]})
    return [h["_source"] for h in r.get("hits", {}).get("hits", [])]

def ataques(rango):
    """Tipos de ataque del rango, del más grave al más leve, con su explicación y un ejemplo real."""
    r = es("/honeypot-events/_search", {"size": 0, "query": {"bool": {"filter": [filtro(rango), {"exists": {"field": "ataque.id"}}]}}, "aggs": {
        "a": {"terms": {"field": "ataque.id", "size": 40, "order": [{"sev": "desc"}, {"_count": "desc"}]}, "aggs": {
            "sev": {"max": {"field": "ataque.severidad"}}, "ips": {"cardinality": {"field": "source.ip"}},
            "ultimo": {"max": {"field": "@timestamp"}}, "paises": {"terms": {"field": "source.geo.country_iso_code", "size": 4}},
            "sensores": {"terms": {"field": "honeypot.sensor", "size": 4, "missing": "red"}},
            "ej": {"top_hits": {"size": 1, "sort": [{"@timestamp": "desc"}], "_source": ["ataque", "threat", "honeypot.command", "honeypot.type",
                    "url.original", "url.domain", "http.request.method", "source.ip", "source.geo.country_name", "user.name", "honeypot.password"]}}}}}})
    out = []
    for b in r.get("aggregations", {}).get("a", {}).get("buckets", []):
        s = (b["ej"]["hits"]["hits"] or [{"_source": {}}])[0]["_source"]
        at, th, hp = s.get("ataque", {}), (s.get("threat") or {}), s.get("honeypot", {}) or {}
        if hp.get("command"): ej = hp["command"]
        elif (s.get("url") or {}).get("original"): ej = ((s.get("http") or {}).get("request") or {}).get("method", "GET") + " " + (s["url"].get("domain") or "") + s["url"]["original"]
        elif hp.get("password"): ej = f"{(s.get('user') or {}).get('name', '?')} / {hp['password']}"
        else: ej = ""
        out.append({"id": b["key"], "nombre": at.get("nombre"), "categoria": at.get("categoria"), "severidad": int(b["sev"]["value"] or 1),
                    "explicacion": at.get("explicacion"), "recomendacion": at.get("recomendacion"), "cve": at.get("cve"), "fuente": at.get("fuente"),
                    "tactica": (th.get("tactic") or {}).get("name"), "tecnica_id": (th.get("technique") or {}).get("id"),
                    "tecnica": (th.get("technique") or {}).get("name"), "eventos": b["doc_count"], "ips": b["ips"]["value"],
                    "ultimo": b["ultimo"].get("value_as_string"), "paises": [x["key"] for x in b["paises"]["buckets"]],
                    "sensores": [x["key"] for x in b["sensores"]["buckets"]], "ejemplo": ej[:300],
                    "ejemplo_ip": (s.get("source") or {}).get("ip"), "ejemplo_pais": ((s.get("source") or {}).get("geo") or {}).get("country_name")})
    return out

def zona(tile, rango):
    """Detalle de un punto del mapa: IPs, qué hicieron y la explicación de sus ataques."""
    import re as _re
    if not _re.fullmatch(r"\d{1,2}/\d{1,7}/\d{1,7}", tile or ""):
        return {"error": "zona inválida"}
    q = {"bool": {"filter": [filtro(rango), {"geo_grid": {"source.geo.location": {"geotile": tile}}}]}}
    r = es("/honeypot-events/_search", {"size": 0, "track_total_hits": True, "query": q, "aggs": {
        "lugar": {"terms": {"field": "source.geo.city_name", "size": 1}}, "pais": {"terms": {"field": "source.geo.country_name", "size": 1}},
        "iso": {"terms": {"field": "source.geo.country_iso_code", "size": 1}},
        "ips": {"terms": {"field": "source.ip", "size": 15}, "aggs": {
            "asn": {"terms": {"field": "source.as.organization.name", "size": 1}}, "ciudad": {"terms": {"field": "source.geo.city_name", "size": 1}},
            "primero": {"min": {"field": "@timestamp"}}, "ultimo": {"max": {"field": "@timestamp"}}, "sev": {"max": {"field": "event.severity"}},
            "sensores": {"terms": {"field": "honeypot.sensor", "size": 4, "missing": "red"}},
            "ataques": {"terms": {"field": "ataque.nombre", "size": 6}, "aggs": {"sev": {"max": {"field": "ataque.severidad"}}}},
            "ej": {"top_hits": {"size": 3, "sort": [{"event.severity": {"order": "desc", "missing": "_last"}}, {"@timestamp": "desc"}],
                   "_source": ["@timestamp", "url.original", "url.domain", "http.request.method", "honeypot.command", "user.name", "honeypot.password", "honeypot.type", "honeypot.sensor"]}}}},
        "ataques": {"terms": {"field": "ataque.id", "size": 8, "order": [{"sev": "desc"}, {"_count": "desc"}]}, "aggs": {
            "sev": {"max": {"field": "ataque.severidad"}},
            "ej": {"top_hits": {"size": 1, "_source": ["ataque.nombre", "ataque.explicacion", "ataque.recomendacion", "ataque.cve", "threat"]}}}}}})
    a = r.get("aggregations", {})
    k = lambda x, c: ((x.get(c) or {}).get("buckets") or [{"key": None}])[0]["key"]
    ips = []
    for b in a.get("ips", {}).get("buckets", []):
        ejemplos = []
        for h in b["ej"]["hits"]["hits"]:
            s_, hp = h["_source"], h["_source"].get("honeypot", {}) or {}
            if hp.get("command"): t = hp["command"]
            elif (s_.get("url") or {}).get("original"): t = ((s_.get("http") or {}).get("request") or {}).get("method", "GET") + " " + ((s_.get("url") or {}).get("domain") or "") + s_["url"]["original"]
            elif hp.get("password"): t = f"login {(s_.get('user') or {}).get('name', '?')} / {hp['password']}"
            else: t = hp.get("type", "")
            ejemplos.append({"t": s_.get("@timestamp"), "texto": t[:220]})
        ips.append({"ip": b["key"], "eventos": b["doc_count"], "asn": k(b, "asn"), "ciudad": k(b, "ciudad"),
                    "primero": b["primero"].get("value_as_string"), "ultimo": b["ultimo"].get("value_as_string"),
                    "severidad": int(b["sev"]["value"] or 0), "sensores": [x["key"] for x in b["sensores"]["buckets"]],
                    "ataques": [{"nombre": x["key"], "n": x["doc_count"], "severidad": int(x["sev"]["value"] or 1)} for x in b["ataques"]["buckets"]],
                    "ejemplos": ejemplos})
    ataques = []
    for b in a.get("ataques", {}).get("buckets", []):
        s_ = (b["ej"]["hits"]["hits"] or [{"_source": {}}])[0]["_source"]; at = s_.get("ataque", {}); th = (s_.get("threat") or {})
        ataques.append({"id": b["key"], "nombre": at.get("nombre"), "severidad": int(b["sev"]["value"] or 1), "n": b["doc_count"],
                        "explicacion": at.get("explicacion"), "recomendacion": at.get("recomendacion"), "cve": at.get("cve"),
                        "tecnica_id": (th.get("technique") or {}).get("id"), "tecnica": (th.get("technique") or {}).get("name")})
    return {"tile": tile, "eventos": r.get("hits", {}).get("total", {}).get("value", 0), "ciudad": k(a, "lugar"), "pais": k(a, "pais"),
            "iso": k(a, "iso"), "ips": ips, "ataques": ataques}

def muestras(rango):
    """Malware y archivos capturados: hashes de archivos subidos y URLs de descarga vistas en los ataques."""
    r = es("/honeypot-events/_search", {"size": 30, "sort": [{"@timestamp": "desc"}], "query": {"bool": {"filter": [filtro(rango)], "should": [
        {"exists": {"field": "honeypot.file_hash"}}, {"exists": {"field": "ataque.urls"}}], "minimum_should_match": 1}},
        "_source": ["@timestamp", "honeypot.file_hash", "ataque.urls", "ataque.nombre", "source.ip", "source.geo.country_iso_code", "honeypot.sensor", "honeypot.type"]})
    return [h["_source"] for h in r.get("hits", {}).get("hits", [])]

def cloudflare(rango):
    m = es("/cloudflare-metrics/_search", {"size": 0, "query": {"bool": {"filter": [filtro(rango), {"term": {"cf.metric": "trafico"}}]}}, "aggs": {
        "req": {"sum": {"field": "cf.requests"}}, "thr": {"sum": {"field": "cf.threats"}}, "bytes": {"sum": {"field": "cf.bytes"}},
        "cache": {"sum": {"field": "cf.cached_requests"}},
        "t": {"date_histogram": {"field": "@timestamp", "fixed_interval": INTERVALO.get(rango, "30m"), "min_doc_count": 0},
              "aggs": {"req": {"sum": {"field": "cf.requests"}}, "thr": {"sum": {"field": "cf.threats"}}}}}})
    p = es("/cloudflare-metrics/_search", {"size": 0, "query": {"bool": {"filter": [filtro(rango), {"term": {"cf.metric": "pais"}}]}},
           "aggs": {"p": {"terms": {"field": "cf.country", "size": 8}, "aggs": {"r": {"sum": {"field": "cf.requests"}}}}}})
    ev = es("/cloudflare-events/_search", {"size": 15, "sort": [{"@timestamp": "desc"}], "query": filtro(rango)})
    a = m.get("aggregations", {})
    return {"solicitudes": a.get("req", {}).get("value", 0), "amenazas": a.get("thr", {}).get("value", 0), "bytes": a.get("bytes", {}).get("value", 0),
            "cache": a.get("cache", {}).get("value", 0),
            "serie": [{"t": b["key_as_string"], "req": b["req"]["value"], "thr": b["thr"]["value"]} for b in a.get("t", {}).get("buckets", [])],
            "paises": [{"valor": b["key"], "n": b["r"]["value"]} for b in p.get("aggregations", {}).get("p", {}).get("buckets", [])],
            "eventos": [h["_source"] for h in ev.get("hits", {}).get("hits", [])]}

def estado():
    try:
        with open("/status/estado.json", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"contenedores": [], "host": {}, "actualizado": None}

class Panel(BaseHTTPRequestHandler):
    server_version = "Centinela"
    sys_version = ""
    def log_message(self, *a): pass

    def _enviar(self, codigo, cuerpo, tipo="application/json"):
        datos = cuerpo if isinstance(cuerpo, bytes) else (json.dumps(cuerpo, ensure_ascii=False) if not isinstance(cuerpo, str) else cuerpo).encode()
        self.send_response(codigo)
        self.send_header("Content-Type", tipo)
        self.send_header("Content-Length", str(len(datos)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; img-src 'self' data: https://assets.example.com; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'")
        self.end_headers()
        self.wfile.write(datos)

    def do_GET(self):
        if self.path == "/salud":   # chequeo de salud: sin datos
            return self._enviar(200, {"ok": True})
        correo = (self.headers.get("Cf-Access-Authenticated-User-Email") or "").lower()
        if PERMITIDOS and correo not in PERMITIDOS:
            return self._enviar(403, {"error": "acceso restringido"})
        u = urlparse(self.path); q = parse_qs(u.query); rango = q.get("rango", ["24h"])[0]
        try:
            if u.path == "/api/resumen": return self._enviar(200, resumen(rango))
            if u.path == "/api/serie": return self._enviar(200, serie(rango))
            if u.path == "/api/mapa": return self._enviar(200, mapa(rango))
            if u.path == "/api/top": return self._enviar(200, top(q.get("campo", ["ips"])[0], rango, q.get("n", ["10"])[0]))
            if u.path == "/api/feed": return self._enviar(200, feed(q.get("n", ["40"])[0]))
            if u.path == "/api/cloudflare": return self._enviar(200, cloudflare(rango))
            if u.path == "/api/ataques": return self._enviar(200, ataques(rango))
            if u.path == "/api/muestras": return self._enviar(200, muestras(rango))
            if u.path == "/api/zona": return self._enviar(200, zona(q.get("tile", [""])[0], rango))
            if u.path == "/api/estado": return self._enviar(200, estado())
            if u.path == "/api/yo": return self._enviar(200, {"correo": correo})
        except Exception as e:
            return self._enviar(502, {"error": "no se pudo consultar Elasticsearch", "detalle": type(e).__name__})
        ruta = "index.html" if u.path in ("/", "") else u.path.lstrip("/")
        archivo = os.path.realpath(os.path.join(ESTATICOS, ruta))
        if not archivo.startswith(ESTATICOS + os.sep) or not os.path.isfile(archivo):
            return self._enviar(404, {"error": "no encontrado"})
        with open(archivo, "rb") as f:
            return self._enviar(200, f.read(), TIPOS.get(os.path.splitext(archivo)[1], "application/octet-stream"))

if __name__ == "__main__":
    ThreadingHTTPServer.daemon_threads = True
    ThreadingHTTPServer((os.environ.get("ESCUCHAR", "0.0.0.0"), 8080), Panel).serve_forever()
