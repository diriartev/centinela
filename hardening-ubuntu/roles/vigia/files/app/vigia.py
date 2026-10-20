#!/usr/bin/env python3
"""Centinela · Vigía de alertas.

Cada minuto revisa Elasticsearch (solo lectura) y el estado del servidor, y manda al bot de
Telegram, a través del Worker de Cloudflare y con firma HMAC:
  · alertas de ataques graves (severidad alta/crítica), explicadas y agrupadas por IP + ataque
  · uso de honeytokens, logins en la consola (Cloudflare Access), port knocking y SSH al servidor real
  · integridad del servidor real: AIDE (archivos cambiados) y auditd (cambios sensibles en tiempo real)
  · muestras de malware: URLs de descarga (las baja el Worker, nunca este servidor) y archivos subidos
  · salud: contenedores caídos, disco lleno, Elasticsearch en rojo
  · un resumen cada 5 min para los comandos del bot y un informe diario a las 08:00 (Bogotá)
Solo librería estándar. No tiene acceso a Docker ni al host: lee archivos montados en solo lectura.
"""
import base64, hashlib, hmac, html, json, os, ssl, threading, time, urllib.error, urllib.request, uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from datetime import datetime, timedelta, timezone
from zipcifrado import zip_cifrado

ES = os.environ.get("ES_URL", "https://10.213.252.10:9200")
ES_AUTH = "Basic " + base64.b64encode(f"centinela_vigia:{os.environ['ES_PASSWORD']}".encode()).decode()
ES_CTX = ssl.create_default_context(cafile="/certs/ca.crt"); ES_CTX.check_hostname = False
RELAY = os.environ.get("RELAY_URL", "https://hooks.example.com").rstrip("/")
RELAY_KEY = open("/run/secrets/relay_key").read().strip()
CONSOLA = os.environ.get("CONSOLA_URL", "https://console.example.com")
GRAFANA = os.environ.get("GRAFANA_URL", "https://metrics.example.com")
ADMIN = os.environ.get("ADMIN_EMAIL", "admin@example.com").lower()
ESCUCHAR_ALERTAS = os.environ.get("ESCUCHAR_ALERTAS", "")
try:
    ALERTAS_TOKEN = open("/run/secrets/alertas_token").read().strip()
except OSError:
    ALERTAS_TOKEN = ""
ESTADO_HOST = "/host/estado.json"
ESTADO = "/estado/vigia.json"
CUARENTENA = "/cuarentena"   # muestras cifradas (ZIP "infected") que quedan en el servidor para análisis
CARPETAS_MUESTRAS = {  # carpeta montada → origen legible
    "/muestras/web": "Señuelo web (archivo subido)",
    "/muestras/h0neytr4p": "Sensor h0neytr4p (payload)",
    "/muestras/log4pot": "Sensor Log4Pot (payload)",
    "/muestras/cowrie": "Cowrie (descarga del atacante)",
    "/muestras/dionaea": "Dionaea (binario capturado)",
    "/muestras/adbhoney": "ADBHoney (APK/descarga)",
}
REPETIR_HORAS = 6           # misma IP + mismo ataque: una alerta cada 6 h
MAX_ALERTAS_HORA = 30
SEV = {3: "🟠 ALTA", 4: "🔴 CRÍTICA"}
BOGOTA = timezone(timedelta(hours=-5))


def log(*a):
    print(datetime.now(timezone.utc).strftime("%H:%M:%S"), *a, flush=True)


def esc(t):
    return html.escape(str(t if t is not None else ""), quote=False)


def bandera(cc):
    return "".join(chr(127397 + ord(c)) for c in cc.upper()) if cc and len(cc) == 2 and cc.isalpha() else "🏳️"


# ── Elasticsearch ────────────────────────────────────────────────────
def es(ruta, cuerpo=None):
    req = urllib.request.Request(ES + ruta, data=json.dumps(cuerpo).encode() if cuerpo is not None else None,
                                 headers={"Authorization": ES_AUTH, "Content-Type": "application/json"},
                                 method="POST" if cuerpo is not None else "GET")
    try:
        with urllib.request.urlopen(req, context=ES_CTX, timeout=20) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {}
        raise


# ── Relay (Worker de Cloudflare), firmado ────────────────────────────
def relay_crudo(ruta, cuerpo: bytes, tipo="application/json"):
    """Petición firmada; devuelve (tipo de contenido, cabeceras, bytes)."""
    fecha = str(int(time.time()))
    firma = hmac.new(RELAY_KEY.encode(), f"{fecha}\n{ruta}\n{hashlib.sha256(cuerpo).hexdigest()}".encode(), hashlib.sha256).hexdigest()
    req = urllib.request.Request(RELAY + ruta, data=cuerpo, method="POST", headers={
        "Content-Type": tipo, "X-VS-Fecha": fecha, "X-VS-Firma": firma, "User-Agent": "centinela-vigia/1.0"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.headers.get("Content-Type", ""), r.headers, r.read(6 * 1024 * 1024)


def relay(ruta, cuerpo: bytes, tipo="application/json"):
    try:
        _, _, datos = relay_crudo(ruta, cuerpo, tipo)
        return json.loads(datos or b"{}")
    except urllib.error.HTTPError as e:
        log("relay", ruta, e.code)
        return {"ok": False, "http": e.code}
    except Exception as e:
        log("relay", ruta, type(e).__name__)
        return {"ok": False}


def mensaje(texto, severidad=3, boton=True):
    d = {"texto": texto, "severidad": severidad}
    if boton is True:
        d["boton"] = {"texto": "Abrir el centro de mando", "url": CONSOLA}
    elif isinstance(boton, dict):
        d["boton"] = boton
    r = relay("/v1/evento", json.dumps(d, ensure_ascii=False).encode())
    if not r.get("ok"):
        log("aviso NO entregado:", r.get("error") or r.get("http") or "sin respuesta", "|", texto.split("\n")[0][:80])
    return r.get("ok", False)


def tipo_de(datos: bytes) -> str:
    c = datos[:4]
    if c.startswith(b"\x7fELF"): return "ELF (Linux)"
    if c.startswith(b"MZ"): return "PE (Windows)"
    if c.startswith(b"#!"): return "script"
    if c.startswith(b"PK\x03\x04"): return "ZIP/APK/JAR"
    if b"<?php" in datos[:4096]: return "PHP"
    return "datos"


def procesar_muestra(datos: bytes, meta: dict):
    """Cifra la muestra (ZIP con contraseña "infected"), la deja en cuarentena y la manda al bot."""
    sha = hashlib.sha256(datos).hexdigest()
    meta = dict(meta, sha256=sha, tam=len(datos), tipo=meta.get("tipo") or tipo_de(datos))
    z = zip_cifrado(f"{sha}.bin", datos)
    try:
        os.makedirs(CUARENTENA, exist_ok=True)
        destino = os.path.join(CUARENTENA, f"{sha}.zip")
        if not os.path.exists(destino):
            with open(destino, "wb") as f:
                f.write(z)
            with open(os.path.join(CUARENTENA, f"{sha}.json"), "w") as f:
                json.dump(dict(meta, fecha=datetime.now(timezone.utc).isoformat()), f, ensure_ascii=False, indent=1)
    except OSError as e:
        log("cuarentena", type(e).__name__)
    return subir_bytes(z, meta)


def subir_archivo(ruta_archivo, meta):
    return procesar_muestra(open(ruta_archivo, "rb").read(20 * 1024 * 1024), meta)


def subir_bytes(datos, meta):
    limite = "----vs" + uuid.uuid4().hex
    partes = [
        f"--{limite}\r\nContent-Disposition: form-data; name=\"meta\"\r\n\r\n{json.dumps(meta, ensure_ascii=False)}\r\n".encode(),
        f"--{limite}\r\nContent-Disposition: form-data; name=\"archivo\"; filename=\"muestra.zip\"\r\nContent-Type: application/zip\r\n\r\n".encode(),
        datos, f"\r\n--{limite}--\r\n".encode()]
    return relay("/v1/archivo", b"".join(partes), f"multipart/form-data; boundary={limite}")


# ── Estado propio ────────────────────────────────────────────────────
def cargar():
    try:
        return json.load(open(ESTADO))
    except Exception:
        ahora = datetime.now(timezone.utc).isoformat()
        return {"desde": ahora, "desde_cf": ahora, "alertadas": {}, "urls": [], "archivos": [], "salud": {}, "lineas_host": [],
                "diario": "", "snapshot": 0, "hora": "", "en_hora": 0, "suprimidas": 0, "nuevo": True}


def guardar(e):
    e["urls"] = e["urls"][-2000:]; e["archivos"] = e["archivos"][-5000:]; e["lineas_host"] = e["lineas_host"][-4000:]
    limite = time.time() - 48 * 3600
    e["alertadas"] = {k: v for k, v in e["alertadas"].items() if v > limite}
    tmp = ESTADO + ".tmp"
    json.dump(e, open(tmp, "w")); os.replace(tmp, ESTADO)


def cupo(e):
    h = datetime.now(timezone.utc).strftime("%Y%m%d%H")
    if e["hora"] != h:
        if e["suprimidas"]:
            mensaje(f"🔇 En la última hora se omitieron <b>{e['suprimidas']}</b> alertas por exceso de volumen. Míralas en la consola.", 3)
        e["hora"], e["en_hora"], e["suprimidas"] = h, 0, 0
    if e["en_hora"] >= MAX_ALERTAS_HORA:
        e["suprimidas"] += 1
        return False
    e["en_hora"] += 1
    return True


# ── 1) Ataques graves ────────────────────────────────────────────────
def evidencia(s):
    hp = s.get("honeypot", {}) or {}
    if hp.get("command"):
        return hp["command"][:300]
    u = (s.get("url") or {})
    m = ((s.get("http") or {}).get("request") or {}).get("method", "")
    if u.get("original"):
        return f"{m} {u.get('domain', '') or ''}{u['original']}"[:300]
    return ""


def texto_alerta(s, repeticiones=1):
    a = s.get("ataque", {}); src = s.get("source", {}); geo = src.get("geo", {}) or {}
    th = (s.get("threat") or {}).get("technique", {}) or {}
    hp = s.get("honeypot", {}) or {}
    sensor = hp.get("sensor") or hp.get("type") or "?"
    dominio = (s.get("url") or {}).get("domain")
    titulo = f"{SEV.get(a.get('severidad'), '🟠')} · <b>{esc(a.get('nombre'))}</b>" + (f" ({esc(a['cve'])})" if a.get("cve") else "")
    t = [titulo, "",
         f"👤 {bandera(geo.get('country_iso_code'))} <code>{esc(src.get('ip'))}</code> · {esc(geo.get('country_name') or '¿?')}"
         + (f", {esc(geo.get('city_name'))}" if geo.get("city_name") else ""),
         f"🏢 {esc((src.get('as') or {}).get('organization', {}).get('name') or 'ASN desconocido')}",
         f"🎯 Sensor: <b>{esc(sensor)}</b>" + (f" · {esc(dominio)}" if dominio else ""),
         f"🧭 MITRE ATT&amp;CK: <b>{esc(th.get('id'))}</b> {esc(th.get('name'))}"]
    if hp.get("honeytoken"):
        t.append(f"🪤 Honeytoken usado: <b>{esc(hp['honeytoken'])}</b>")
    ev = evidencia(s)
    if ev:
        t.append(f"🔎 <code>{esc(ev)}</code>")
    if repeticiones > 1:
        t.append(f"🔁 {repeticiones} eventos iguales en este minuto")
    t += ["", f"📖 {esc(a.get('explicacion'))}", "", f"✅ <i>{esc(a.get('recomendacion'))}</i>"]
    return "\n".join(t)


def revisar_ataques(e):
    r = es("/honeypot-events/_search", {"size": 500, "sort": [{"event.ingested": "asc"}], "query": {"bool": {"filter": [
        {"range": {"event.ingested": {"gt": e["desde"]}}}, {"range": {"event.severity": {"gte": 3}}}],
        # las pruebas internas (IPs privadas) no generan alertas
        "must_not": [{"term": {"source.geo.country_name": "Red interna (prueba)"}}]}}})
    hits = r.get("hits", {}).get("hits", [])
    grupos = {}
    for h in hits:
        s = h["_source"]
        e["desde"] = max(e["desde"], (s.get("event") or {}).get("ingested") or e["desde"])
        a = s.get("ataque") or {}
        clave = f"{a.get('id')}|{(s.get('source') or {}).get('ip')}"
        g = grupos.setdefault(clave, {"doc": s, "n": 0})
        g["n"] += 1
        for u in a.get("urls") or []:   # muestras de malware para capturar
            if u.lower().startswith(("http://", "https://")) and u not in e["urls"]:
                e["urls"].append(u)
                ctx = {"ip": (s.get("source") or {}).get("ip"), "pais_iso": ((s.get("source") or {}).get("geo") or {}).get("country_iso_code"),
                       "asn": ((s.get("source") or {}).get("as") or {}).get("organization", {}).get("name"),
                       "ataque": a.get("nombre"), "sensor": (s.get("honeypot") or {}).get("sensor") or (s.get("honeypot") or {}).get("type")}
                try:
                    tipo, cab, datos = relay_crudo("/v1/muestra", json.dumps({"url": u, "contexto": ctx}, ensure_ascii=False).encode())
                    if tipo.startswith("application/octet-stream") and datos:
                        res = procesar_muestra(datos, dict(ctx, url=cab.get("x-vs-url-final") or u, truncada=cab.get("x-vs-truncada") == "1"))
                        log("muestra capturada", res.get("ok"), u[:80])
                    else:
                        r = json.loads(datos or b"{}"); log("muestra", r.get("ok"), r.get("error"), u[:80])
                except Exception as ex:
                    log("muestra", type(ex).__name__, u[:80])
    ahora = time.time()
    for clave, g in grupos.items():
        sev = (g["doc"].get("ataque") or {}).get("severidad", 3)
        ultima = e["alertadas"].get(clave, 0)
        if ahora - ultima < REPETIR_HORAS * 3600 and not (g["doc"].get("honeypot") or {}).get("honeytoken"):
            continue
        if sev < 4 and not cupo(e):
            continue
        if mensaje(texto_alerta(g["doc"], g["n"]), sev):
            e["alertadas"][clave] = ahora
    if hits:
        log("ataques", len(hits), "eventos graves,", len(grupos), "grupos")


# ── 2) Logins en la consola (Cloudflare Access) ──────────────────────
def revisar_access(e):
    r = es("/cloudflare-events/_search", {"size": 50, "sort": [{"@timestamp": "asc"}], "query": {"bool": {"filter": [
        {"term": {"cf.kind": "access"}}, {"range": {"@timestamp": {"gt": e["desde_cf"]}}}]}}})
    for h in r.get("hits", {}).get("hits", []):
        s = h["_source"]; cf = s.get("cf", {})
        e["desde_cf"] = max(e["desde_cf"], s.get("@timestamp") or e["desde_cf"])
        ok = cf.get("allowed")
        mensaje(("🔐 <b>Inicio de sesión en Centinela</b>" if ok else "⛔️ <b>Intento de acceso BLOQUEADO a la consola</b>") +
                f"\n\n👤 {esc(cf.get('user_email') or '¿?')}\n🌐 {bandera(cf.get('country'))} <code>{esc((s.get('source') or {}).get('ip'))}</code>"
                f"\n🖥 {esc(cf.get('app'))}\n\n" + ("Si no fuiste tú, revoca las sesiones en Cloudflare Zero Trust → Logs."
                                                    if ok else "Cloudflare Access lo frenó; no entró."),
                # crítico (llega aunque el bot esté en silencio) si entra alguien que no es el administrador o si fue bloqueado
                4 if (not ok or (cf.get("user_email") or "").lower() != ADMIN) else 3)


# ── 3) Eventos del servidor real (SSH, port knocking) ────────────────
ATRIB = {"p": "permisos", "u": "dueño", "g": "grupo", "s": "tamaño", ">": "tamaño", "C": "contenido", "l": "destino del enlace", "i": "inodo"}
ICONO_CAMBIO = {"añadido": "➕", "eliminado": "➖", "modificado": "✏️"}


def texto_integridad(ev):
    inesperados = ev.get("inesperados", 0)
    pt = ev.get("por_tipo", {})
    if inesperados:
        cab = (f"🧬 <b>Integridad: {inesperados} archivo(s) del sistema cambiaron sin explicación</b>\n"
               "AIDE comparó el servidor con su huella anterior. No coincide con ninguna actualización de apt ni con un despliegue de Ansible.")
    else:
        cab = f"🧬 Integridad: {ev.get('total')} cambio(s) explicado(s) ({esc(ev.get('aceptado') or 'actualizaciones apt')})."
    filas = []
    for a in ev.get("archivos", [])[:12]:
        attrs = ", ".join(dict.fromkeys(ATRIB[c] for c in a.get("atributos", "") if c in ATRIB))
        filas.append(f"{ICONO_CAMBIO.get(a['cambio'], '•')} <code>{esc(a['ruta'])}</code>" + (f" — {attrs}" if attrs else "") +
                     (f" <i>({esc(a['origen'])})</i>" if a.get("origen") else " ⚠️"))
    resto = ev.get("total", 0) - len(filas)
    pie = ("\n\nSi no fuiste tú: revisa con <code>sudo cat /var/lib/centinela/integridad/reporte-*.txt</code> "
           "y los responsables con <code>sudo ausearch -i -f RUTA</code>. Ante duda, aísla el servidor." if inesperados else "")
    return (f"{cab}\n\n➕ {pt.get('añadido', 0)} · ➖ {pt.get('eliminado', 0)} · ✏️ {pt.get('modificado', 0)}\n" + "\n".join(filas) +
            (f"\n… y {resto} más" if resto > 0 else "") + pie)


def avisar_audit(e, nuevos):
    """Agrupa los cambios sensibles que vio auditd en este ciclo: un mensaje por clave + origen."""
    grupos = {}
    for ev in nuevos:
        grupos.setdefault((ev.get("clave"), ev.get("origen") or ""), []).append(ev)
    for (clave, origen), evs in grupos.items():
        if origen:   # Ansible o apt: no se avisa uno por uno (AIDE manda un resumen silencioso; Grafana los cuenta)
            continue
        rutas = list(dict.fromkeys(r for ev in evs for r in ev.get("rutas", [])))
        quienes = sorted({f"{ev.get('usuario')}→{ev.get('como')}" for ev in evs})
        programas = sorted({(ev.get("comando") or ev.get("programa") or "")[:90] for ev in evs})
        # mismo archivo y mismo origen: un aviso por hora
        agrupar = f"audit|{clave}|{origen}|{'|'.join(rutas[:3])}"
        if time.time() - e["alertadas"].get(agrupar, 0) < 3600:
            continue
        e["alertadas"][agrupar] = time.time()
        sev = 2 if origen else max(ev.get("severidad", 3) for ev in evs)
        fallidos = sum(1 for ev in evs if not ev.get("exito", True))
        cab = (f"🛠 Cambio de {esc(evs[0].get('que'))} por {esc(origen)}" if origen else
               f"{'🚨' if sev >= 4 else '🛡'} <b>auditd: cambio en {esc(evs[0].get('que'))}</b>")
        mensaje(f"{cab}\n\n" + "\n".join(f"📄 <code>{esc(r)}</code>" for r in rutas[:8]) +
                f"\n👤 {esc(', '.join(quienes))}\n⚙️ " + "\n⚙️ ".join(f"<code>{esc(p)}</code>" for p in programas[:4]) +
                (f"\n❌ {fallidos} intento(s) DENEGADO(s)" if fallidos else "") +
                f"\n🕒 {esc(hora_local(evs[-1].get('fecha')))}" +
                ("" if origen else "\n\nSi no fuiste tú, es grave: alguien con root está tocando el servidor real."), sev, False)


def revisar_host(e, estado):
    audit_nuevos = []
    for ev in estado.get("eventos_host", []) or []:
        clave = hashlib.sha256(json.dumps(ev, sort_keys=True).encode()).hexdigest()[:20]
        if clave in e["lineas_host"]:
            continue
        e["lineas_host"].append(clave)
        if e.get("nuevo"):
            continue   # en el primer arranque no se avisa de lo viejo
        if ev.get("tipo") == "audit":
            audit_nuevos.append(ev); continue
        if ev.get("tipo") == "integridad":
            mensaje(texto_integridad(ev), 4 if ev.get("inesperados") else 2, {"texto": "Ver en Grafana", "url": GRAFANA})
            continue
        # misma persona y misma IP: un aviso cada 6 h (Ansible abre varias sesiones seguidas)
        agrupar = f"host|{ev.get('tipo')}|{ev.get('usuario', '')}|{ev.get('ip')}"
        if time.time() - e["alertadas"].get(agrupar, 0) < REPETIR_HORAS * 3600:
            continue
        e["alertadas"][agrupar] = time.time()
        if ev.get("tipo") == "ssh":
            mensaje(f"🔑 <b>Inicio de sesión SSH en el SERVIDOR REAL</b>\n\n👤 <code>{esc(ev.get('usuario'))}</code> desde <code>{esc(ev.get('ip'))}</code>"
                    f"\n🔐 Método: {esc(ev.get('metodo'))}\n🕒 {esc(ev.get('fecha'))}\n\nSi no fuiste tú: cambia la contraseña y rota la secuencia de knocking.", 4)
        elif ev.get("tipo") == "knock":
            mensaje(f"🚪 <b>Port knocking correcto</b> desde <code>{esc(ev.get('ip'))}</code>\nEl SSH se abrió 5 min para esa IP.\n🕒 {esc(ev.get('fecha'))}", 3, False)
        elif ev.get("tipo") == "ban":
            mensaje(f"🚫 Fail2Ban bloqueó <code>{esc(ev.get('ip'))}</code> ({esc(ev.get('jail'))}).", 3, False)
    if audit_nuevos:
        avisar_audit(e, audit_nuevos)


# ── 4) Salud ─────────────────────────────────────────────────────────
def revisar_salud(e, estado):
    prev = e["salud"]; ahora = {}
    for c in estado.get("contenedores", []):
        malo = c.get("estado") != "running" or c.get("salud") == "unhealthy"
        ahora["c:" + c["nombre"]] = "mal" if malo else "bien"
    h = estado.get("host", {})
    for clave, usado, total in (("disco_docker", h.get("docker_usado"), h.get("docker_total")), ("disco_raiz", h.get("raiz_usado"), h.get("raiz_total"))):
        if usado and total:
            ahora[clave] = "mal" if usado / total > 0.85 else "bien"
    try:
        ahora["es"] = "mal" if es("/_cluster/health").get("status") == "red" else "bien"
    except Exception:
        ahora["es"] = "mal"
    for k, v in ahora.items():
        antes = prev.get(k)
        # se exige que el problema se mantenga dos ciclos seguidos (evita falsas alarmas al reiniciar)
        if v == "mal" and antes == "mal1":
            mensaje(f"🩺 <b>Problema en el servidor</b>: {esc(k.replace('c:', 'contenedor '))} no está bien. Revisa /estado.", 4)
            ahora[k] = "mal2"
        elif v == "mal" and antes in ("mal2",):
            ahora[k] = "mal2"
        elif v == "mal":
            ahora[k] = "mal1"
        elif v == "bien" and antes == "mal2":
            mensaje(f"💚 Recuperado: {esc(k.replace('c:', 'contenedor '))}.", 3, False)
    e["salud"] = ahora


# ── 5) Archivos capturados por los sensores ──────────────────────────
def parece_muestra(ruta):
    try:
        if os.path.getsize(ruta) < 64 or os.path.getsize(ruta) > 20 * 1024 * 1024:
            return False
        cabeza = open(ruta, "rb").read(4096)
    except OSError:
        return False
    return (cabeza.startswith((b"\x7fELF", b"MZ", b"#!", b"PK\x03\x04")) or b"<?php" in cabeza or b"base64_decode" in cabeza
            or b"wget " in cabeza or b"curl " in cabeza)


def revisar_archivos(e):
    for carpeta, origen in CARPETAS_MUESTRAS.items():
        if not os.path.isdir(carpeta):
            continue
        for raiz, _, nombres in os.walk(carpeta):
            for n in nombres[:500]:
                ruta = os.path.join(raiz, n)
                clave = f"{ruta}:{os.path.getsize(ruta) if os.path.exists(ruta) else 0}"
                if clave in e["archivos"]:
                    continue
                e["archivos"].append(clave)
                if e.get("nuevo") or not parece_muestra(ruta):
                    continue
                res = subir_archivo(ruta, {"origen": origen})
                log("archivo", origen, res.get("ok"), res.get("sha256", "")[:16])


# ── 6) Resumen para los comandos del bot ─────────────────────────────
def snapshot(estado):
    f24 = {"range": {"@timestamp": {"gte": "now-24h"}}}
    r = es("/honeypot-events/_search", {"size": 0, "track_total_hits": True, "query": f24, "aggs": {
        "ips": {"cardinality": {"field": "source.ip"}}, "paises": {"cardinality": {"field": "source.geo.country_iso_code"}},
        "graves": {"filter": {"range": {"event.severity": {"gte": 3}}}},
        "creds": {"filter": {"exists": {"field": "honeypot.password"}}},
        "sensor": {"terms": {"field": "honeypot.sensor", "size": 12, "missing": "red"}},
        "tipo": {"terms": {"field": "honeypot.type", "size": 12}},
        "paises_top": {"terms": {"field": "source.geo.country_name", "size": 6}, "aggs": {"iso": {"terms": {"field": "source.geo.country_iso_code", "size": 1}}}},
        "ataques": {"terms": {"field": "ataque.id", "size": 12, "order": {"sev": "desc"}}, "aggs": {
            "sev": {"max": {"field": "ataque.severidad"}}, "ips": {"cardinality": {"field": "source.ip"}},
            "ej": {"top_hits": {"size": 1, "_source": ["ataque", "threat"]}}}},
        "ips_top": {"terms": {"field": "source.ip", "size": 25}, "aggs": {
            "pais": {"terms": {"field": "source.geo.country_name", "size": 1}}, "iso": {"terms": {"field": "source.geo.country_iso_code", "size": 1}},
            "asn": {"terms": {"field": "source.as.organization.name", "size": 1}}, "primero": {"min": {"field": "@timestamp"}},
            "ultimo": {"max": {"field": "@timestamp"}}, "sens": {"terms": {"field": "honeypot.type", "size": 5}},
            "atq": {"terms": {"field": "ataque.nombre", "size": 6}}}},
        "usuarios": {"terms": {"field": "user.name", "size": 6}}, "claves": {"terms": {"field": "honeypot.password", "size": 6}},
        "rutas": {"terms": {"field": "url.path", "size": 6}}}})
    a = r.get("aggregations", {})
    b = lambda k: [{"valor": x["key"], "n": x["doc_count"]} for x in a.get(k, {}).get("buckets", [])]
    ataques = []
    for x in a.get("ataques", {}).get("buckets", []):
        hit = (x["ej"]["hits"]["hits"] or [{"_source": {}}])[0]["_source"]; at = hit.get("ataque", {}); th = (hit.get("threat") or {}).get("technique", {})
        ataques.append({"id": x["key"], "nombre": at.get("nombre"), "severidad": int(x["sev"]["value"] or 1), "n": x["doc_count"],
                        "ips": x["ips"]["value"], "explicacion": at.get("explicacion"), "cve": at.get("cve"),
                        "tecnica_id": th.get("id"), "tecnica": th.get("name")})
    ips_detalle = {}
    for x in a.get("ips_top", {}).get("buckets", []):
        p = lambda k: (x[k]["buckets"] or [{"key": None}])[0]["key"]
        ips_detalle[x["key"]] = {"eventos": x["doc_count"], "pais": p("pais"), "pais_iso": p("iso"), "asn": p("asn"),
                                 "primero": x["primero"].get("value_as_string"), "ultimo": x["ultimo"].get("value_as_string"),
                                 "sensores": [y["key"] for y in x["sens"]["buckets"]], "ataques": [y["key"] for y in x["atq"]["buckets"]]}
    ult = es("/honeypot-events/_search", {"size": 10, "sort": [{"@timestamp": "desc"}], "query": {"bool": {"filter": [f24, {"range": {"event.severity": {"gte": 3}}}]}},
                                          "_source": ["@timestamp", "source.ip", "source.geo.country_iso_code", "ataque.nombre", "ataque.severidad",
                                                      "honeypot.sensor", "honeypot.type", "honeypot.command", "url.original", "url.domain", "http.request.method"]})
    ultimos = []
    for h in ult.get("hits", {}).get("hits", []):
        s = h["_source"]
        ultimos.append({"fecha": s.get("@timestamp"), "ip": (s.get("source") or {}).get("ip"), "pais_iso": ((s.get("source") or {}).get("geo") or {}).get("country_iso_code"),
                        "ataque": (s.get("ataque") or {}).get("nombre"), "severidad": (s.get("ataque") or {}).get("severidad"),
                        "sensor": (s.get("honeypot") or {}).get("sensor") or (s.get("honeypot") or {}).get("type"), "detalle": evidencia(s)[:120]})
    h = estado.get("host", {})
    pct = lambda u, t: round(100 * u / t) if u and t else None
    try:
        es_estado = es("/_cluster/health").get("status", "?")
    except Exception:
        es_estado = "sin respuesta"
    sensores = b("sensor")
    sensores = [x for x in sensores if x["valor"] != "red"] + [{"valor": t["valor"], "n": t["n"]} for t in b("tipo") if t["valor"] != "web"]
    return {"host": {"carga5": h.get("carga5"), "cpus": h.get("cpus"), "ram_pct": pct(h.get("ram_usada"), h.get("ram_total")),
                     "docker_pct": pct(h.get("docker_usado"), h.get("docker_total")), "raiz_pct": pct(h.get("raiz_usado"), h.get("raiz_total"))},
            "contenedores": [{"nombre": c["nombre"], "estado": c.get("estado"), "salud": c.get("salud")} for c in estado.get("contenedores", [])],
            "es_estado": es_estado,
            "resumen24": {"eventos": r.get("hits", {}).get("total", {}).get("value", 0), "ips": a.get("ips", {}).get("value", 0),
                          "paises": a.get("paises", {}).get("value", 0), "graves": a.get("graves", {}).get("doc_count", 0),
                          "credenciales": a.get("creds", {}).get("doc_count", 0), "por_sensor": sensores,
                          "paises_top": [{"valor": x["key"], "n": x["doc_count"], "iso": (x["iso"]["buckets"] or [{"key": None}])[0]["key"]}
                                         for x in a.get("paises_top", {}).get("buckets", [])],
                          "ataques": ataques, "ips_top": b("ips_top")[:8], "usuarios_top": b("usuarios"), "claves_top": b("claves"), "rutas_top": b("rutas")},
            "ultimos_graves": ultimos, "ips_detalle": ips_detalle}


def informe_diario(snap):
    r = snap["resumen24"]
    at = "\n".join(f"• {esc(x['nombre'])}: {x['n']}" for x in r["ataques"][:6]) or "• Sin ataques clasificados"
    pa = "\n".join(f"{bandera(x['iso'])} {esc(x['valor'])}: {x['n']}" for x in r["paises_top"][:5]) or "—"
    mensaje(f"☀️ <b>Informe diario Centinela</b>\n\nÚltimas 24 h: <b>{r['eventos']}</b> eventos de <b>{r['ips']}</b> IPs en <b>{r['paises']}</b> países."
            f"\nGraves: <b>{r['graves']}</b> · Credenciales probadas: <b>{r['credenciales']}</b>\n\n<b>Ataques</b>\n{at}\n\n<b>Países</b>\n{pa}\n\nMás detalle: /ataques · /top", 3)


# ── 7) Alertas de infraestructura (Alertmanager → aquí → bot), prioridad máxima ──────
def hora_local(iso):
    try:
        return datetime.fromisoformat(iso.replace("Z", "+00:00")).astimezone(BOGOTA).strftime("%d/%m %H:%M")
    except Exception:
        return "?"


def texto_infra(a, estado):
    et, an = a.get("labels", {}), a.get("annotations", {})
    critica = et.get("severidad") == "critica"
    if estado == "resolved":
        try:
            dur = (datetime.fromisoformat(a["endsAt"].replace("Z", "+00:00")) - datetime.fromisoformat(a["startsAt"].replace("Z", "+00:00"))).total_seconds() / 60
            d = f" (duró {dur:.0f} min)"
        except Exception:
            d = ""
        return f"✅ <b>INFRA · Resuelto</b>{d}\n{esc(an.get('resumen') or et.get('alertname'))}"
    t = [f"🖥️ <b>INFRA · {'🔴 CRÍTICA' if critica else '🟠 ALTA'}</b>", f"<b>{esc(an.get('resumen') or et.get('alertname'))}</b>", "",
         esc(an.get("descripcion", "")), "", f"🕒 Desde: {hora_local(a.get('startsAt', ''))} (Bogotá)"]
    extra = [f"{k}: {esc(v)}" for k, v in et.items() if k in ("nombre", "mountpoint", "device")]
    t.append(f"🏷 {esc(et.get('alertname'))}" + (" · " + " · ".join(extra) if extra else ""))
    return "\n".join(t)


class Alertas(BaseHTTPRequestHandler):
    server_version = "vigia"
    sys_version = ""

    def log_message(self, *a):
        pass

    def do_POST(self):
        auth = self.headers.get("Authorization", "")
        if self.path != "/alertmanager" or not ALERTAS_TOKEN or not hmac.compare_digest(auth, "Bearer " + ALERTAS_TOKEN):
            self.send_response(401); self.end_headers(); return
        try:
            n = min(int(self.headers.get("Content-Length") or 0), 1024 * 1024)
            d = json.loads(self.rfile.read(n))
            for a in d.get("alerts", [])[:20]:
                estado = a.get("status", "firing")
                sev = 4 if a.get("labels", {}).get("severidad") == "critica" and estado == "firing" else 3
                mensaje(texto_infra(a, estado), sev, {"texto": "Abrir Grafana", "url": GRAFANA})
            log("alertas infra:", len(d.get("alerts", [])), d.get("status"))
            self.send_response(200)
        except Exception as ex:
            log("alertas infra error:", type(ex).__name__)
            self.send_response(400)
        self.end_headers()

    do_GET = do_PUT = lambda self: (self.send_response(405), self.end_headers())


def servidor_alertas():
    if not ESCUCHAR_ALERTAS:
        return
    h, p = ESCUCHAR_ALERTAS.rsplit(":", 1)
    srv = ThreadingHTTPServer((h, int(p)), Alertas)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    log("escuchando alertas de infraestructura en", ESCUCHAR_ALERTAS)


def main():
    log("vigía iniciado; relay", RELAY)
    servidor_alertas()
    while True:
        e = cargar()
        try:
            try:
                estado = json.load(open(ESTADO_HOST))
            except Exception:
                estado = {}
            if not e.get("bienvenida"):   # se reintenta hasta que el bot esté configurado
                e["bienvenida"] = mensaje("🟢 <b>Vigía de Centinela conectado.</b>\nDesde ahora recibirás aquí los ataques graves, el malware capturado y los avisos del servidor. Escribe /ayuda.", 4)
            revisar_ataques(e)
            revisar_access(e)
            revisar_host(e, estado)
            revisar_salud(e, estado)
            revisar_archivos(e)
            if time.time() - e["snapshot"] > 300:
                snap = snapshot(estado)
                if relay("/v1/snapshot", json.dumps(snap, ensure_ascii=False, default=str).encode()).get("ok"):
                    e["snapshot"] = time.time()
                hoy = datetime.now(BOGOTA)
                if hoy.hour >= 8 and e["diario"] != hoy.strftime("%Y-%m-%d"):
                    informe_diario(snap)
                    e["diario"] = hoy.strftime("%Y-%m-%d")
            e["nuevo"] = False
        except Exception as ex:
            log("error en el ciclo:", type(ex).__name__, str(ex)[:200])
        guardar(e)
        time.sleep(60)


if __name__ == "__main__":
    main()
