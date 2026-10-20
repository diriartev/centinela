#!/usr/bin/env python3
"""Centinela · colector de métricas de Cloudflare → Elasticsearch.
Token de Cloudflare de SOLO LECTURA. Sale a internet solo hacia api.cloudflare.com
(red edge, IP autorizada en el firewall). Escribe en cloudflare-metrics / cloudflare-events.
"""
import json, os, ssl, time, base64, urllib.request, urllib.error
from datetime import datetime, timedelta, timezone

CF_TOKEN = open("/run/secrets/cf_token").read().strip()
ZONA = os.environ["CF_ZONA"]; CUENTA = os.environ["CF_CUENTA"]
ES = os.environ.get("ES_URL", "https://10.213.252.10:9200")
ES_AUTH = "Basic " + base64.b64encode(f"centinela_cfmetrics:{os.environ['ES_PASSWORD']}".encode()).decode()
CTX_ES = ssl.create_default_context(cafile="/certs/ca.crt"); CTX_ES.check_hostname = False
ESTADO = "/estado/estado.json"
INTERVALO = int(os.environ.get("INTERVALO", "300"))

def log(*a): print(datetime.now(timezone.utc).strftime("%H:%M:%S"), *a, flush=True)

def cf_graphql(query, variables):
    req = urllib.request.Request("https://api.cloudflare.com/client/v4/graphql", method="POST",
                                 data=json.dumps({"query": query, "variables": variables}).encode(),
                                 headers={"Authorization": f"Bearer {CF_TOKEN}", "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        d = json.loads(r.read())
    if d.get("errors"): raise RuntimeError(d["errors"][0].get("message"))
    return d["data"]

def cf_rest(ruta):
    req = urllib.request.Request("https://api.cloudflare.com/client/v4" + ruta, headers={"Authorization": f"Bearer {CF_TOKEN}"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())

def es_bulk(indice, docs):
    if not docs: return 0
    cuerpo = "".join(json.dumps({"create": {"_index": indice}}) + "\n" + json.dumps(d) + "\n" for d in docs)
    req = urllib.request.Request(ES + "/_bulk", data=cuerpo.encode(), method="POST",
                                 headers={"Authorization": ES_AUTH, "Content-Type": "application/x-ndjson"})
    with urllib.request.urlopen(req, context=CTX_ES, timeout=30) as r:
        res = json.loads(r.read())
    if res.get("errors"): log("aviso: algunos documentos fallaron", json.dumps([i for i in res["items"] if "error" in i["create"]][:1])[:300])
    return len(docs)

def cargar():
    try: return json.load(open(ESTADO))
    except Exception: return {"horas": [], "rayos": [], "access": []}

def guardar(e):
    for k in ("horas", "rayos", "access"): e[k] = e.get(k, [])[-3000:]
    tmp = ESTADO + ".tmp"; json.dump(e, open(tmp, "w")); os.replace(tmp, ESTADO)

Q_HORAS = """query($z:String!,$desde:Time!,$hasta:Time!){viewer{zones(filter:{zoneTag:$z}){httpRequests1hGroups(limit:72,
 filter:{datetime_geq:$desde,datetime_lt:$hasta},orderBy:[datetime_ASC]){dimensions{datetime}
 sum{requests cachedRequests threats bytes pageViews countryMap{clientCountryName requests threats} responseStatusMap{edgeResponseStatus requests}}
 uniq{uniques}}}}}"""

Q_SEGURIDAD = """query($z:String!,$desde:Time!){viewer{zones(filter:{zoneTag:$z}){firewallEventsAdaptive(limit:500,
 filter:{datetime_geq:$desde},orderBy:[datetime_ASC]){datetime action source clientIP clientCountryName clientAsn
 clientRequestHTTPHost clientRequestPath userAgent rayName ruleId}}}}"""

def ciclo(e):
    ahora = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
    desde = ahora - timedelta(hours=48)
    # 1) Tráfico por hora (solo horas completas y no enviadas antes)
    d = cf_graphql(Q_HORAS, {"z": ZONA, "desde": desde.isoformat().replace("+00:00", "Z"), "hasta": ahora.isoformat().replace("+00:00", "Z")})
    docs = []
    for g in d["viewer"]["zones"][0]["httpRequests1hGroups"]:
        h = g["dimensions"]["datetime"]
        if h in e["horas"]: continue
        s = g["sum"]
        docs.append({"@timestamp": h, "cf": {"metric": "trafico", "zone": ZONA, "requests": s["requests"], "cached_requests": s["cachedRequests"],
                     "threats": s["threats"], "bytes": s["bytes"], "page_views": s["pageViews"], "uniques": g["uniq"]["uniques"]}})
        for c in s["countryMap"]:
            docs.append({"@timestamp": h, "cf": {"metric": "pais", "country": c["clientCountryName"], "requests": c["requests"], "threats": c["threats"]}})
        for st in s["responseStatusMap"]:
            docs.append({"@timestamp": h, "cf": {"metric": "estado_http", "status": str(st["edgeResponseStatus"]), "requests": st["requests"]}})
        e["horas"].append(h)
    n1 = es_bulk("cloudflare-metrics", docs)
    # 2) Eventos de seguridad (WAF, bots, reglas) de las últimas 24 h
    n2 = 0
    try:
        d = cf_graphql(Q_SEGURIDAD, {"z": ZONA, "desde": (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat().replace("+00:00", "Z")})
        docs = []
        for ev in d["viewer"]["zones"][0]["firewallEventsAdaptive"]:
            if ev["rayName"] in e["rayos"]: continue
            docs.append({"@timestamp": ev["datetime"], "source": {"ip": ev["clientIP"], "as": {"number": ev["clientAsn"]}},
                         "cf": {"kind": "seguridad", "action": ev["action"], "source": ev["source"], "rule_id": ev["ruleId"], "host": ev["clientRequestHTTPHost"],
                                "path": ev["clientRequestPath"], "country": ev["clientCountryName"], "user_agent": ev["userAgent"], "ray": ev["rayName"]}})
            e["rayos"].append(ev["rayName"])
        n2 = es_bulk("cloudflare-events", docs)
    except Exception as x:
        log("seguridad: no disponible ->", str(x)[:160])
    # 3) Inicios de sesión en Cloudflare Access
    n3 = 0
    try:
        r = cf_rest(f"/accounts/{CUENTA}/access/logs/access_requests?limit=100&direction=desc")
        docs = []
        for a in r.get("result", []):
            clave = a.get("ray_id") or (a.get("created_at", "") + a.get("user_email", ""))
            if clave in e["access"]: continue
            docs.append({"@timestamp": a.get("created_at"), "source": {"ip": a.get("ip_address")},
                         "cf": {"kind": "access", "action": a.get("action"), "allowed": a.get("allowed"), "user_email": a.get("user_email"),
                                "app": a.get("app_domain"), "country": (a.get("country") or "").upper(), "ray": a.get("ray_id")}})
            e["access"].append(clave)
        n3 = es_bulk("cloudflare-events", docs)
    except Exception as x:
        log("access: no disponible ->", str(x)[:160])
    guardar(e)
    log(f"ok: {n1} métricas, {n2} eventos de seguridad, {n3} accesos")

if __name__ == "__main__":
    e = cargar()
    while True:
        try:
            ciclo(e)
        except urllib.error.HTTPError as x:
            log("error HTTP", x.code, x.read()[:200])
        except Exception as x:
            log("error:", type(x).__name__, str(x)[:200])
        time.sleep(INTERVALO)
