#!/usr/bin/env python3
"""Genera los objetos de Kibana (visualizaciones + dashboards) de Centinela en NDJSON."""
import json
DV, DVM, DVE = "dv-honeypot", "dv-cf-metrics", "dv-cf-events"
objs = []

def busqueda(dv, consulta=""):
    return {"searchSourceJSON": json.dumps({"query": {"query": consulta, "language": "kuery"}, "filter": [],
            "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index"})}

def vis(id_, titulo, tipo, aggs, params, dv=DV, consulta=""):
    objs.append({"type": "visualization", "id": id_, "attributes": {"title": titulo, "description": "",
        "visState": json.dumps({"title": titulo, "type": tipo, "aggs": aggs, "params": params}), "uiStateJSON": "{}", "version": 1,
        "kibanaSavedObjectMeta": busqueda(dv, consulta)},
        "references": [{"name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern", "id": dv}],
        "typeMigrationVersion": "8.5.0"})

def metrica(id_, titulo, agg, campo=None, dv=DV, consulta=""):
    a = {"id": "1", "enabled": True, "type": agg, "schema": "metric", "params": ({"field": campo, "customLabel": titulo} if campo else {"customLabel": titulo})}
    vis(id_, titulo, "metric", [a], {"addTooltip": True, "addLegend": False, "type": "metric", "metric": {"percentageMode": False, "useRanges": False,
        "colorSchema": "Green to Red", "metricColorMode": "None", "colorsRange": [{"from": 0, "to": 10000}], "labels": {"show": True}, "invertColors": False,
        "style": {"bgFill": "#000", "bgColor": False, "labelColor": False, "subText": "", "fontSize": 48}}}, dv, consulta)

def tabla(id_, titulo, campo, n=10, etiqueta=None, dv=DV, consulta=""):
    vis(id_, titulo, "table", [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {"customLabel": "Eventos"}},
        {"id": "2", "enabled": True, "type": "terms", "schema": "bucket", "params": {"field": campo, "size": n, "order": "desc", "orderBy": "1",
         "otherBucket": False, "missingBucket": False, "customLabel": etiqueta or campo}}],
        {"perPage": 10, "showPartialRows": False, "showMetricsAtAllLevels": False, "showTotal": False, "totalFunc": "sum", "percentageCol": ""}, dv, consulta)

def torta(id_, titulo, campo, n=10, dv=DV):
    vis(id_, titulo, "pie", [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
        {"id": "2", "enabled": True, "type": "terms", "schema": "segment", "params": {"field": campo, "size": n, "order": "desc", "orderBy": "1"}}],
        {"type": "pie", "addTooltip": True, "legendDisplay": "show", "legendPosition": "right", "isDonut": True, "nestedLegend": False,
         "distinctColors": True, "palette": {"type": "palette", "name": "default"},
         "labels": {"show": True, "values": True, "last_level": True, "truncate": 100, "position": "default", "valuesFormat": "percent"}}, dv)

def histograma(id_, titulo, metrica_aggs, dividir=None, dv=DV, tipo="histogram", consulta=""):
    aggs = metrica_aggs + [{"id": "9", "enabled": True, "type": "date_histogram", "schema": "segment",
        "params": {"field": "@timestamp", "interval": "auto", "min_doc_count": 1, "extended_bounds": {}}}]
    if dividir:
        aggs.append({"id": "8", "enabled": True, "type": "terms", "schema": "group", "params": {"field": dividir, "size": 10, "order": "desc", "orderBy": "1"}})
    vis(id_, titulo, tipo, aggs, {"type": tipo, "grid": {"categoryLines": False}, "addTooltip": True, "addLegend": True, "legendPosition": "top",
        "times": [], "addTimeMarker": False, "palette": {"type": "palette", "name": "default"},
        "categoryAxes": [{"id": "CategoryAxis-1", "type": "category", "position": "bottom", "show": True, "scale": {"type": "linear"}, "labels": {"show": True, "filter": True, "truncate": 100}, "title": {}}],
        "valueAxes": [{"id": "ValueAxis-1", "name": "LeftAxis-1", "type": "value", "position": "left", "show": True, "scale": {"type": "linear", "mode": "normal"}, "labels": {"show": True, "rotate": 0, "filter": False, "truncate": 100}, "title": {"text": ""}}],
        "seriesParams": [{"show": True, "type": "histogram" if tipo == "histogram" else "line", "mode": "stacked", "data": {"label": m["params"].get("customLabel", "Eventos"), "id": m["id"]},
                          "valueAxis": "ValueAxis-1", "drawLinesBetweenPoints": True, "lineWidth": 2, "showCircles": True, "interpolate": "linear"} for m in metrica_aggs]}, dv, consulta)

def nube(id_, titulo, campo, n=40):
    vis(id_, titulo, "tagcloud", [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
        {"id": "2", "enabled": True, "type": "terms", "schema": "segment", "params": {"field": campo, "size": n, "order": "desc", "orderBy": "1"}}],
        {"scale": "linear", "orientation": "single", "minFontSize": 14, "maxFontSize": 56, "showLabel": False, "palette": {"type": "palette", "name": "default"}})

CUENTA = [{"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {"customLabel": "Eventos"}}]
# ── Honeypot ──
metrica("v-eventos", "Eventos", "count")
metrica("v-ips", "IPs atacantes", "cardinality", "source.ip")
metrica("v-paises", "Países", "cardinality", "source.geo.country_iso_code")
metrica("v-creds", "Credenciales capturadas", "count", consulta="honeypot.password:*")
histograma("v-linea", "Actividad por honeypot", CUENTA, "honeypot.type")
torta("v-torta", "Eventos por honeypot", "honeypot.type")
torta("v-paises-torta", "Países de origen", "source.geo.country_name", 12)
tabla("v-top-ips", "Top IPs atacantes", "source.ip", 15, "IP")
tabla("v-top-asn", "Top redes (ASN)", "source.as.organization.name", 15, "Organización")
tabla("v-top-puertos", "Puertos atacados", "destination.port", 15, "Puerto")
tabla("v-top-users", "Usuarios probados", "user.name", 20, "Usuario")
tabla("v-top-pass", "Contraseñas probadas", "honeypot.password", 20, "Contraseña")
tabla("v-top-cmds", "Comandos ejecutados", "honeypot.command.keyword", 20, "Comando")
tabla("v-top-trampas", "Trampas web activadas", "honeypot.trap", 15, "Trampa")
tabla("v-top-rutas", "Rutas web pedidas", "url.path", 20, "Ruta", consulta="honeypot.type:web")
nube("v-nube-pass", "Nube de contraseñas", "honeypot.password")
# ── Cloudflare ──
SUMA = lambda campo, etiqueta, i: {"id": i, "enabled": True, "type": "sum", "schema": "metric", "params": {"field": campo, "customLabel": etiqueta}}
histograma("v-cf-trafico", "Cloudflare · solicitudes y amenazas", [SUMA("cf.requests", "Solicitudes", "1"), SUMA("cf.threats", "Amenazas", "2")], dv=DVM, tipo="line", consulta="cf.metric:trafico")
vis("v-cf-paises", "Cloudflare · solicitudes por país", "table", [SUMA("cf.requests", "Solicitudes", "1"),
    {"id": "2", "enabled": True, "type": "terms", "schema": "bucket", "params": {"field": "cf.country", "size": 20, "order": "desc", "orderBy": "1", "customLabel": "País"}}],
    {"perPage": 10, "showTotal": False}, DVM, "cf.metric:pais")
vis("v-cf-estados", "Cloudflare · códigos HTTP", "pie", [SUMA("cf.requests", "Solicitudes", "1"),
    {"id": "2", "enabled": True, "type": "terms", "schema": "segment", "params": {"field": "cf.status", "size": 10, "order": "desc", "orderBy": "1"}}],
    {"type": "pie", "isDonut": True, "legendDisplay": "show", "addTooltip": True, "palette": {"type": "palette", "name": "default"}, "labels": {"show": True, "values": True, "last_level": True, "truncate": 100, "position": "default", "valuesFormat": "percent"}}, DVM, "cf.metric:estado_http")
metrica("v-cf-req", "Solicitudes en el borde", "sum", "cf.requests", DVM, "cf.metric:trafico")
metrica("v-cf-thr", "Amenazas bloqueadas", "sum", "cf.threats", DVM, "cf.metric:trafico")
tabla("v-cf-eventos", "Eventos de seguridad / Access", "cf.action", 10, "Acción", DVE)
tabla("v-cf-access", "Inicios de sesión en Access", "cf.user_email", 10, "Usuario", DVE, "cf.kind:access")

# ── Ataques explicados (clasificador + MITRE ATT&CK) ──
metrica("v-graves", "Ataques graves (alta/crítica)", "count", consulta="event.severity >= 3")
metrica("v-criticos", "Ataques críticos", "count", consulta="event.severity >= 4")
metrica("v-honeytokens", "Honeytokens usados", "count", consulta="honeypot.honeytoken:*")
metrica("v-ips-graves", "IPs con ataques graves", "cardinality", "source.ip", consulta="event.severity >= 3")
histograma("v-sev-linea", "Ataques por severidad", CUENTA, "ataque.severidad_txt", consulta="ataque.id:*")
torta("v-categorias", "Categorías de ataque", "ataque.categoria", 12)
tabla("v-top-ataques", "Tipos de ataque", "ataque.nombre", 25, "Ataque")
tabla("v-top-tecnicas", "Técnicas MITRE ATT&CK", "threat.technique.name", 20, "Técnica")
tabla("v-top-tacticas", "Tácticas MITRE ATT&CK", "threat.tactic.name", 12, "Táctica")
tabla("v-top-cves", "CVEs explotados", "ataque.cve", 20, "CVE")
tabla("v-top-sensores", "Sensores web atacados", "honeypot.sensor", 10, "Sensor", consulta="honeypot.type:web")
tabla("v-top-urls-malware", "URLs de descarga de malware", "ataque.urls", 20, "URL")
objs.append({"type": "search", "id": "s-ataques", "attributes": {"title": "Ataques graves explicados (detalle)", "description": "",
    "columns": ["ataque.severidad_txt", "ataque.nombre", "source.ip", "source.geo.country_name", "honeypot.sensor", "threat.technique.id", "ataque.cve", "url.original", "honeypot.command", "ataque.explicacion"],
    "sort": [["@timestamp", "desc"]], "kibanaSavedObjectMeta": busqueda(DV, "event.severity >= 3")},
    "references": [{"name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern", "id": DV}]})

# ── Búsqueda guardada (detalle de eventos) ──
objs.append({"type": "search", "id": "s-eventos", "attributes": {"title": "Eventos del honeypot (detalle)", "description": "",
    "columns": ["honeypot.type", "source.ip", "source.geo.country_name", "destination.port", "event.action", "user.name", "honeypot.password", "honeypot.command", "url.path"],
    "sort": [["@timestamp", "desc"]], "kibanaSavedObjectMeta": busqueda(DV)},
    "references": [{"name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern", "id": DV}]})

def dashboard(id_, titulo, desc, filas):
    paneles, refs, y = [], [], 0
    for fila in filas:
        x, alto = 0, max(p[2] for p in fila)
        for i, (vid, ancho, h) in enumerate(fila):
            n = f"panel_{len(paneles)}"
            tipo = "search" if vid.startswith("s-") else "visualization"
            paneles.append({"version": "9.5.4", "type": tipo, "gridData": {"x": x, "y": y, "w": ancho, "h": h, "i": n}, "panelIndex": n, "embeddableConfig": {}, "panelRefName": n})
            refs.append({"name": n, "type": tipo, "id": vid}); x += ancho
        y += alto
    objs.append({"type": "dashboard", "id": id_, "attributes": {"title": titulo, "description": desc, "panelsJSON": json.dumps(paneles),
        "optionsJSON": json.dumps({"useMargins": True, "syncColors": True, "syncCursor": True, "syncTooltips": True, "hidePanelTitles": False}),
        "timeRestore": True, "timeFrom": "now-24h", "timeTo": "now", "refreshInterval": {"pause": False, "value": 30000},
        "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps({"query": {"query": "", "language": "kuery"}, "filter": []})}},
        "references": refs, "typeMigrationVersion": "10.2.0"})

dashboard("d-honeypot", "Centinela · Honeypot", "Ataques capturados por los sensores (SSH/Telnet, multiprotocolo, ICS, Redis, Elasticsearch, SMTP, ADB y web señuelo).", [
    [("v-eventos", 12, 7), ("v-ips", 12, 7), ("v-paises", 12, 7), ("v-creds", 12, 7)],
    [("v-linea", 32, 14), ("v-torta", 16, 14)],
    [("v-paises-torta", 16, 14), ("v-top-ips", 16, 14), ("v-top-asn", 16, 14)],
    [("v-top-users", 12, 15), ("v-top-pass", 12, 15), ("v-nube-pass", 24, 15)],
    [("v-top-cmds", 24, 15), ("v-top-puertos", 12, 15), ("v-top-trampas", 12, 15)],
    [("v-top-rutas", 16, 15), ("s-eventos", 32, 15)]])
dashboard("d-ataques", "Centinela · Ataques explicados (MITRE ATT&CK)", "Cada evento clasificado por el pipeline: qué ataque es, su gravedad, técnica MITRE ATT&CK, CVE y explicación en español (reglas Centinela + trampas de T-Pot).", [
    [("v-graves", 12, 7), ("v-criticos", 12, 7), ("v-honeytokens", 12, 7), ("v-ips-graves", 12, 7)],
    [("v-sev-linea", 32, 14), ("v-categorias", 16, 14)],
    [("v-top-ataques", 20, 16), ("v-top-tecnicas", 16, 16), ("v-top-tacticas", 12, 16)],
    [("v-top-cves", 16, 14), ("v-top-sensores", 12, 14), ("v-top-urls-malware", 20, 14)],
    [("s-ataques", 48, 18)]])
dashboard("d-cloudflare", "Centinela · Cloudflare", "Tráfico y seguridad en el borde de Cloudflare (zona example.com) e inicios de sesión en Access.", [
    [("v-cf-req", 24, 7), ("v-cf-thr", 24, 7)],
    [("v-cf-trafico", 32, 15), ("v-cf-estados", 16, 15)],
    [("v-cf-paises", 16, 15), ("v-cf-eventos", 16, 15), ("v-cf-access", 16, 15)]])

with open("objetos.ndjson", "w") as f:
    for o in objs: f.write(json.dumps(o, ensure_ascii=False) + "\n")
print(len(objs), "objetos")
