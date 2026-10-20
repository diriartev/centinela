#!/usr/bin/env python3
"""Genera dashboards/centinela-salud.json (dashboard principal de Grafana, en español)."""
import json
DS = {"type": "prometheus", "uid": "prometheus"}
P, y, nid = [], 0, 1
NAR, ROJ, AMB, VER = "#F97316", "#E94343", "#F59E0B", "#22C55E"

def umbrales(*pasos):
    return {"mode": "absolute", "steps": [{"color": c, "value": v} for v, c in pasos]}

def panel(tipo, titulo, x, w, h, objetivos, **extra):
    global nid
    p = {"id": nid, "type": tipo, "title": titulo, "datasource": DS, "gridPos": {"x": x, "y": y, "w": w, "h": h},
         "targets": [dict({"refId": chr(65 + i), "datasource": DS}, **o) for i, o in enumerate(objetivos)]}
    p.update(extra); nid += 1; P.append(p); return p

def stat(titulo, expr, x, w, unidad="percent", pasos=((None, VER), (70, AMB), (85, ROJ)), mapeos=None, decimales=0, desc=""):
    return panel("stat", titulo, x, w, 4, [{"expr": expr, "instant": True}], description=desc,
                 fieldConfig={"defaults": {"unit": unidad, "decimals": decimales, "thresholds": umbrales(*pasos), "color": {"mode": "thresholds"},
                                           "mappings": mapeos or []}, "overrides": []},
                 options={"colorMode": "background_solid" if mapeos else "value", "graphMode": "area", "justifyMode": "center", "textMode": "value_and_name" if False else "auto",
                          "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False}, "orientation": "auto"})

def serie(titulo, objetivos, x, w, h=8, unidad="percent", maximo=None, apilado=False):
    d = {"unit": unidad, "custom": {"drawStyle": "line", "lineWidth": 2, "fillOpacity": 18, "gradientMode": "opacity", "showPoints": "never",
                                    "lineInterpolation": "smooth", "stacking": {"mode": "normal" if apilado else "none"}}, "color": {"mode": "palette-classic"}}
    if maximo is not None: d["max"] = maximo
    return panel("timeseries", titulo, x, w, h, objetivos, fieldConfig={"defaults": d, "overrides": []},
                 options={"legend": {"displayMode": "list", "placement": "bottom"}, "tooltip": {"mode": "multi", "sort": "desc"}})

def fila(titulo):
    global y, nid
    P.append({"id": nid, "type": "row", "title": titulo, "collapsed": False, "gridPos": {"x": 0, "y": y, "w": 24, "h": 1}, "panels": []}); nid += 1; y += 1

CPU = '100 - avg(rate(node_cpu_seconds_total{mode="idle"}[5m])) * 100'
RAM = '(1 - node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes) * 100'
DISCO = lambda m: f'(1 - node_filesystem_avail_bytes{{mountpoint="{m}"}} / node_filesystem_size_bytes{{mountpoint="{m}"}}) * 100'

fila("Estado general")
stat("Alertas activas", 'count(ALERTS{alertstate="firing"}) or vector(0)', 0, 4, "none", ((None, VER), (1, ROJ)),
     desc="Alertas de infraestructura activas ahora (también llegan al bot de Telegram).")
stat("Contenedores corriendo", 'sum(centinela_contenedor_arriba)', 4, 4, "none", ((None, ROJ), (19, VER)))
stat("Con fallas", 'count(centinela_contenedor_salud == 0) or vector(0)', 8, 4, "none", ((None, VER), (1, ROJ)))
stat("Elasticsearch", 'centinela_es_salud', 12, 4, "none", ((None, VER), (1, AMB), (2, ROJ)),
     mapeos=[{"type": "value", "options": {"0": {"text": "Verde", "color": VER}, "1": {"text": "Amarillo", "color": AMB},
                                             "2": {"text": "Rojo", "color": ROJ}, "3": {"text": "Sin respuesta", "color": ROJ}}}])
stat("Encendido hace", 'time() - node_boot_time_seconds', 16, 4, "s", ((None, AMB), (3600, VER)))
stat("Ataques a la carnada (24 h)", 'centinela_eventos_24h', 20, 4, "none", ((None, VER), (50000, AMB), (200000, ROJ)),
     desc="Eventos que recibieron los honeypots en las últimas 24 h: tráfico de atacantes contra la carnada, NO contra el servidor real.")
y += 4
stat("CPU", CPU, 0, 4, decimales=1)
stat("Memoria RAM", RAM, 4, 4, decimales=1)
stat("Swap", '(1 - node_memory_SwapFree_bytes / node_memory_SwapTotal_bytes) * 100', 8, 4, decimales=1, pasos=((None, VER), (30, AMB), (60, ROJ)))
stat("Disco sistema (/)", DISCO("/"), 12, 4, decimales=1)
stat("Disco Docker", DISCO("/var/lib/docker"), 16, 4, decimales=1)
stat("Carga / núcleos", 'node_load5 / scalar(count(node_cpu_seconds_total{mode="idle"}))', 20, 4, "none", ((None, VER), (1, AMB), (2, ROJ)), decimales=2)
y += 4

fila("Integridad del servidor real (AIDE + auditd)")
stat("Última revisión AIDE", 'time() - centinela_integridad_ultima_revision', 0, 4, "s", ((None, VER), (5400, AMB), (10800, ROJ)),
     desc="AIDE compara cada hora la huella (hash, permisos, dueño) de binarios, /etc, arranque, llaves SSH, módulos y stacks.")
stat("Archivos vigilados", 'centinela_integridad_archivos', 4, 4, "none", ((None, VER),))
stat("Cambios sin explicación", 'centinela_integridad_inesperados', 8, 4, "none", ((None, VER), (1, ROJ)),
     desc="Archivos cambiados en la última revisión que no vienen de apt ni de un despliegue de Ansible. Debe ser 0.")
stat("Cambios a mano (24 h)", 'sum(centinela_audit_eventos_24h{origen="manual"})', 12, 4, "none", ((None, VER), (1, ROJ)),
     desc="auditd: cambios en usuarios, sudo, SSH, PAM, cron, servicios, firewall o módulos hechos fuera de Ansible/apt.")
stat("auditd", 'centinela_auditd_activo', 16, 4, "none", ((None, ROJ), (1, VER)),
     mapeos=[{"type": "value", "options": {"1": {"text": "Registrando", "color": VER}, "0": {"text": "DETENIDO", "color": ROJ}}}])
stat("Reglas de auditoría", 'centinela_audit_reglas', 20, 4, "none", ((None, ROJ), (40, VER)),
     desc="Reglas cargadas en el kernel. Si bajan, alguien las borró.")
y += 4
panel("bargauge", "Cambios sensibles en 24 h (auditd)", 0, 12, 8,
      [{"expr": 'sum by (clave, origen) (centinela_audit_eventos_24h) > 0', "legendFormat": "{{clave}} · {{origen}}", "instant": True}],
      fieldConfig={"defaults": {"unit": "none", "min": 0, "noValue": "Sin cambios sensibles ✓", "thresholds": umbrales((None, NAR)), "color": {"mode": "thresholds"}},
                   "overrides": [{"matcher": {"id": "byRegexp", "options": ".*manual.*"}, "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": ROJ}}]}]},
      options={"displayMode": "gradient", "orientation": "horizontal", "showUnfilled": True, "reduceOptions": {"calcs": ["lastNotNull"], "values": False}},
      description="Origen: manual (alguien con root), ansible (despliegue), apt (actualizaciones) o docker (arranque de contenedores). Lo manual llega al bot al instante.")
serie("Cambios detectados por AIDE (por hora)", [{"expr": 'increase(centinela_integridad_cambios_total[1h])', "legendFormat": "todos"},
                                                 {"expr": 'increase(centinela_integridad_inesperados_total[1h])', "legendFormat": "sin explicación"}], 12, 12, unidad="none")
y += 8

fila("Rendimiento")
serie("CPU por tipo", [{"expr": f'avg(rate(node_cpu_seconds_total{{mode="{m}"}}[$__rate_interval])) * 100', "legendFormat": n}
                       for m, n in (("user", "usuario"), ("system", "sistema"), ("iowait", "espera de disco"), ("steal", "robado (VM)"))], 0, 12, apilado=True, maximo=100)
serie("Memoria", [{"expr": 'node_memory_MemTotal_bytes - node_memory_MemAvailable_bytes', "legendFormat": "en uso"},
                  {"expr": 'node_memory_Cached_bytes + node_memory_Buffers_bytes', "legendFormat": "caché"},
                  {"expr": 'node_memory_MemTotal_bytes', "legendFormat": "total"}], 12, 12, unidad="bytes")
y += 8
serie("Red (interfaz principal)", [{"expr": 'rate(node_network_receive_bytes_total{device=~"ens.*|eth.*|enp.*"}[$__rate_interval]) * 8', "legendFormat": "entrada {{device}}"},
                                   {"expr": 'rate(node_network_transmit_bytes_total{device=~"ens.*|eth.*|enp.*"}[$__rate_interval]) * 8', "legendFormat": "salida {{device}}"}], 0, 8, unidad="bps")
serie("Disco (lectura / escritura)", [{"expr": 'sum(rate(node_disk_read_bytes_total[$__rate_interval]))', "legendFormat": "lectura"},
                                      {"expr": 'sum(rate(node_disk_written_bytes_total[$__rate_interval]))', "legendFormat": "escritura"}], 8, 8, unidad="Bps")
serie("Carga del sistema", [{"expr": 'node_load1', "legendFormat": "1 min"}, {"expr": 'node_load5', "legendFormat": "5 min"},
                            {"expr": 'count(node_cpu_seconds_total{mode="idle"})', "legendFormat": "núcleos"}], 16, 8, unidad="none")
y += 8
panel("bargauge", "Espacio usado por disco", 0, 12, 7,
      [{"expr": '(1 - node_filesystem_avail_bytes{fstype=~"ext4|xfs|btrfs|vfat"} / node_filesystem_size_bytes{fstype=~"ext4|xfs|btrfs|vfat"}) * 100', "legendFormat": "{{mountpoint}}", "instant": True}],
      fieldConfig={"defaults": {"unit": "percent", "min": 0, "max": 100, "thresholds": umbrales((None, VER), (75, AMB), (85, ROJ)), "color": {"mode": "thresholds"}}, "overrides": []},
      options={"displayMode": "gradient", "orientation": "horizontal", "showUnfilled": True, "reduceOptions": {"calcs": ["lastNotNull"], "values": False}})
panel("table", "Alertas activas", 12, 12, 7, [{"expr": 'ALERTS{alertstate="firing"}', "instant": True, "format": "table"}],
      transformations=[{"id": "organize", "options": {"excludeByName": {"Time": True, "Value": True, "__name__": True, "alertstate": True, "instance": True, "job": True, "infra": True},
                                                      "renameByName": {"alertname": "Alerta", "severidad": "Severidad", "nombre": "Contenedor", "mountpoint": "Disco"}}}],
      fieldConfig={"defaults": {"custom": {"align": "left"}, "noValue": "Sin alertas ✓"}, "overrides": [
          {"matcher": {"id": "byName", "options": "Severidad"}, "properties": [{"id": "custom.cellOptions", "value": {"type": "color-text"}},
              {"id": "mappings", "value": [{"type": "value", "options": {"critica": {"color": ROJ, "text": "CRÍTICA"}, "alta": {"color": NAR, "text": "alta"}}}]}]}]})
y += 7

fila("Contenedores")
tabla = panel("table", "Contenedores (ahora)", 0, 24, 10, [
    {"expr": 'centinela_contenedor_arriba', "instant": True, "format": "table"},
    {"expr": 'centinela_contenedor_salud', "instant": True, "format": "table"},
    {"expr": 'centinela_contenedor_cpu_porcentaje', "instant": True, "format": "table"},
    {"expr": 'centinela_contenedor_memoria_bytes', "instant": True, "format": "table"},
    {"expr": '100 * centinela_contenedor_memoria_bytes / centinela_contenedor_memoria_limite_bytes', "instant": True, "format": "table"},
    {"expr": 'centinela_contenedor_reinicios', "instant": True, "format": "table"}],
    transformations=[{"id": "joinByField", "options": {"byField": "nombre", "mode": "outer"}},
                     {"id": "organize", "options": {"excludeByName": {k: True for k in ["Time", "Time 1", "Time 2", "Time 3", "Time 4", "Time 5", "Time 6", "instance", "instance 1", "instance 2", "instance 3", "instance 4", "instance 5", "instance 6",
                                                                                         "job", "job 1", "job 2", "job 3", "job 4", "job 5", "job 6", "instancia", "instancia 1", "instancia 2", "instancia 3", "instancia 4", "instancia 5", "instancia 6",
                                                                                         "infra", "infra 1", "infra 2", "infra 3", "infra 4", "infra 5", "infra 6"]},
                                                   "renameByName": {"nombre": "Contenedor", "Value #A": "Corriendo", "Value #B": "Salud", "Value #C": "CPU %",
                                                                    "Value #D": "Memoria", "Value #E": "% del límite", "Value #F": "Reinicios"}}},
                     {"id": "sortBy", "options": {"sort": [{"field": "CPU %", "desc": True}]}}],
    fieldConfig={"defaults": {"custom": {"align": "left"}}, "overrides": [
        {"matcher": {"id": "byName", "options": "Corriendo"}, "properties": [{"id": "mappings", "value": [{"type": "value", "options": {"1": {"text": "● sí", "color": VER}, "0": {"text": "● NO", "color": ROJ}}}]},
                                                                               {"id": "custom.cellOptions", "value": {"type": "color-text"}}]},
        {"matcher": {"id": "byName", "options": "Salud"}, "properties": [{"id": "mappings", "value": [{"type": "value", "options": {"1": {"text": "sano", "color": VER}, "0": {"text": "FALLA", "color": ROJ}, "-1": {"text": "sin chequeo", "color": "#9AA3B8"}}}]},
                                                                           {"id": "custom.cellOptions", "value": {"type": "color-text"}}]},
        {"matcher": {"id": "byName", "options": "Memoria"}, "properties": [{"id": "unit", "value": "bytes"}]},
        {"matcher": {"id": "byName", "options": "CPU %"}, "properties": [{"id": "unit", "value": "percent"}, {"id": "decimals", "value": 1},
                                                                           {"id": "custom.cellOptions", "value": {"type": "gauge", "mode": "gradient"}}, {"id": "max", "value": 100},
                                                                           {"id": "thresholds", "value": umbrales((None, VER), (60, AMB), (85, ROJ))}]},
        {"matcher": {"id": "byName", "options": "% del límite"}, "properties": [{"id": "unit", "value": "percent"}, {"id": "decimals", "value": 0},
                                                                                  {"id": "custom.cellOptions", "value": {"type": "gauge", "mode": "gradient"}}, {"id": "max", "value": 100},
                                                                                  {"id": "thresholds", "value": umbrales((None, VER), (75, AMB), (90, ROJ))}]}]})
y += 10
serie("CPU por contenedor", [{"expr": 'topk(8, centinela_contenedor_cpu_porcentaje)', "legendFormat": "{{nombre}}"}], 0, 12)
serie("Memoria por contenedor", [{"expr": 'topk(8, centinela_contenedor_memoria_bytes)', "legendFormat": "{{nombre}}"}], 12, 12, unidad="bytes")
y += 8
fila("Actividad del honeypot (carnada)")
stat("Eventos última hora", 'centinela_eventos_1h', 0, 6, "none", ((None, VER), (10000, AMB), (40000, ROJ)))
stat("Eventos 24 h", 'centinela_eventos_24h', 6, 6, "none", ((None, VER),))
stat("Atacantes únicos (24 h)", 'centinela_atacantes_24h', 12, 6, "none", ((None, VER),))
stat("Ataques graves (24 h)", 'centinela_ataques_graves_24h', 18, 6, "none", ((None, VER), (1, NAR)),
     desc="Eventos clasificados con severidad alta o crítica (explotación de CVE, malware, honeytokens).")
y += 4
serie("Eventos contra los honeypots (ventana de 1 h)", [{"expr": 'centinela_eventos_1h', "legendFormat": "última hora"},
                                                       {"expr": 'centinela_eventos_5m * 12', "legendFormat": "ritmo actual (5 min × 12)"}], 0, 24, 7, unidad="none")

dash = {"uid": "centinela-salud", "title": "Centinela · Salud de la infraestructura", "tags": ["centinela", "infra"], "timezone": "America/Bogota",
        "schemaVersion": 39, "version": 2, "editable": False, "graphTooltip": 1, "refresh": "30s", "time": {"from": "now-6h", "to": "now"},
        "panels": P, "templating": {"list": []}, "annotations": {"list": []},
        "description": "CPU, memoria, discos, red, contenedores, integridad (AIDE/auditd), Elasticsearch y alertas activas del servidor del honeypot."}
json.dump(dash, open("dashboards/centinela-salud.json", "w"), ensure_ascii=False, indent=1)
print("✓ dashboards/centinela-salud.json ·", len(P), "paneles")
