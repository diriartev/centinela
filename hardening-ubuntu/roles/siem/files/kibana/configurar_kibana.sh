#!/usr/bin/env bash
# Configura Kibana: modo oscuro, zona horaria, vistas de datos y dashboards (idempotente).
set -euo pipefail
cd /opt/stacks/siem; set -a; . ./.env; . ./setup/usuarios.env; set +a
K="https://${KIBANA_IP}:5601"
k() { curl -sS --cacert certs/ca.crt --fail-with-body -u "elastic:${ELASTIC_PASSWORD}" -H 'kbn-xsrf: true' -H 'Content-Type: application/json' "$@"; echo; }
for i in $(seq 1 60); do curl -s --cacert certs/ca.crt -o /dev/null -w '%{http_code}' -u "elastic:${ELASTIC_PASSWORD}" "$K/api/status" | grep -q 200 && break; sleep 5; done
echo "· vistas de datos"
dv() { curl -s --cacert certs/ca.crt -o /dev/null -u "elastic:${ELASTIC_PASSWORD}" -H 'kbn-xsrf: true' -X DELETE "$K/api/data_views/data_view/$1" || true
       k -X POST "$K/api/data_views/data_view" -d "{\"override\":true,\"data_view\":{\"id\":\"$1\",\"title\":\"$2\",\"name\":\"$3\",\"timeFieldName\":\"@timestamp\"}}" >/dev/null; }
dv dv-honeypot "honeypot-events*" "Honeypot · eventos"
dv dv-cf-metrics "cloudflare-metrics*" "Cloudflare · métricas"
dv dv-cf-events "cloudflare-events*" "Cloudflare · eventos"
echo "· ajustes (modo oscuro, zona horaria, vista por defecto)"
k -H "x-elastic-internal-origin: Kibana" -X POST "$K/internal/kibana/settings" -d '{"changes":{"theme:darkMode":"enabled","dateFormat:tz":"America/Bogota","defaultIndex":"dv-honeypot","dateFormat":"YYYY-MM-DD HH:mm:ss","timepicker:timeDefaults":"{\"from\":\"now-24h\",\"to\":\"now\"}","defaultRoute":"/app/dashboards#/view/d-honeypot","hideAnnouncements":true}}' >/dev/null
echo "· dashboards"
curl -sS --cacert certs/ca.crt --fail-with-body -u "elastic:${ELASTIC_PASSWORD}" -H 'kbn-xsrf: true' -X POST "$K/api/saved_objects/_import?overwrite=true" --form file=@setup/objetos.ndjson | jq -c '{ok:.success,importados:.successCount,errores:[.errors[]?|{id,e:.error.type}]}'
echo "OK: Kibana configurado"
