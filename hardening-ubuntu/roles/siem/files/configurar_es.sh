#!/usr/bin/env bash
# Configura Elasticsearch para Centinela (idempotente). Lee secretos de /opt/stacks/siem/.env
set -euo pipefail
cd /opt/stacks/siem
set -a; . ./.env; . ./setup/usuarios.env; set +a
ES="https://${ES_IP}:9200"
c() { curl -sS --fail-with-body --cacert certs/ca.crt -u "elastic:${ELASTIC_PASSWORD}" -H 'Content-Type: application/json' "$@"; echo; }

# Rotación del superusuario: si la contraseña nueva aún no funciona, se cambia usando la anterior
if [ -n "${ELASTIC_ANTERIOR:-}" ] && ! curl -sf -o /dev/null --cacert certs/ca.crt -u "elastic:${ELASTIC_PASSWORD}" "$ES/_security/_authenticate"; then
  echo "· rotando contraseña de elastic"
  curl -sS --fail-with-body --cacert certs/ca.crt -u "elastic:${ELASTIC_ANTERIOR}" -H 'Content-Type: application/json' \
       -X POST "$ES/_security/user/elastic/_password" -d "{\"password\":\"${ELASTIC_PASSWORD}\"}" >/dev/null
fi
echo "· contraseña de kibana_system"
c -X POST "$ES/_security/user/kibana_system/_password" -d "{\"password\":\"${KIBANA_PASSWORD}\"}" >/dev/null

echo "· roles"
c -X PUT "$ES/_security/role/centinela_ingest" -d '{"cluster":["monitor","read_pipeline"],"indices":[{"names":["honeypot-*"],"privileges":["create_doc","auto_configure","view_index_metadata"]}]}' >/dev/null
c -X PUT "$ES/_security/role/centinela_panel" -d '{"cluster":["monitor"],"indices":[{"names":["honeypot-*","cloudflare-*"],"privileges":["read","view_index_metadata"]}]}' >/dev/null
c -X PUT "$ES/_security/role/centinela_vigia" -d '{"cluster":["monitor"],"indices":[{"names":["honeypot-*","cloudflare-*"],"privileges":["read","view_index_metadata"]}]}' >/dev/null
c -X PUT "$ES/_security/role/centinela_cfmetrics" -d '{"cluster":["monitor"],"indices":[{"names":["cloudflare-*"],"privileges":["create_doc","auto_configure","view_index_metadata","read"]}]}' >/dev/null
c -X PUT "$ES/_security/role/centinela_analista" -d '{"cluster":["monitor","manage_index_templates","manage_ilm","manage_pipeline"],"indices":[{"names":["honeypot-*","cloudflare-*"],"privileges":["all"]}]}' >/dev/null

echo "· usuarios"
u() { c -X PUT "$ES/_security/user/$1" -d "{\"password\":\"$2\",\"roles\":$3,\"full_name\":\"$4\"}" >/dev/null; }
u centinela_ingest    "$INGEST_PASSWORD"    '["centinela_ingest"]'    "Filebeat (solo escribe eventos)"
u centinela_panel     "$PANEL_PASSWORD"     '["centinela_panel"]'     "Panel Centinela (solo lectura)"
u centinela_cfmetrics "$CFMETRICS_PASSWORD" '["centinela_cfmetrics"]' "Colector de Cloudflare"
[ -n "${VISOR_PASSWORD:-}" ] && u centinela_visor "$VISOR_PASSWORD" '["viewer"]' "Kibana vía Cloudflare Access (solo lectura)"
[ -n "${VIGIA_PASSWORD:-}" ] && u centinela_vigia "$VIGIA_PASSWORD" '["centinela_vigia"]' "Vigía de alertas (solo lectura)"
u "$ADMIN_USER"    "$ADMIN_PASSWORD"     '["kibana_admin","centinela_analista","monitoring_user"]' "Administrador Centinela"

echo "· política de retención (ILM)"
c -X PUT "$ES/_ilm/policy/centinela-retencion" -d "{\"policy\":{\"phases\":{
  \"hot\":{\"actions\":{\"rollover\":{\"max_age\":\"7d\",\"max_primary_shard_size\":\"10gb\"}}},
  \"delete\":{\"min_age\":\"${RETENCION_DIAS}d\",\"actions\":{\"delete\":{}}}}}}" >/dev/null

echo "· plantillas"
for t in setup/plantilla_*.json; do n=$(basename "$t" .json); n=${n#plantilla_}; c -X PUT "$ES/_index_template/$n" -d @"$t" >/dev/null; done

echo "· campos nuevos en los índices existentes (solo se agregan)"
jq '.template.mappings | {properties}' setup/plantilla_honeypot-events.json \
  | curl -sS --fail-with-body --cacert certs/ca.crt -u "elastic:${ELASTIC_PASSWORD}" -H 'Content-Type: application/json' \
         -X PUT "$ES/honeypot-events/_mapping" -d @- >/dev/null 2>&1 || echo "  (aún no existe el data stream)"

echo "· pipeline de ingesta"
c -X PUT "$ES/_ingest/pipeline/honeypot" -d @setup/pipeline_honeypot.api.json >/dev/null

echo "· snapshots diarios (03:30, se guardan 7)"
c -X PUT "$ES/_snapshot/local" -d '{"type":"fs","settings":{"location":"/usr/share/elasticsearch/snapshots","compress":true}}' >/dev/null
c -X PUT "$ES/_slm/policy/diario" -d '{"schedule":"0 30 8 * * ?","name":"<centinela-{now/d}>","repository":"local","config":{"indices":["honeypot-*","cloudflare-*"],"include_global_state":true},"retention":{"expire_after":"8d","min_count":1,"max_count":7}}' >/dev/null

echo "· data streams"
for ds in honeypot-events cloudflare-metrics cloudflare-events; do
  curl -s -o /dev/null -w '' --cacert certs/ca.crt -u "elastic:${ELASTIC_PASSWORD}" -X PUT "$ES/_data_stream/$ds" || true
done
echo "OK: Elasticsearch configurado"
