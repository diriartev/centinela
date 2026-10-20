#!/usr/bin/env bash
# Escribe el estado de los contenedores y del host para el panel y el vigía
# (ninguno de los dos tiene acceso al socket de Docker ni al host).
set -euo pipefail
OUT=/opt/stacks/panel/status/estado.json
TMP=$(mktemp)
contenedores=$(docker ps -a --format '{{json .}}' | jq -s '[.[] | {nombre: .Names, imagen: .Image, estado: .State, detalle: .Status,
  salud: (if (.Status|test("\\(healthy\\)")) then "healthy" elif (.Status|test("unhealthy")) then "unhealthy" else null end)}]')
read -r c1 c5 c15 _ < /proc/loadavg
mt=$(awk '/MemTotal/{print $2*1024}' /proc/meminfo); ma=$(awk '/MemAvailable/{print $2*1024}' /proc/meminfo)
read -r dt du < <(df -B1 --output=size,used /var/lib/docker | tail -1)
read -r rt ru < <(df -B1 --output=size,used / | tail -1)

# Eventos de seguridad del servidor REAL (el vigía los avisa por Telegram): SSH, knocking, Fail2Ban, auditd y AIDE
eventos=$( {
  journalctl -u ssh --since "-15min" -o short-iso --no-pager 2>/dev/null | grep -E "sshd\[[0-9]+\]: Accepted (password|publickey|keyboard-interactive)" \
    | awk '{for(i=1;i<=NF;i++){if($i=="Accepted")m=$(i+1); if($i=="for")u=$(i+1); if($i=="from")ip=$(i+1)}
           printf "{\"tipo\":\"ssh\",\"fecha\":\"%s\",\"metodo\":\"%s\",\"usuario\":\"%s\",\"ip\":\"%s\"}\n",$1,m,u,ip}'
  journalctl -u knockd --since "-15min" -o short-iso --no-pager 2>/dev/null | grep -E "OPEN SESAME" \
    | awk '{ip=$4; sub(":$","",ip); printf "{\"tipo\":\"knock\",\"fecha\":\"%s\",\"ip\":\"%s\"}\n",$1,ip}'
  journalctl -u fail2ban --since "-15min" -o short-iso --no-pager 2>/dev/null | grep -E "\] Ban " \
    | awk '{for(i=1;i<=NF;i++){if($i=="Ban")ip=$(i+1); if($i ~ /^\[.*\]$/)j=$i} gsub(/[\[\]]/,"",j)
           printf "{\"tipo\":\"ban\",\"fecha\":\"%s\",\"ip\":\"%s\",\"jail\":\"%s\"}\n",$1,ip,j}'
  # Integridad: cambios sensibles en tiempo real (auditd) y revisiones de AIDE de las últimas 24 h
  [ -x /usr/local/sbin/centinela-integridad ] && /usr/local/sbin/centinela-integridad audit 15 2>/dev/null | jq -c '.[]?'
  [ -r /var/lib/centinela/integridad/eventos.json ] && jq -c --arg d "$(date -u -d '-24 hours' +%FT%TZ)" '.[]? | select(.fecha >= $d)' /var/lib/centinela/integridad/eventos.json
  true   # sin coincidencias no es un error
} | jq -s -c '.' 2>/dev/null) || eventos='[]'
[ -n "$eventos" ] || eventos='[]'

jq -n --argjson c "$contenedores" --argjson ev "$eventos" --arg c5 "$c5" --arg cpus "$(nproc)" --arg mt "$mt" --arg ma "$ma" --arg dt "$dt" --arg du "$du" --arg rt "$rt" --arg ru "$ru" \
  '{actualizado: (now|todate), contenedores: $c, eventos_host: $ev, host: {carga5: ($c5|tonumber), cpus: ($cpus|tonumber), ram_total: ($mt|tonumber),
    ram_usada: (($mt|tonumber)-($ma|tonumber)), docker_total: ($dt|tonumber), docker_usado: ($du|tonumber), raiz_total: ($rt|tonumber), raiz_usado: ($ru|tonumber)}}' > "$TMP"
chmod 0644 "$TMP"; mv -f "$TMP" "$OUT"

# ── Métricas para Prometheus (colector "textfile" de node-exporter) ──────────────
set +e +o pipefail   # una métrica que falle no debe tumbar el resto
DIR=/var/lib/centinela/textfile; mkdir -p "$DIR"; PROM=$(mktemp -p "$DIR" .centinela.XXXX)
{
  echo "# HELP centinela_estado_timestamp Última ejecución del script de estado"
  echo "# TYPE centinela_estado_timestamp gauge"; echo "centinela_estado_timestamp $(date +%s)"
  echo "# TYPE centinela_contenedor_arriba gauge"; echo "# TYPE centinela_contenedor_salud gauge"; echo "# TYPE centinela_contenedor_reinicios counter"
  docker inspect $(docker ps -aq) --format '{{.Name}} {{.State.Running}} {{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}} {{.RestartCount}}' 2>/dev/null \
    | awk '{n=substr($1,2); up=($2=="true")?1:0; s=($3=="healthy")?1:(($3=="none")?-1:0);
            printf "centinela_contenedor_arriba{nombre=\"%s\"} %d\ncentinela_contenedor_salud{nombre=\"%s\"} %d\ncentinela_contenedor_reinicios{nombre=\"%s\"} %d\n",n,up,n,s,n,$4}'
  echo "# TYPE centinela_contenedor_cpu_porcentaje gauge"; echo "# TYPE centinela_contenedor_memoria_bytes gauge"; echo "# TYPE centinela_contenedor_memoria_limite_bytes gauge"
  docker stats --no-stream --format '{{.Name}} {{.CPUPerc}} {{.MemUsage}}' 2>/dev/null | awk '
    function b(v,  n,u){ n=v+0; u=v; gsub(/[0-9.]/,"",u); if(u=="KiB")n*=1024; else if(u=="MiB")n*=1048576; else if(u=="GiB")n*=1073741824; else if(u=="kB")n*=1000; else if(u=="MB")n*=1e6; else if(u=="GB")n*=1e9; return n }
    { c=$2; sub(/%/,"",c); printf "centinela_contenedor_cpu_porcentaje{nombre=\"%s\"} %s\ncentinela_contenedor_memoria_bytes{nombre=\"%s\"} %.0f\ncentinela_contenedor_memoria_limite_bytes{nombre=\"%s\"} %.0f\n",$1,c,$1,b($3),$1,b($5) }'
  echo "# TYPE centinela_systemd_fallidos gauge"; echo "centinela_systemd_fallidos $(systemctl --failed --no-legend --plain 2>/dev/null | wc -l)"
  echo "# TYPE centinela_reinicio_pendiente gauge"; echo "centinela_reinicio_pendiente $([ -f /var/run/reboot-required ] && echo 1 || echo 0)"
  # Elasticsearch: 0 verde · 1 amarillo · 2 rojo · 3 sin respuesta; y volumen de eventos (detecta picos / DoS)
  if [ -r /opt/stacks/siem/.env ]; then
    EP=$(grep -E '^ELASTIC_PASSWORD=' /opt/stacks/siem/.env | cut -d= -f2-)
    st=$(curl -s -m 5 --cacert /opt/stacks/siem/certs/ca.crt -u "elastic:$EP" https://10.213.252.10:9200/_cluster/health | jq -r '.status // "x"' 2>/dev/null || echo x)
    case "$st" in green) v=0;; yellow) v=1;; red) v=2;; *) v=3;; esac
    echo "# TYPE centinela_es_salud gauge"; echo "centinela_es_salud $v"
    # Eventos recibidos por los honeypots (tráfico de atacantes contra la carnada, NO contra el servidor real)
    for v in 5m 1h 24h; do
      ev=$(curl -s -m 5 --cacert /opt/stacks/siem/certs/ca.crt -u "elastic:$EP" -H 'Content-Type: application/json' https://10.213.252.10:9200/honeypot-events/_count \
           -d "{\"query\":{\"range\":{\"@timestamp\":{\"gte\":\"now-$v\"}}}}" | jq -r '.count // 0' 2>/dev/null || echo 0)
      echo "# TYPE centinela_eventos_$v gauge"; echo "centinela_eventos_$v ${ev:-0}"
    done
    ips=$(curl -s -m 5 --cacert /opt/stacks/siem/certs/ca.crt -u "elastic:$EP" -H 'Content-Type: application/json' "https://10.213.252.10:9200/honeypot-events/_search?size=0" \
         -d '{"query":{"range":{"@timestamp":{"gte":"now-24h"}}},"aggs":{"i":{"cardinality":{"field":"source.ip"}},"g":{"filter":{"range":{"ataque.severidad":{"gte":3}}}}}}' \
         | jq -r '"\(.aggregations.i.value // 0) \(.aggregations.g.doc_count // 0)"' 2>/dev/null || echo "0 0")
    echo "# TYPE centinela_atacantes_24h gauge"; echo "centinela_atacantes_24h ${ips%% *}"
    echo "# TYPE centinela_ataques_graves_24h gauge"; echo "centinela_ataques_graves_24h ${ips##* }"
    unset EP
  fi
} > "$PROM" 2>/dev/null
chmod 0644 "$PROM"; mv -f "$PROM" "$DIR/centinela.prom"
