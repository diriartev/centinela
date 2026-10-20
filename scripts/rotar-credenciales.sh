#!/usr/bin/env bash
# Rota credenciales de Centinela y las aplica en el servidor (no imprime ningún secreto).
#   ./scripts/rotar-credenciales.sh elastic-servicios   # kibana_system, ingest, panel, cfmetrics y tu usuario de Kibana
#   ./scripts/rotar-credenciales.sh elastic             # superusuario "elastic"
#   ./scripts/rotar-credenciales.sh knock               # nueva secuencia de 5 puertos
#   ./scripts/rotar-credenciales.sh portainer           # contraseña del admin de Portainer
#   ./scripts/rotar-credenciales.sh tunel               # secreto del túnel de Cloudflare
#   ./scripts/rotar-credenciales.sh relay               # clave de firma servidor → bot de Telegram
#   (token del bot de Telegram: @BotFather /revoke y luego ./scripts/configurar-bot-telegram.sh)
# Al final regenera CREDENCIALES/credenciales.md
set -euo pipefail
source "$(dirname "$0")/../config.env"   # tu dominio, IDs de Cloudflare y correo admin (ver config.example.env)
B="$(cd "$(dirname "$0")/.." && pwd)"; A="$B/hardening-ubuntu"; S="$A/secretos"
nueva() { python3 -c "import secrets,string;a=string.ascii_letters+string.digits;print(''.join(secrets.choice(a) for _ in range(${1:-32})))"; }
fijar() { # archivo clave valor  (reemplaza la línea sin mostrar el valor)
  python3 - "$1" "$2" "$3" <<'PY'
import sys,re
f,k,v=sys.argv[1:4]; s=open(f).read()
if re.search(rf'^{k}:',s,re.M): s=re.sub(rf'^{k}:.*$',f'{k}: "{v}"',s,flags=re.M)
else: s+=f'{k}: "{v}"\n'
open(f,'w').write(s)
PY
}
cd "$A"; "$B/scripts/backup-servidor.sh" >/dev/null
case "${1:-}" in
  elastic-servicios)
    for k in es_kibana_system_password es_ingest_password es_panel_password es_cfmetrics_password es_vigia_password; do fijar "$S/stack.yml" $k "$(nueva 32)"; done
    fijar "$S/stack.yml" es_admin_password "$(nueva 24)"
    python3 "$B/knocking/knock.py" >/dev/null; ansible-playbook site.yml --tags siem,panel,cfmetrics,vigia ;;
  elastic)
    viejo=$(grep -E '^es_elastic_password:' "$S/stack.yml" | sed -E 's/^[^"]*"(.*)"$/\1/')
    fijar "$S/stack.yml" es_elastic_password_anterior "$viejo"; fijar "$S/stack.yml" es_elastic_password "$(nueva 32)"
    python3 "$B/knocking/knock.py" >/dev/null; ansible-playbook site.yml --tags siem
    fijar "$S/stack.yml" es_elastic_password_anterior "" ;;
  knock)
    python3 "$B/knocking/knock.py" >/dev/null   # abre con la secuencia ACTUAL (5 min) antes de cambiarla
    python3 - "$S/generados.yml" <<'PY2'
import sys,re,secrets
r=secrets.SystemRandom(); f=sys.argv[1]; s=open(f).read()
ssh=int(re.search(r'^ssh_puerto:\s*(\d+)',s,re.M).group(1))
res=set(range(0,1024))|set(range(32768,61000))|{ssh,1080,1433,2222,2323,2375,2376,3306,3389,5000,5432,5555,5601,5900,6379,8000,8080,8443,9000,9200,9300,9443,11211,27017}
pool=[x for x in range(1024,65536) if x not in res]
sec=[f"{p}:{r.choice(['tcp','udp'])}" for p in r.sample(pool,5)]
s=re.sub(r'^knock_secuencia:.*$',f'knock_secuencia: {sec}',s,flags=re.M); open(f,'w').write(s)
PY2
    ansible-playbook site.yml --tags firewall ;;
  portainer)
    nuevo=$(nueva 28); viejo=$(grep -E '^portainer_admin_password:' "$S/generados.yml" | sed -E 's/^[^"]*"(.*)"$/\1/')
    python3 "$B/knocking/knock.py" >/dev/null
    ansible honeypot -m shell -a "set -e; U=https://10.213.251.10:9443/api; J=\$(curl -sk \$U/auth -d '{\"username\":\"admin\",\"password\":\"$viejo\"}' | jq -r .jwt); curl -skf -X PUT \$U/users/1/passwd -H \"Authorization: Bearer \$J\" -d '{\"password\":\"$viejo\",\"newPassword\":\"$nuevo\"}' >/dev/null && echo OK" 2>/dev/null | tail -1
    fijar "$S/generados.yml" portainer_admin_password "$nuevo"
    ansible-playbook site.yml --tags portainer >/dev/null ;;
  tunel)
    T=$(cat "$S/cloudflare_token"); TID=$(awk '/cloudflared_tunnel_id/{print $2}' "$S/cloudflared.yml")
    API=https://api.cloudflare.com/client/v4/accounts/${CF_ACCOUNT_ID}/cfd_tunnel/$TID
    curl -sf -X PATCH -H "Authorization: Bearer $T" -H 'Content-Type: application/json' "$API" -d "{\"tunnel_secret\":\"$(head -c 32 /dev/urandom | base64)\"}" >/dev/null
    (umask 077; curl -sf -H "Authorization: Bearer $T" "$API/token" | jq -r .result > "$S/cloudflared_tunnel_token")
    python3 "$B/knocking/knock.py" >/dev/null; ansible-playbook site.yml --tags edge ;;
  relay)
    (umask 077; python3 -c "import secrets;print(secrets.token_hex(32),end='')" > "$S/relay_hmac_key")
    (cd "$B/cloudflare/worker-hooks" && CLOUDFLARE_API_TOKEN="$(cat "$S/cloudflare_token")" npx -y wrangler@4 secret put RELAY_KEY < "$S/relay_hmac_key" >/dev/null 2>&1)
    python3 "$B/knocking/knock.py" >/dev/null; ansible-playbook site.yml --tags vigia ;;
  *) sed -n '2,11p' "$0"; exit 1 ;;
esac
python3 "$B/scripts/generar-credenciales.py"
echo "✓ Rotación '$1' aplicada. Actualiza tu gestor de contraseñas con CREDENCIALES/credenciales.md"
