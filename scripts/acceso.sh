#!/usr/bin/env bash
# Da o quita acceso a Centinela (console./ops./insights./metrics./shell.) con un solo comando.
#
#   ./scripts/acceso.sh agregar  persona@example.com [persona@example.com ...]
#   ./scripts/acceso.sh quitar   persona@example.com [...]
#   ./scripts/acceso.sh listar
#
# Qué hace "agregar" con cada correo:
#   1. Cloudflare Access: lo mete en la política "Solo admin Centinela" (sirve para la app y WARP).
#   2. Consola: lo agrega a correos_permitidos y redespliega el panel (ansible --tags panel).
# Auth0 NO se toca: el registro está abierto y crea la cuenta sola en el primer inicio de sesión
# (código por correo). Quien decide si entra es la lista de Cloudflare Access.
# Todo es idempotente: si el correo ya está, no cambia nada. Nunca imprime secretos.
# Grafana crea solo al usuario como Viewer. Kibana y Portainer tienen cuentas aparte (no se tocan aquí).
set -euo pipefail
source "$(dirname "$0")/../config.env"   # tu dominio, IDs de Cloudflare y correo admin (ver config.example.env)

B="$(cd "$(dirname "$0")/.." && pwd)"; A="$B/hardening-ubuntu"; S="$A/secretos"
VARS="$A/group_vars/all/main.yml"
CF_API="https://api.cloudflare.com/client/v4/accounts/${CF_ACCOUNT_ID}"
CF_POLICY="${CF_POLICY_ID}"   # "Solo admin Centinela"

verde() { printf '\033[32m%s\033[0m\n' "$*"; }
amarillo() { printf '\033[33m%s\033[0m\n' "$*"; }
rojo() { printf '\033[31m%s\033[0m\n' "$*" >&2; }
muere() { rojo "$*"; exit 1; }

for c in curl jq python3 ansible-playbook; do command -v $c >/dev/null || muere "Falta '$c'."; done

valida_correo() {
  [[ "$1" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]] || muere "Correo inválido: $1"
}

# ───────────────────────── Cloudflare Access ─────────────────────────
cf() { # método ruta [json] — reintenta si Cloudflare responde un error temporal (504, HTML, sin respuesta)
  local T r i; T=$(cat "$S/cloudflare_token")
  for i in 1 2 3 4 5; do
    r=$(curl -sS -m 30 -X "$1" -H "Authorization: Bearer $T" -H "Content-Type: application/json" \
         "$CF_API$2" ${3:+--data "$3"} 2>/dev/null) || r=""
    jq -e . >/dev/null 2>&1 <<<"$r" && { printf '%s' "$r"; return 0; }
    sleep $((i * 3))
  done
  printf '%s' '{"success":false,"errors":[{"message":"Cloudflare no responde (reintentado 5 veces)"}]}'
}

cf_politica() {
  local r; r=$(cf GET "/access/policies/$CF_POLICY")
  [[ $(jq -r .success <<<"$r") == true ]] || muere "Cloudflare: no pude leer la política: $(jq -c .errors <<<"$r")"
  jq .result <<<"$r"
}

cf_correos() { cf_politica | jq -r '.include[] | .email.email // empty'; }

cf_guardar() { # recibe la política modificada por stdin y la sube (solo campos editables)
  local body r
  body=$(jq '{name, decision, include, exclude, require, session_duration}
             + (if has("isolation_required") then {isolation_required} else {} end)
             + (if has("approval_required") then {approval_required, approval_groups} else {} end)
             + (if has("purpose_justification_required") then {purpose_justification_required, purpose_justification_prompt} else {} end)')
  r=$(cf PUT "/access/policies/$CF_POLICY" "$body")
  [[ $(jq -r .success <<<"$r") == true ]] || muere "Cloudflare: no pude guardar la política: $(jq -c .errors <<<"$r")"
}

cf_agregar() {
  local e=$1 pol
  pol=$(cf_politica)
  if jq -e --arg e "$e" 'any(.include[]; (.email.email // "" | ascii_downcase) == $e)' <<<"$pol" >/dev/null; then
    echo "  Cloudflare: ya estaba"; return
  fi
  jq --arg e "$e" '.include += [{email:{email:$e}}]' <<<"$pol" | cf_guardar
  verde "  Cloudflare: agregado a la política"
}

cf_quitar() {
  local e=$1 pol
  [[ "$e" == "$ADMIN_EMAIL" ]] && muere "No quito al admin de Cloudflare."
  pol=$(cf_politica)
  if ! jq -e --arg e "$e" 'any(.include[]; (.email.email // "" | ascii_downcase) == $e)' <<<"$pol" >/dev/null; then
    echo "  Cloudflare: no estaba"; return
  fi
  jq --arg e "$e" '.include |= map(select((.email.email // "" | ascii_downcase) != $e))' <<<"$pol" | cf_guardar
  verde "  Cloudflare: quitado de la política"
}

# ─────────────────────────── Consola (panel) ───────────────────────────
consola() { # agregar|quitar correo → imprime "cambio" o "igual"
  python3 - "$VARS" "$1" "$2" <<'PY'
import os, sys, re
f, op, e = sys.argv[1], sys.argv[2], sys.argv[3].lower()
s = open(f).read()
m = re.search(r'^correos_permitidos:\s*\[(.*)\]\s*$', s, re.M)
if not m: sys.exit("No encontré 'correos_permitidos: [...]' en " + f)
lista = [x.strip().strip('"\'') for x in m.group(1).split(',') if x.strip()]
antes = list(lista)
if op == "agregar" and e not in [x.lower() for x in lista]: lista.append(e)
if op == "quitar":
    if e == os.environ["ADMIN_EMAIL"]: sys.exit("No quito al admin de la consola.")
    lista = [x for x in lista if x.lower() != e]
if lista == antes: print("igual"); sys.exit()
s = s[:m.start()] + "correos_permitidos: [" + ", ".join(lista) + "]" + s[m.end():]
open(f, "w").write(s); print("cambio")
PY
}

redesplegar_panel() {
  if ps aux | grep -E 'ssh .*200\.116\.199\.229' | grep -v grep >/dev/null; then
    amarillo "Ojo: hay una sesión SSH abierta al servidor (MaxSessions 2). Si Ansible falla con 'Session open refused', ciérrala y reintenta."
  fi
  echo "Redesplegando el panel (console.)..."
  cd "$A"
  ansible-playbook tocar.yml >/dev/null
  ansible-playbook site.yml --tags panel 2>&1 | grep -E 'fatal|failed:|unreachable|PLAY RECAP|srv-honey +:' || true
  ansible srv-honey -b -m shell -a 'docker exec panel printenv CORREOS_PERMITIDOS' 2>/dev/null | tail -1 \
    | tr ',' '\n' | sed 's/^/  consola: /'
}

# ───────────────────────────── comandos ─────────────────────────────
cmd=${1:-}; shift || true

case "$cmd" in
  agregar|quitar)
    [[ $# -ge 1 ]] || muere "Uso: $0 $cmd correo@dominio.com [...]"
    panel=0
    for raw in "$@"; do
      e=$(tr 'A-Z' 'a-z' <<<"$raw"); valida_correo "$e"
      echo "▶ $cmd $e"
      if [[ $cmd == agregar ]]; then cf_agregar "$e"; else cf_quitar "$e"; fi
      if [[ $(consola "$cmd" "$e") == cambio ]]; then panel=1; verde "  Consola: lista actualizada"
      else echo "  Consola: sin cambios"; fi
    done
    [[ $panel == 1 ]] && redesplegar_panel
    echo
    if [[ $cmd == agregar ]]; then
      verde "Listo. Entran por https://console.$DOMINIO con su correo (código por email) y la primera vez enrolan su MFA."
    else
      amarillo "Listo. Si tenía una sesión abierta, dura hasta 8 h: para cortarla ya, Zero Trust → Users → Revoke sessions."
    fi
    ;;
  listar)
    echo "Cloudflare Access (política):"; cf_correos | sed 's/^/  /'
    echo "Consola (correos_permitidos):"; sed -n 's/^correos_permitidos: *\[\(.*\)\]/\1/p' "$VARS" | tr ',' '\n' | sed 's/^ */  /'
    ;;
  *)
    sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'; exit 1 ;;
esac
