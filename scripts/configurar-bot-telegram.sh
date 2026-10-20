#!/usr/bin/env bash
# Centinela · Configura el bot de Telegram de alertas (ejecútalo TÚ en tu terminal).
#
# Antes: en Telegram habla con @BotFather →  /newbot  (ponle un nombre que no diga "honeypot")
#        y copia el token. Recomendado en @BotFather: /setjoingroups → Disable.
#
# Qué hace (el token nunca se muestra ni se guarda en disco):
#   1. Pide el token sin mostrarlo y comprueba que es válido.
#   2. Te pide escribirle /start al bot para conocer TU chat (solo ese chat podrá usarlo).
#   3. Guarda token, chat y secretos como "secrets" del Worker hooks.example.com.
#   4. Conecta Telegram con el Worker (webhook con secreto) y registra los comandos.
# Repetirlo sirve también para ROTAR el token (en @BotFather: /revoke y luego este script).
set -euo pipefail
source "$(dirname "$0")/../config.env"   # tu dominio, IDs de Cloudflare y correo admin (ver config.example.env)
D="$(cd "$(dirname "$0")/.." && pwd)"
W="$D/cloudflare/worker-hooks"
SEC="$D/hardening-ubuntu/secretos"
HOOK="https://hooks.$DOMINIO/tg/webhook"
export CLOUDFLARE_API_TOKEN="$(cat "$SEC/cloudflare_token")"

c_ok() { printf '\033[1;32m✓\033[0m %s\n' "$*"; }
c_info() { printf '\033[1;33m›\033[0m %s\n' "$*"; }
c_err() { printf '\033[1;31m✗\033[0m %s\n' "$*" >&2; exit 1; }

[ -t 0 ] || c_err "Ejecuta este script en una terminal normal (necesita leer el token sin mostrarlo)."
command -v jq >/dev/null || c_err "Falta jq (sudo dnf install jq)."
[ -s "$SEC/relay_hmac_key" ] || c_err "Falta $SEC/relay_hmac_key (la crea scripts/inicializar-secretos.py)."

printf '\033[1;33m›\033[0m Pega el token de @BotFather (no se verá) y Enter: '
read -rs TOKEN; echo
[[ "$TOKEN" =~ ^[0-9]+:[A-Za-z0-9_-]{30,}$ ]] || c_err "Eso no parece un token de bot."
API="https://api.telegram.org/bot$TOKEN"

YO=$(curl -s "$API/getMe" | jq -r 'if .ok then .result.username else empty end')
[ -n "$YO" ] || c_err "Telegram rechazó el token."
c_ok "Bot válido: @$YO"

curl -s "$API/deleteWebhook?drop_pending_updates=true" >/dev/null
c_info "Abre Telegram, entra a @$YO y escríbele /start  (espero hasta 3 minutos)…"
CHAT=""; NOMBRE=""
for _ in $(seq 1 60); do
  R=$(curl -s "$API/getUpdates?timeout=3&allowed_updates=%5B%22message%22%5D")
  CHAT=$(jq -r '[.result[]?.message | select(.chat.type=="private" and (.text//"")=="/start")] | last | .chat.id // empty' <<<"$R")
  NOMBRE=$(jq -r '[.result[]?.message | select(.chat.type=="private" and (.text//"")=="/start")] | last | (.from.first_name // "") + " @" + (.from.username // "")' <<<"$R")
  [ -n "$CHAT" ] && break
done
[ -n "$CHAT" ] || c_err "No llegó ningún /start. Vuelve a intentar."
read -rp "$(printf '\033[1;33m›\033[0m') ¿Eres tú «$NOMBRE» (chat $CHAT)? [s/N] " OK
[[ "$OK" =~ ^[sSyY]$ ]] || c_err "Cancelado."
# Vaciar la cola para que el webhook no reciba el /start viejo
ULT=$(jq -r '[.result[]?.update_id] | max // 0' <<<"$R"); curl -s "$API/getUpdates?offset=$((ULT + 1))&timeout=0" >/dev/null

SECRETO=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')
cd "$W"
c_info "Guardando secretos en el Worker (Cloudflare)…"
printf '%s' "$TOKEN"   | npx -y wrangler@4 secret put TG_TOKEN          >/dev/null 2>&1 || c_err "No se pudo guardar TG_TOKEN"
printf '%s' "$CHAT"    | npx -y wrangler@4 secret put TG_CHAT_ID        >/dev/null 2>&1 || c_err "No se pudo guardar TG_CHAT_ID"
printf '%s' "$SECRETO" | npx -y wrangler@4 secret put TG_WEBHOOK_SECRET >/dev/null 2>&1 || c_err "No se pudo guardar TG_WEBHOOK_SECRET"
npx -y wrangler@4 secret put RELAY_KEY < "$SEC/relay_hmac_key" >/dev/null 2>&1 || c_err "No se pudo guardar RELAY_KEY"
c_ok "Secretos guardados en Cloudflare (no quedan en este equipo)"

jq -n --arg u "$HOOK" --arg s "$SECRETO" '{url:$u, secret_token:$s, allowed_updates:["message"], drop_pending_updates:true, max_connections:5}' \
  | curl -s -X POST -H 'Content-Type: application/json' "$API/setWebhook" -d @- | jq -e '.ok' >/dev/null || c_err "Telegram no aceptó el webhook"
c_ok "Webhook conectado: $HOOK"

jq -n '{commands:[
  {command:"estado",description:"Salud del servidor y sensores"},
  {command:"resumen",description:"Actividad de las últimas 24 h"},
  {command:"ataques",description:"Ataques de hoy, explicados"},
  {command:"ultimos",description:"Últimos ataques graves"},
  {command:"top",description:"IPs, usuarios y contraseñas más usados"},
  {command:"ip",description:"Qué hizo una IP"},
  {command:"muestras",description:"Malware capturado"},
  {command:"silenciar",description:"Pausar alertas no críticas"},
  {command:"activar",description:"Reanudar alertas"},
  {command:"ayuda",description:"Ayuda"}]}' | curl -s -X POST -H 'Content-Type: application/json' "$API/setMyCommands" -d @- >/dev/null
curl -s -X POST "$API/setMyDescription" -d "description=Bot privado." >/dev/null
curl -s -X POST "$API/setMyShortDescription" -d "short_description=Bot privado." >/dev/null
unset TOKEN SECRETO

c_ok "Listo. En 1-2 minutos el vigía te escribirá «Vigía de Centinela conectado». Prueba /estado."
c_info "Para rotar: en @BotFather /revoke → vuelve a ejecutar este script."
