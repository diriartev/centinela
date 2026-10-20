#!/usr/bin/env bash
# Configura las rutas del túnel centinela-edge y sus DNS (idempotente).
# Rutas protegidas: cloudflared exige además el token de Access (audTag).
# Rutas públicas (cebo): apex, www y los sensores web blog/api/vpn/sso → gateway del señuelo.
set -euo pipefail
source "$(dirname "$0")/../config.env"   # tu dominio, IDs de Cloudflare y correo admin (ver config.example.env)
cd "$(dirname "$0")/../hardening-ubuntu"
T=$(cat secretos/cloudflare_token); A="Authorization: Bearer $T"; J='Content-Type: application/json'
API=https://api.cloudflare.com/client/v4; AC=${CF_ACCOUNT_ID}; Z=${CF_ZONE_ID}; D=$DOMINIO
TID=$(awk '/cloudflared_tunnel_id/{print $2}' secretos/cloudflared.yml); P=$(awk '/^ssh_puerto:/{print $2}' secretos/generados.yml)
AUD=$(curl -s -H "$A" $API/accounts/$AC/access/apps | jq -r '.result[]|select(.name==$ENV.CF_APP_NAME)|.aud')
jq -n --arg d "$D" --arg p "$P" --arg aud "$AUD" '
  {"required":true,"teamName":$ENV.CF_TEAM,"audTag":[$aud]} as $acc |
  {config:{"warp-routing":{enabled:false},ingress:[
    {hostname:("ops."+$d),      service:"https://10.213.251.10:9443", originRequest:{noTLSVerify:true,connectTimeout:10,access:$acc}},
    {hostname:("insights."+$d), service:"https://10.213.251.11:5601", originRequest:{noTLSVerify:true,connectTimeout:10,access:$acc}},
    {hostname:("console."+$d),  service:"http://10.213.251.12:8080",  originRequest:{connectTimeout:10,access:$acc}},
    {hostname:("shell."+$d),    service:("ssh://10.213.250.1:"+$p),   originRequest:{access:$acc}},
    {hostname:("metrics."+$d),  service:"http://10.213.248.13:3000",  originRequest:{connectTimeout:10,access:$acc}},
    {hostname:$d,               service:"http://10.213.254.10:8080",  originRequest:{connectTimeout:10,httpHostHeader:$d}},
    {hostname:("www."+$d),      service:"http://10.213.254.10:8080",  originRequest:{connectTimeout:10}},
    {hostname:("blog."+$d),     service:"http://10.213.254.10:8080",  originRequest:{connectTimeout:10}},
    {hostname:("api."+$d),      service:"http://10.213.254.10:8080",  originRequest:{connectTimeout:10}},
    {hostname:("vpn."+$d),      service:"http://10.213.254.10:8080",  originRequest:{connectTimeout:10}},
    {hostname:("sso."+$d),      service:"http://10.213.254.10:8080",  originRequest:{connectTimeout:10}},
    {service:"http_status:404"}]}}' \
 | curl -s -X PUT -H "$A" -H "$J" "$API/accounts/$AC/cfd_tunnel/$TID/configurations" -d @- | jq -c '{rutas_ok:.success,version:.result.version,err:.errors}'
for h in ops insights console shell metrics @ www blog api vpn sso; do
  name=$([ "$h" = "@" ] && echo "$D" || echo "$h.$D")
  ID=$(curl -s -H "$A" "$API/zones/$Z/dns_records?name=$name&type=CNAME" | jq -r '.result[0].id // empty')
  B=$(jq -n --arg n "$name" --arg c "$TID.cfargotunnel.com" '{type:"CNAME",name:$n,content:$c,proxied:true,comment:"Túnel centinela-edge"}')
  if [ -n "$ID" ]; then M=PUT; U="$API/zones/$Z/dns_records/$ID"; else M=POST; U="$API/zones/$Z/dns_records"; fi
  curl -s -X $M -H "$A" -H "$J" "$U" -d "$B" | jq -c --arg n "$name" '{dns:$n,ok:.success,err:.errors[0].message}'
done
