#!/usr/bin/env python3
"""Arma CREDENCIALES/credenciales.md a partir de hardening-ubuntu/secretos/ (no imprime nada)."""
import os, re, datetime
B = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
S = os.path.join(B, "hardening-ubuntu", "secretos")
def yml(f):
    d = {}
    for l in open(os.path.join(S, f), encoding="utf-8"):
        m = re.match(r'^(\w+):\s*"?(.*?)"?\s*$', l)
        if m: d[m.group(1)] = m.group(2)
    return d
g, st = yml("generados.yml"), yml("stack.yml")
DOM = next((l.split("=",1)[1].strip().strip('"') for l in open(os.path.join(B, "config.env")) if l.startswith("export DOMINIO=")), "example.com")
knock = " ".join(x.strip().strip("'\"") for x in g["knock_secuencia"].strip("[]").split(","))
existe = lambda f: "✅ guardado en `hardening-ubuntu/secretos/" + f + "`" if os.path.exists(os.path.join(S, f)) else "⏳ pendiente"
texto = f"""# 🔐 Credenciales de Centinela
Generado: {datetime.datetime.now():%Y-%m-%d %H:%M}. **Archivo privado (permisos 600). No lo subas a git, no lo compartas, no lo imprimas.**
Guarda estos datos en tu gestor de contraseñas (Bitwarden, 1Password…) y después puedes borrar este archivo:
se regenera cuando quieras con `python3 scripts/generar-credenciales.py`. Para cambiarlas: `ROTACION.md`.

## 1. Acceso al servidor (IP en hardening-ubuntu/inventory.ini)
| Dato | Valor |
|---|---|
| Usuario SSH | `honeypot` (llave `~/.ssh/id_ed25519` o tu contraseña) |
| Puerto SSH (cerrado a internet) | `{g['ssh_puerto']}` |
| Secuencia de port knocking (5 toques, en orden) | `{knock}` |
| Comando rápido | `./knocking/ssh-honeypot.sh` |
| Por Cloudflare (normal) | `cloudflared access ssh --hostname shell.{DOM}` (ver guía) |

## 2. Paneles web (todos detrás de Cloudflare Access + Auth0 + MFA)
| Servicio | URL | Usuario | Contraseña |
|---|---|---|---|
| Centro de mando | https://console.{DOM} | (solo Access) | — |
| Kibana (entra solo, lectura) | https://insights.{DOM} | (Access) | — |
| Kibana (administrar) | https://insights.{DOM}/login?auth_provider_hint=admin | `{st['es_admin_user']}` | `{st['es_admin_password']}` |
| Portainer | https://ops.{DOM} | `admin` | `{g['portainer_admin_password']}` |
| Web señuelo (pública) | https://{DOM} | — | — |

## 3. Cuentas de servicio de Elasticsearch (las usan los contenedores; normalmente no las necesitas)
| Usuario | Para qué | Contraseña |
|---|---|---|
| `elastic` | Superusuario (solo emergencias) | `{st['es_elastic_password']}` |
| `kibana_system` | Kibana → Elasticsearch | `{st['es_kibana_system_password']}` |
| `centinela_ingest` | Filebeat (solo escribe eventos) | `{st['es_ingest_password']}` |
| `centinela_panel` | Centro de mando (solo lee) | `{st['es_panel_password']}` |
| `centinela_cfmetrics` | Colector de Cloudflare | `{st['es_cfmetrics_password']}` |
| `centinela_vigia` | Vigía de alertas (solo lee) | `{st.get('es_vigia_password', '—')}` |

Grafana (`metrics.`) entra con tu sesión de Access (no tiene contraseña de uso diario). Admin interno de emergencia: `{st.get('grafana_admin_password', '—')}` · token Alertmanager→vigía: solo en el servidor.

## 4. Tokens y llaves
| Qué | Estado |
|---|---|
| Token API de Cloudflare (administración) | {existe('cloudflare_token')} |
| Token del túnel `centinela-edge` | {existe('cloudflared_tunnel_token')} |
| Token de Cloudflare de solo lectura (métricas) | {existe('cloudflare_readonly_token')} |
| Contraseña de sudo para Ansible | {existe('become_pass')} |
| Clave de firma servidor → bot (`relay_hmac_key`) | {existe('relay_hmac_key')} (también como secreto `RELAY_KEY` del Worker) |
| Token del bot de Telegram | No se guarda en este equipo: vive como secreto `TG_TOKEN` del Worker `centinela-hooks`. Rotar: @BotFather `/revoke` + `scripts/configurar-bot-telegram.sh` |
| CA interna (clave) | solo en el servidor: `/opt/stacks/siem/certs/ca.key` (root, 0400) |

## 5. Señuelos (honeytokens) — son FALSOS a propósito
Las claves que aparecen en la web señuelo (`/.env`, comentario del login, etc.) no sirven para nada real: están en
`hardening-ubuntu/roles/decoy/files/app/honeytokens.json`. Si un atacante usa cualquiera de ellas, el evento queda como
**Uso de credencial señuelo** (severidad crítica) y te llega al instante por Telegram.

## 6. Identidad (fuera de este equipo)
- **Auth0** (`tu-tenant.us.auth0.com`): entras con tu correo + código + app autenticadora. Código de recuperación del MFA: en tu gestor de contraseñas.
- **Cloudflare** (cuenta nueva de Centinela): tu correo + 2FA.
"""
d = os.path.join(B, "CREDENCIALES"); os.makedirs(d, exist_ok=True)
ruta = os.path.join(d, "credenciales.md")
with open(os.open(ruta, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w", encoding="utf-8") as f:
    f.write(texto)
os.chmod(ruta, 0o600)
print("✓ CREDENCIALES/credenciales.md actualizado (600)")
