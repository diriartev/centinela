# 📘 Guía de instalación paso a paso

De un **Ubuntu Server recién instalado** a **recibir el primer ataque en Telegram**.
Cada paso tiene la misma estructura:

> 🎯 **Objetivo** — qué vas a lograr · 🧠 **Qué pasa por dentro** — por qué se hace así ·
> ⌨️ **Comandos** · ✅ **Comprobación** — cómo saber que funcionó · 🆘 **Si falla**

⏱️ Tiempo total: **1,5 a 2 horas** (la mayor parte es Cloudflare y la primera descarga de imágenes).
Los comandos se ejecutan **en tu equipo** (desde la raíz del repositorio) salvo que diga «en el servidor».

## Índice

0. [Requisitos](#paso-0--requisitos)
1. [Preparar el servidor](#paso-1--preparar-el-servidor)
2. [Clonar y configurar](#paso-2--clonar-y-configurar)
3. [Generar los secretos](#paso-3--generar-los-secretos)
4. [Cloudflare: dominio, identidad y Access](#paso-4--cloudflare-dominio-identidad-y-access)
5. [Cloudflare: túnel y tokens](#paso-5--cloudflare-túnel-y-tokens)
6. [Primer despliegue](#paso-6--primer-despliegue)
7. [Cerrar el SSH público](#paso-7--cerrar-el-ssh-público)
8. [Rutas del túnel y DNS](#paso-8--rutas-del-túnel-y-dns)
9. [Bot de Telegram](#paso-9--bot-de-telegram)
10. [Verificación final](#paso-10--verificación-final)

---

## Paso 0 · Requisitos

| Dónde | Qué | Por qué |
|---|---|---|
| Servidor | Ubuntu Server **22.04 LTS** | Es la versión probada; el playbook verifica la versión antes de tocar nada. |
| Servidor | 4+ núcleos, **16 GB de RAM**, 120+ GB de disco | Elasticsearch reserva 6 GB; el resto lo usan los sensores y el monitoreo. |
| Servidor | Disco con **LVM** y espacio libre en el grupo de volúmenes | El rol `docker` crea un volumen propio para `/var/lib/docker` (cuotas y aislamiento del disco del sistema). |
| Servidor | Salida a internet por HTTPS (443) | El túnel es **saliente**: no hace falta abrir nada de entrada. |
| Tu equipo | Linux, macOS o WSL con `ansible-core` ≥ 2.15, Python 3, `jq`, `curl`, Node.js 20+ | Ansible despliega todo; Node se usa solo para el Worker de Telegram. |
| Cuentas | Dominio en **Cloudflare** (plan gratis) | Túnel, Access, WAF y DNS. |
| Cuentas | **Auth0** (gratis) y **Telegram** | MFA para el acceso y alertas en el celular. Opcionales, muy recomendados. |

> 💡 **Elige bien el dominio y la marca del señuelo.** No uses palabras como «honeypot» o «trap», ni tu nombre,
> ni el de tu institución. El objetivo es que parezca una empresa pequeña cualquiera.

```bash
# Fedora:  sudo dnf install ansible-core jq nodejs
# Ubuntu:  sudo apt install ansible-core jq nodejs npm
# macOS:   brew install ansible jq node
ansible --version && jq --version && node --version
```

---

## Paso 1 · Preparar el servidor

🎯 **Objetivo:** que Ansible pueda entrar al servidor con tu llave SSH y usar `sudo`.

🧠 **Qué pasa por dentro:** Ansible no instala agentes; se conecta por SSH y ejecuta módulos de Python.
Solo necesita un usuario con `sudo` y tu llave pública. A partir de aquí **no vuelves a configurar nada a mano**
en el servidor: todo cambio pasa por el playbook, así el servidor siempre se puede reconstruir.

⌨️ **Comandos:**
```bash
ssh-keygen -t ed25519                       # solo si aún no tienes llave
ssh-copy-id -i ~/.ssh/id_ed25519.pub <usuario>@<ip-del-servidor>
ssh <usuario>@<ip-del-servidor> 'sudo -v && lsb_release -ds && sudo vgs'
```

✅ **Comprobación:** entras sin contraseña, `sudo -v` no falla, ves `Ubuntu 22.04.x LTS` y `vgs` muestra
espacio libre (`VFree`) suficiente para `docker_lv_tam` (140 GB por defecto; ajústalo en el paso 2).

🆘 **Si falla:** si `vgs` no muestra nada, el disco no usa LVM; reinstala Ubuntu con la opción *LVM* o
desactiva la creación de volúmenes en el rol `docker`.

---

## Paso 2 · Clonar y configurar

🎯 **Objetivo:** adaptar el proyecto a tu servidor, tu dominio y tu red.

🧠 **Qué pasa por dentro:** toda la configuración **no secreta** vive en `group_vars/all/main.yml`
(comentada línea por línea). Lo que identifica tu despliegue (dominio, IDs de Cloudflare, correo) va en
`config.env`, que **git ignora**: así puedes contribuir al repositorio sin filtrar tu instalación.

⌨️ **Comandos:**
```bash
git clone https://github.com/diriartev/centinela.git && cd centinela
cp config.example.env config.env
nano config.env                                   # completa lo que puedas; los IDs salen en los pasos 4 y 5
nano hardening-ubuntu/inventory.ini               # ansible_host = IP, ansible_user = tu usuario
nano hardening-ubuntu/group_vars/all/main.yml
ansible-galaxy collection install community.docker community.general ansible.posix
```

Variables de `main.yml` que conviene revisar:

| Variable | Para qué | Valor recomendado |
|---|---|---|
| `decoy_marca` | Nombre de la empresa ficticia del señuelo | Algo creíble y genérico |
| `docker_lv_vg` · `docker_lv_tam` · `home_lv_tam` | Grupo de volúmenes y tamaños | Según tu disco |
| `docker_pool` | Rango de las redes de Docker | Uno que **no exista** en tu red (el playbook lo verifica) |
| `redes_admin` | Redes con SSH directo (p. ej. la VPN de TI) | `[]` = solo túnel y knocking |
| `correos_permitidos` | Quién ve la consola | Tu correo (luego se gestiona con `scripts/acceso.sh`) |
| `reiniciar_si_hace_falta` | Reinicio automático tras actualizar el kernel | `false` en un datacenter |

✅ **Comprobación:** `cd hardening-ubuntu && ansible honeypot -m ping` responde `pong`.

🆘 **Si falla:** `UNREACHABLE` = IP, usuario o llave incorrectos en `inventory.ini`.

---

## Paso 3 · Generar los secretos

🎯 **Objetivo:** crear todas las contraseñas y claves de **tu** instalación, sin que nadie (ni tú) tenga que
inventarlas ni verlas.

🧠 **Qué pasa por dentro:** `inicializar-secretos.py` genera con `secrets` (criptográficamente seguro):
contraseñas de 24–32 caracteres para cada servicio, un **puerto SSH alto aleatorio**, una **secuencia de port
knocking** de 5 puertos TCP/UDP mezclados y la clave HMAC que firma las alertas. Todo queda en
`hardening-ubuntu/secretos/` con permisos `600`, fuera de git. `regenerar-honeytokens.py` crea credenciales
**falsas pero únicas** (llaves de AWS, tokens, contraseñas) que el señuelo deja «filtradas» como cebo: como
nadie legítimo las conoce, **cualquier uso = atacante confirmado**.

⌨️ **Comandos:**
```bash
python3 scripts/inicializar-secretos.py        # solo te pide la contraseña de sudo del servidor
python3 scripts/regenerar-honeytokens.py
python3 scripts/generar-credenciales.py        # opcional: CREDENCIALES/credenciales.md para tu gestor de contraseñas
```

✅ **Comprobación:** `ls -l hardening-ubuntu/secretos/` muestra archivos `-rw-------` y
`git status` **no** los lista (están ignorados).

🆘 **Si falla:** si el script dice «ya existe, no se toca», es a propósito: nunca sobrescribe secretos.
Para cambiarlos usa `scripts/rotar-credenciales.sh`.

> 🔐 Guarda el contenido de `CREDENCIALES/credenciales.md` en un gestor de contraseñas y **borra el archivo**.

---

## Paso 4 · Cloudflare: dominio, identidad y Access

🎯 **Objetivo:** que las consolas de administración solo se abran para ti, con MFA, y nunca queden expuestas.

🧠 **Qué pasa por dentro:** **Cloudflare Access** se pone delante de `console.`, `insights.`, `ops.`,
`metrics.` y `shell.`. Antes de que una petición llegue al servidor, Cloudflare exige iniciar sesión con tu
proveedor de identidad. Luego, `cloudflared` vuelve a verificar en el servidor el **JWT firmado** de Access
(*audTag*): aunque alguien descubriera cómo llegar al origen, sin ese token no entra.

⌨️ **Pasos en el panel de Cloudflare:**

1. **Agrega tu dominio** a Cloudflare y cambia los *nameservers* en tu registrador.
   Anota el **Zone ID** y el **Account ID** (Overview → barra lateral) → `CF_ZONE_ID`, `CF_ACCOUNT_ID`.
2. **Zero Trust** → crea tu equipo (`<equipo>.cloudflareaccess.com`) → `CF_TEAM`.
3. **Proveedor de identidad** (*Settings → Authentication → Login methods*):
   - **Recomendado — Auth0:** crea una app *Regular Web Application*, activa *Passwordless → Email*
     y *Multi-factor → One-time Password* con política **Always**; agrégala en Cloudflare como **OpenID Connect**.
     Resultado: correo + código + app autenticadora en cada acceso.
   - **Mínimo — One-time PIN** de Cloudflare (código por correo, sin segundo factor).
4. **Access → Applications → Add → Self-hosted**: nombre `Centinela` (= `CF_APP_NAME`) con los dominios
   `console.`, `insights.`, `ops.`, `metrics.` y `shell.` de tu dominio.
5. **Política Allow**: *Include → Emails* = tu correo; *Require → Login method* = tu proveedor
   (con Auth0 añade *Require → Authentication method → mfa*).
6. Copia el **ID de la política** (aparece en la URL al editarla) → `CF_POLICY_ID`.

✅ **Comprobación:** abre `https://console.<tu-dominio>` en una ventana privada: debe aparecer la pantalla
de login de Access (todavía no hay nada detrás, es normal).

🆘 **Si falla:** si la página carga sin pedir login, la aplicación no cubre ese subdominio.

---

## Paso 5 · Cloudflare: túnel y tokens

🎯 **Objetivo:** crear el túnel saliente y los dos tokens de API que usan los scripts.

🧠 **Qué pasa por dentro:** el contenedor `cloudflared` abre conexiones **salientes** hacia Cloudflare y por
ellas recibe las peticiones. Por eso el servidor no necesita ningún puerto abierto: el firewall descarta todo
lo que llega. Los tokens se crean con **mínimo privilegio** y **fecha de vencimiento**: si alguno se filtra,
solo sirve para lo justo y caduca solo.

⌨️ **Túnel** (*Zero Trust → Networks → Tunnels → Create → Cloudflared*, nombre `centinela-edge`):
```bash
read -rs T; printf '%s' "$T" > hardening-ubuntu/secretos/cloudflared_tunnel_token; unset T   # pega el token
echo "cloudflared_tunnel_id: <ID-del-túnel>" > hardening-ubuntu/secretos/cloudflared.yml
chmod 600 hardening-ubuntu/secretos/*
```
> `read -rs` lee sin mostrar en pantalla ni dejar rastro en el historial de la terminal.

⌨️ **Tokens** (*My Profile → API Tokens → Create Custom Token*, con **TTL**):

| Archivo en `secretos/` | Permisos | Lo usa |
|---|---|---|
| `cloudflare_token` | Account: *Cloudflare Tunnel: Edit*, *Access: Apps and Policies: Edit*, *Workers Scripts: Edit* · Zone: *DNS: Edit*, *Workers Routes: Edit* | Scripts de administración |
| `cloudflare_readonly_token` | Account y Zone: *Analytics: Read* | Colector de métricas de Cloudflare |

Guárdalos igual que el token del túnel (`read -rs … > archivo`).

✅ **Comprobación:**
```bash
curl -s -H "Authorization: Bearer $(cat hardening-ubuntu/secretos/cloudflare_token)" \
  https://api.cloudflare.com/client/v4/user/tokens/verify | jq '.result | {status, expires_on}'
```
Debe decir `"status": "active"` y una fecha de vencimiento.

🆘 **Si falla:** `Invalid API Token` = se copió con espacios o saltos de línea; vuelve a guardarlo con `read -rs`.

---

## Paso 6 · Primer despliegue

🎯 **Objetivo:** aplicar el hardening y levantar los 25 contenedores.

🧠 **Qué pasa por dentro:** `site.yml` primero hace verificaciones (*pre-flight*): versión de Ubuntu, interfaz
de salida, que el rango de Docker no choque con tus redes y tu IP de administración. Después aplica los roles
en orden: **host** (base, kernel, autenticación, SSH, firewall, auditoría) → **contenedores** (Docker con
`userns-remap`, Portainer, túnel) → **engaño** (señuelo y sensores) → **datos y alertas** (SIEM, panel,
métricas, monitoreo, vigía). Al final acepta sus propios cambios en la línea base de AIDE, para que el control
de integridad solo avise de lo que **no** hizo Ansible.

La primera vez el SSH aún está en el puerto 22, así que se le indica al playbook que se conecte por ahí y que
deje el 22 abierto mientras migra al puerto nuevo:

⌨️ **Comandos:**
```bash
source config.env && cd hardening-ubuntu
ansible-playbook site.yml --check --diff -e ssh_puerto_conexion=22      # opcional: simulacro sin cambios
ansible-playbook site.yml -e ssh_puerto_conexion=22 -e ssh_transicion=true -e cerrar_ssh_publico=false
```
⏱️ La primera ejecución tarda 20–40 min (descarga de imágenes y creación de índices).

✅ **Comprobación:** el resumen final (`PLAY RECAP`) muestra `failed=0`, y:
```bash
ansible honeypot -b -m shell -a 'docker ps --format "{{"{{"}}.Names{{"}}"}}: {{"{{"}}.Status{{"}}"}}"'
```
lista los contenedores como `Up` (los que tienen chequeo de salud, `healthy`).

🆘 **Si falla:**
| Mensaje | Causa | Solución |
|---|---|---|
| `Pre-flight ... choca con` | `docker_pool` ya existe en tu red | Cambia `docker_pool` y los `10.213.*` de `main.yml` |
| `Falta ... honeytokens.json` | No corriste el paso 3 | `python3 scripts/regenerar-honeytokens.py` |
| `Insufficient free space` | El VG no tiene espacio | Baja `docker_lv_tam` |
| Se corta a mitad | Red inestable | Vuelve a ejecutar: el playbook es **idempotente** |

---

## Paso 7 · Cerrar el SSH público

🎯 **Objetivo:** que el puerto 22 deje de existir para internet.

🧠 **Qué pasa por dentro:** quedan dos caminos de entrada y **los dos hay que probarlos antes de cerrar**:
1. **Normal:** Cloudflare Access → túnel → `sshd` en localhost (con MFA).
2. **Emergencia** (si Cloudflare cae): **port knocking**. `knockd` escucha con libpcap aunque el firewall
   descarte los paquetes; si recibe los 5 toques en orden en menos de 15 s, abre el puerto SSH **solo para tu
   IP y durante 5 minutos**. Para un escáner, el servidor no tiene nada abierto.

⌨️ **Comandos:**
```bash
python3 ../knocking/knock.py && ssh -p <ssh_puerto> <usuario>@<ip>     # el puerto está en secretos/generados.yml
# (en otra terminal, después del paso 8)  cloudflared access ssh --hostname shell.<tu-dominio>
ansible-playbook site.yml                                               # ahora sí: cierra el 22
```

✅ **Comprobación:** desde otra red (p. ej. los datos del celular), `nmap -Pn -p 22,<ssh_puerto> <ip>` muestra
ambos como `filtered`.

🆘 **Si te quedas fuera:** espera 1 minuto y repite el knocking (cada toque debe llegar en orden). Si tu IP
cambió, el puerto se abre para la nueva tras el knocking. Como último recurso, consola física del servidor.

---

## Paso 8 · Rutas del túnel y DNS

🎯 **Objetivo:** publicar el señuelo y las consolas a través del túnel.

🧠 **Qué pasa por dentro:** `cloudflare-tunel.sh` crea los registros DNS (CNAME hacia el túnel) y la tabla de
rutas: el dominio, `www`, `blog`, `api`, `vpn` y `sso` van al **gateway del señuelo** (públicos, para atraer
atacantes); las consolas van a su servicio interno **exigiendo el JWT de Access**. Cualquier otro nombre
devuelve 404.

⌨️ **Comandos:**
```bash
cd .. && ./scripts/cloudflare-tunel.sh
```

✅ **Comprobación:**
```bash
curl -sI https://<tu-dominio> | head -1                    # HTTP/2 200 → el señuelo
curl -sI https://console.<tu-dominio> | head -1            # 302 → redirige al login de Access
curl -s  https://<tu-dominio>/.env | head -3               # el .env falso con tus honeytokens
```

**Protección extra recomendada en Cloudflare:**
- *Security → WAF → Rate limiting*: 200 peticiones / 10 s por IP (excluye `hooks.`).
- *SSL/TLS*: modo **Full**, *Always Use HTTPS* y HSTS.
- 2FA en tu cuenta de Cloudflare.

---

## Paso 9 · Bot de Telegram

🎯 **Objetivo:** recibir en el celular las alertas y poder consultar el estado.

🧠 **Qué pasa por dentro:** el servidor nunca habla directo con Telegram. El **vigía** firma cada alerta con
HMAC y la envía a un **Cloudflare Worker**; el Worker verifica la firma, aplica anti-repetición y silencios, y
la entrega a Telegram. El **token del bot nunca se guarda en disco**: vive solo como secreto del Worker. Si el
servidor deja de reportar, el Worker avisa solo (vigilancia de «hombre muerto» cada 10 min).

⌨️ **Comandos:**
1. En Telegram, habla con **@BotFather** → `/newbot` (un nombre que no diga «honeypot») y copia el token.
2. Publica el Worker y conéctalo:
```bash
cd cloudflare/worker-hooks && nano wrangler.toml          # cambia example.com por tu dominio (2 sitios)
source ../../config.env && CLOUDFLARE_ACCOUNT_ID=$CF_ACCOUNT_ID \
  CLOUDFLARE_API_TOKEN=$(cat ../../hardening-ubuntu/secretos/cloudflare_token) npx -y wrangler@4 deploy
cd ../.. && ./scripts/configurar-bot-telegram.sh          # pide el token sin mostrarlo y te pide /start
```
3. ¿Lo quieres en un grupo del equipo? Agrega el bot al grupo, hazte administrador y escribe `/vincular`.

✅ **Comprobación:** en 1–2 minutos el bot escribe «Vigía conectado». Prueba `/estado` y `/resumen`.

---

## Paso 10 · Verificación final

| # | Prueba | Resultado esperado |
|---|---|---|
| 1 | `nmap -Pn <ip>` desde fuera | **Todos** los puertos `filtered` |
| 2 | `https://<tu-dominio>` | Web de la empresa ficticia |
| 3 | `https://console.<tu-dominio>` | Login de Access → correo → MFA → consola |
| 4 | `curl -H "Authorization: Bearer <api-token de tus honeytokens>" https://<tu-dominio>/api/v1/x` | 🚨 Alerta crítica de honeytoken en Telegram |
| 5 | `ansible-playbook lynis.yml` | Índice ≈ **90** |
| 6 | `./scripts/docker-bench.sh` | Sin hallazgos críticos |
| 7 | `sudo touch /etc/ssh/sshd_config` en el servidor (prueba) | 🚨 Alerta de cambio manual (luego acéptalo: `sudo centinela-integridad aide --aceptar "prueba"`) |
| 8 | Reiniciar el servidor | Todo vuelve solo en ~4 min y Grafana queda sin alertas |

🎉 **Listo.** En las próximas horas empezarán a llegar los primeros escaneos automáticos de internet. Para el día
a día (dar acceso a otras personas, rotar credenciales, backups, reinicios, responder a un incidente) sigue
**[operacion.md](operacion.md)**.
