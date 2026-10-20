# Seguridad

## Modelo de amenazas

| Amenaza | Mitigación |
|---|---|
| El atacante compromete un sensor (son software vulnerable a propósito) | Contenedor sin root, `cap_drop: ALL`, solo lectura, `no-new-privileges`, `userns-remap` (root del contenedor = UID sin privilegios en el host), red interna sin salida y límites de memoria/CPU/PIDs. |
| Usar el honeypot como trampolín hacia la red de la institución | Egress denegado por defecto en `DOCKER-USER`: bloqueo explícito de RFC 1918, CGNAT, link-local y el rango público propio. Las redes de sensores son `internal`. |
| Escaneo / explotación directa del servidor | Cero puertos de entrada. SSH en puerto aleatorio, cerrado en UFW, que solo se abre 5 min para la IP que hace el knocking correcto. |
| Robo de credenciales del administrador | Cloudflare Access + IdP + **MFA** obligatoria + validación del JWT en el origen. Consolas nunca publicadas directamente. |
| Persistencia en el host | auditd (60+ reglas: identidad, sudoers, SSH, PAM, cron, systemd, módulos, binarios…) + AIDE cada hora, con alerta crítica para cambios hechos a mano. |
| Exfiltración de secretos del repositorio | Ningún secreto en git; honeytokens y credenciales se generan por instalación; el token del bot vive solo en el Worker. |
| Abuso del sitio (DoS, fuerza bruta) | WAF y rate limiting de Cloudflare; límites de recursos por contenedor. |
| Descarga de malware al servidor | Las muestras se descargan desde la red de Cloudflare (Worker), nunca desde el servidor, y se guardan en ZIP cifrado. |

## Endurecimiento de contenedores

Estado verificado con `docker inspect` en un despliegue real:

| Control | Resultado |
|---|---|
| Contenedores privilegiados | **0** |
| Puertos publicados en el host | **0** (todo entra por el túnel) |
| `cap_drop: ALL` | **Todos** (algunos sensores recuperan solo `NET_BIND_SERVICE`) |
| `no-new-privileges` | **Todos** (también por defecto en `daemon.json`) |
| Sistema de archivos de solo lectura | Todos salvo Elasticsearch (lo necesita para su `tmp`) |
| Límites de memoria y PIDs | **Todos** |
| `userns-remap` | Todos salvo dos excepciones documentadas (abajo) |
| Daemon | `icc: false`, `userland-proxy: false`, `live-restore`, logs rotados, rango de red propio |

**Excepciones (documentadas y acotadas):**
- **Portainer** monta `docker.sock` y usa el *user namespace* del host (no funciona de otra forma). Por eso solo
  es accesible por Access + MFA y además tiene su propio login. Si no lo necesitas, no lo despliegues
  (quita el rol `portainer` de `site.yml`).
- **node-exporter** usa la red y los PID del host (lo exige para medirlo), pero corre como `nobody`, sin
  capacidades, de solo lectura y con `/` montado solo lectura.
- **Dionaea** (sensor de red, no expuesto por defecto) necesita algunas capacidades para soltar privilegios.

## Hardening del host (resumen)

- **Kernel:** sysctl endurecido (ASLR, `kptr_restrict`, `dmesg_restrict`, `yama.ptrace_scope`, rp_filter, sin redirects), módulos y sistemas de archivos raros bloqueados.
- **SSH:** solo llave (contraseña opcional por usuario), `AllowGroups`, sin root, algoritmos modernos, `MaxAuthTries` bajo.
- **Autenticación:** política de contraseñas (pwquality), bloqueo por intentos (faillock), `umask 027`.
- **Registro:** auditd (las reglas se recargan al arrancar y una alerta avisa si alguien las borra), journald persistente.
- **Integridad:** AIDE enfocado (~12 000 archivos en ~12 s) con línea base que avanza y correlación con dpkg/Ansible/Docker.
- **Otros:** AppArmor, USBGuard, `/dev/shm` con `noexec,nosuid,nodev`, TMOUT de 15 min en las shells, `unattended-upgrades` solo de seguridad y **sin reinicio automático**.
- **Puntuación:** Lynis **56 → 90**, docker-bench sin hallazgos críticos.

## Pruebas realizadas

Se hizo un pentest completo del despliegue (externo, a través de Cloudflare, y desde un contenedor
comprometido simulado): 13 hallazgos, 11 corregidos y 2 que no aplican o son decisiones de diseño.
Ejemplos de lo que se probó: escaneo de puertos, bypass de Access, acceso directo al origen,
movimiento lateral entre redes Docker, salida a la red interna, escape de contenedor con capacidades
y montajes, y fuerza bruta contra el portal.

## Riesgos residuales

Ningún sistema es invulnerable. Lo que queda fuera del alcance o depende de ti:
- **Vulnerabilidades de día cero** en el kernel o en el runtime de contenedores (mitigadas por `userns-remap`,
  AppArmor, el perfil seccomp por defecto de Docker y actualizaciones automáticas, pero no eliminadas).
- **Cloudflare** es un tercero de confianza: si tu cuenta cae, cae el acceso. Usa 2FA y tokens con vencimiento.
- **La huella de AIDE** vive en el mismo servidor; un atacante con root podría alterarla. Mejora sugerida:
  copiarla fuera periódicamente.
- **Kernel nuevo = reinicio manual.** Las actualizaciones se instalan solas pero el servidor no se reinicia
  solo; la alerta `ReinicioPendiente` avisa a los 3 días.
