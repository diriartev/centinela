# Operación

Todo se hace desde tu equipo, en la raíz del repositorio y con `source config.env` cargado.

## Accesos

```bash
./scripts/acceso.sh agregar persona@empresa.com     # Cloudflare Access + consola
./scripts/acceso.sh quitar  persona@empresa.com
./scripts/acceso.sh listar
```

La persona entra a `https://console.<tu-dominio>` con su correo (código por email) y la primera vez enrola su MFA.
Kibana y Portainer tienen cuentas propias de administración.

## Conectarse al servidor

| Situación | Cómo |
|---|---|
| Normal | `cloudflared access ssh --hostname shell.<tu-dominio>` (o configúralo en `~/.ssh/config` con `ProxyCommand`) |
| Cloudflare caído | `python3 knocking/knock.py && ssh -p <ssh_puerto> <usuario>@<ip>` (el puerto se abre 5 min solo para tu IP) |
| Ansible | Los playbooks hacen el knocking solos (`tocar.yml`) |

## Alertas

| Severidad | Ejemplos | Qué hacer |
|---|---|---|
| Crítica (suena aunque el bot esté en silencio) | Uso de un honeytoken, cambio hecho a mano en usuarios/SSH/PAM/sudoers, archivos del sistema modificados sin explicación | Revisar de inmediato: ¿fuiste tú? Si no, aislar (ver abajo). |
| Alta | Servicio caído, disco casi lleno, Elasticsearch en rojo | Revisar en Grafana. |
| Informativa (sin sonido) | Resumen diario, cambios explicados por apt/Ansible | Nada. |

Comandos del bot: `/estado`, `/resumen`, `/ataques`, `/ultimos`, `/top`, `/ip <dirección>`, `/muestras`, `/silenciar`, `/activar`, `/ayuda`. Para usarlo en un grupo del equipo: agrega el bot al grupo siendo administrador y escribe `/vincular`.

## Mantenimiento

| Tarea | Frecuencia | Comando |
|---|---|---|
| Backup de configuración y datos | Antes de cambios grandes | `./scripts/backup-servidor.sh` |
| Rotar credenciales | Cada 3–6 meses o si sospechas | `./scripts/rotar-credenciales.sh elastic-servicios\|elastic\|knock\|portainer\|tunel\|relay` |
| Honeytokens nuevos | Si los publicaste por error o cada año | `python3 scripts/regenerar-honeytokens.py && (cd hardening-ubuntu && ansible-playbook site.yml --tags decoy)` |
| Auditoría | Mensual | `./scripts/lynis.sh` y `./scripts/docker-bench.sh` |
| Muestras de malware | Cuando quieras analizarlas | `./scripts/descargar-muestras.sh` (ZIP cifrado, contraseña `infected`) |
| Extender tokens de Cloudflare | Al vencer | *My Profile → API Tokens → Edit → TTL* |

### Reinicios
Las actualizaciones de seguridad se instalan solas, pero el servidor **no se reinicia solo**. Cuando un kernel
nuevo lo requiere, la alerta `ReinicioPendiente` avisa a los 3 días. Hazlo en horario laboral:

```bash
./scripts/backup-servidor.sh
cd hardening-ubuntu && ansible honeypot -b -m reboot -a "reboot_timeout=600"
```

Todo vuelve solo en unos 4 minutos; verifica en Grafana que no queden alertas.

## Respuesta a incidentes

1. **No apagues el servidor** (perderías memoria y procesos para el análisis).
2. Revisa el detalle en el bot o en `/var/lib/centinela/integridad/` (reportes de AIDE y eventos de auditd).
3. Si un sensor está comprometido: `docker stop <sensor>`; queda aislado y los logs se conservan.
4. Si el host está comprometido: revoca el túnel en Cloudflare (corta todo el acceso) y escala al equipo de TI.
5. Acepta los cambios legítimos en la línea base: `sudo centinela-integridad aide --aceptar "motivo"`.

## Solución de problemas

| Síntoma | Causa probable | Solución |
|---|---|---|
| Ansible no conecta | El knocking no llegó o cambió tu IP | `python3 knocking/knock.py` y reintenta en 1 s |
| Una consola da 502 | El contenedor reinicia | Grafana → panel de contenedores; `docker logs <nombre>` |
| `ReglasDeAuditoriaBorradas` tras reiniciar | Una regla apunta a un archivo que aún no existía | Ya contemplado (`auditctl -i`); si persiste, `sudo augenrules --load` |
| Alerta de cambio manual que sí hiciste tú | Esperado | Acepta el cambio con `centinela-integridad aide --aceptar` |
| El playbook falla en `Pre-flight` por rango de red | `docker_pool` choca con una red existente | Cambia `docker_pool` y todos los `10.213.*` de `main.yml` |
