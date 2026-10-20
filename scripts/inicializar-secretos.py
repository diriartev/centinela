#!/usr/bin/env python3
"""Crea los secretos de una instalación nueva en hardening-ubuntu/secretos/ (carpeta en .gitignore).

  python3 scripts/inicializar-secretos.py

Genera contraseñas largas y aleatorias, un puerto SSH alto al azar y una secuencia de port knocking
de 5 puertos (TCP/UDP mezclados). No imprime ningún valor. Si un archivo ya existe NO lo toca
(para cambiar credenciales existentes usa scripts/rotar-credenciales.sh).
Lo único que te pide es la contraseña de sudo de tu usuario en el servidor (no se muestra al escribir).
"""
import getpass, os, secrets, string

B = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
S = os.path.join(B, "hardening-ubuntu", "secretos")
G = os.path.join(B, "hardening-ubuntu", "group_vars", "all")
r = secrets.SystemRandom()
alnum = string.ascii_letters + string.digits
clave = lambda n=32: "".join(secrets.choice(alnum) for _ in range(n))


def escribir(nombre, contenido):
    ruta = os.path.join(S, nombre)
    if os.path.exists(ruta):
        print("· ya existe, no se toca:", os.path.relpath(ruta, B)); return
    fd = os.open(ruta, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(contenido)
    print("✓ creado:", os.path.relpath(ruta, B))


os.makedirs(S, mode=0o700, exist_ok=True)
ssh = r.randrange(20000, 32000)
reservados = set(range(0, 1024)) | set(range(32768, 61000)) | {ssh, 1080, 1433, 2222, 2323, 2375, 2376, 3306, 3389, 5000,
             5432, 5555, 5601, 5900, 6379, 8000, 8080, 8443, 9000, 9200, 9300, 9443, 11211, 27017}
knock = [f"{p}:{r.choice(['tcp', 'udp'])}" for p in r.sample([x for x in range(1024, 65536) if x not in reservados], 5)]
escribir("generados.yml", "# Generado por scripts/inicializar-secretos.py. PRIVADO.\n"
         f"ssh_puerto: {ssh}\nknock_secuencia: {knock}\nportainer_admin_password: \"{clave(28)}\"\n")
stack = {k: clave(32) for k in ("es_elastic_password", "es_kibana_system_password", "es_ingest_password", "es_panel_password",
                                 "es_cfmetrics_password", "es_vigia_password", "kibana_visor_password", "kibana_enc_key",
                                 "kibana_sec_key", "kibana_rep_key", "panel_session_key", "alertas_token", "grafana_admin_password")}
stack["es_admin_user"] = "admin-" + secrets.token_hex(3)
stack["es_admin_password"] = clave(24)
escribir("stack.yml", "# Generado por scripts/inicializar-secretos.py. PRIVADO.\n" + "".join(f'{k}: "{v}"\n' for k, v in stack.items()))
escribir("relay_hmac_key", secrets.token_hex(32))
if not os.path.exists(os.path.join(S, "become_pass")):
    escribir("become_pass", getpass.getpass("Contraseña de sudo de tu usuario en el servidor: "))
for enlace, destino in (("secretos.yml", "../../secretos/generados.yml"), ("stack.yml", "../../secretos/stack.yml")):
    p = os.path.join(G, enlace)
    if not os.path.lexists(p):
        os.symlink(destino, p); print("✓ enlace:", os.path.relpath(p, B))
print("\nFaltan (los crea Cloudflare, ver docs/instalacion.md): secretos/cloudflare_token, "
      "secretos/cloudflare_readonly_token, secretos/cloudflared_tunnel_token y secretos/cloudflared.yml")
