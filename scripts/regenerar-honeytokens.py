#!/usr/bin/env python3
"""Genera los honeytokens (credenciales FALSAS y únicas) de esta instalación.

La web señuelo los muestra en lugares tentadores (.env expuesto, comentario olvidado en el login) y el
gateway revisa cada petición: si alguien USA uno de ellos, es un atacante que ya leyó el cebo → alerta crítica.
Se guardan en roles/decoy/files/app/honeytokens.json, que está en .gitignore: NUNCA los publiques,
porque un honeytoken conocido deja de ser secreto (y delataría tu señuelo).

Uso: python3 scripts/regenerar-honeytokens.py && cd hardening-ubuntu && ansible-playbook site.yml --tags decoy
"""
import base64, json, os, secrets, string

DESTINO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "hardening-ubuntu",
                       "roles", "decoy", "files", "app", "honeytokens.json")
B32 = string.ascii_uppercase + "234567"
alnum = string.ascii_letters + string.digits
tokens = {
    "aws-access-key": "AKIA" + "".join(secrets.choice(B32) for _ in range(16)),
    "aws-secret-key": "".join(secrets.choice(alnum + "+/") for _ in range(40)),
    "app-key": base64.b64encode(secrets.token_bytes(32)).decode(),
    "api-token": "live_" + secrets.token_hex(20),
    "db-password": "".join(secrets.choice(alnum) for _ in range(8)) + "!" + secrets.token_urlsafe(6),
    "mail-password": "".join(secrets.choice(alnum) for _ in range(10)) + "#",
    "redis-password": secrets.token_urlsafe(18),
    "qa-portal-password": "Pruebas-" + str(secrets.randbelow(9000) + 1000) + "!",
    "blog-editor-password": secrets.token_urlsafe(9) + "!",
    "jwt-secret": secrets.token_hex(32),
}
old = os.umask(0o022)   # legible al construir la imagen (el repo lo ignora en .gitignore)
with open(DESTINO, "w") as f:
    json.dump(tokens, f, indent=1)
os.umask(old)
print("✓ Honeytokens nuevos en", os.path.relpath(DESTINO))
print("  Aplica: cd hardening-ubuntu && ansible-playbook site.yml --tags decoy")
