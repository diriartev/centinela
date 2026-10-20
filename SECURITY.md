# Política de seguridad

## Reportar una vulnerabilidad

Si encuentras una vulnerabilidad en el código o en la configuración de este repositorio, **no abras un issue
público**. Usa *Security → Report a vulnerability* (GitHub Private Vulnerability Reporting) con:

- Qué componente afecta (rol de Ansible, script, Worker…).
- Pasos para reproducirlo y su impacto.

Respondo en un plazo de 7 días.

## Alcance

- ✅ Código y configuración de este repositorio.
- ❌ Instalaciones de terceros que usen este proyecto: repórtalo a quien la administra.
- ❌ Atacar instalaciones en funcionamiento sin autorización.

## Buenas prácticas para quien lo use

- Nunca subas `config.env`, `hardening-ubuntu/secretos/`, `CREDENCIALES/` ni `honeytokens.json` (ya están en `.gitignore`).
- Genera tus propios secretos y honeytokens (`scripts/inicializar-secretos.py`, `scripts/regenerar-honeytokens.py`).
- Pon fecha de vencimiento a los tokens de API de Cloudflare y activa 2FA en todas las cuentas.
- Usa una marca y un dominio para el señuelo que no se relacionen contigo ni con tu institución.
