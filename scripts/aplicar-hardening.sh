#!/usr/bin/env bash
# Reaplica todo el hardening (idempotente: solo cambia lo que se haya desviado).
# Hace backup antes. Uso: ./scripts/aplicar-hardening.sh [--tags ssh,firewall] [--check --diff]
set -euo pipefail
D="$(cd "$(dirname "$0")" && pwd)"
"$D/backup-servidor.sh"
cd "$D/../hardening-ubuntu" && ansible-playbook site.yml "$@"
