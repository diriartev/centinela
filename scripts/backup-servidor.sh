#!/usr/bin/env bash
# Backup del server del honeypot → <repo>/backups/<fecha>/
# Incluye /etc completo, /opt/stacks (compose, secretos, logs y snapshots de Elasticsearch),
# los volúmenes de Docker (Portainer, etc.) y el estado de UFW/paquetes.
# Uso:  ./scripts/backup-servidor.sh
set -euo pipefail
H="$(cd "$(dirname "$0")/.." && pwd)"
A="$H/hardening-ubuntu"
FECHA="$(date +%Y-%m-%d_%H%M%S)"
DEST="$H/backups/$FECHA"
umask 077
mkdir -p "$DEST"
cd "$A"
python3 "$H/knocking/knock.py" >/dev/null; sleep 1
REMOTO="/root/backup-$FECHA.tar.gz"
echo "→ Creando backup en el server..."
ansible honeypot -m shell -a "set -e
  mkdir -p /root/bk-tmp && cd /root/bk-tmp
  dpkg --get-selections > paquetes.txt
  ufw status numbered > ufw.txt 2>&1 || true
  docker ps -a > docker-ps.txt 2>&1 || true
  if command -v docker >/dev/null; then
    for v in \$(docker volume ls -q | grep -v esdata); do
      docker run --rm -v \$v:/v:ro -v /root/bk-tmp:/out --network none alpine:3.20 tar czf /out/vol-\$v.tar.gz -C /v . || true; done
  fi
  tar czf $REMOTO --warning=no-file-changed /etc /opt/stacks /root/bk-tmp 2>/dev/null || [ \$? -eq 1 ]
  rm -rf /root/bk-tmp; chmod 600 $REMOTO" >/dev/null
echo "→ Descargando..."
ansible honeypot -m fetch -a "src=$REMOTO dest=$DEST/ flat=yes" >/dev/null
ansible honeypot -m file -a "path=$REMOTO state=absent" >/dev/null
chmod 600 "$DEST"/*
echo "✓ Backup en $DEST ($(du -sh "$DEST" | cut -f1))"
