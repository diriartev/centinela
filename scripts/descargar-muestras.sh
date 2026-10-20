#!/usr/bin/env bash
# Descarga a tu PC las muestras de malware en cuarentena (ZIP cifrados, contraseña "infected").
# Quedan en <repo>/muestras/ junto con su ficha .json (URL, IP, ataque, hash).
# ⚠️ Ábrelas solo dentro de una VM/sandbox de análisis (REMnux, FLARE-VM, ANY.RUN, Triage).
set -euo pipefail
B="$(cd "$(dirname "$0")/.." && pwd)"; DEST="$B/muestras"; mkdir -p "$DEST"; chmod 700 "$DEST"
cd "$B/hardening-ubuntu"; python3 "$B/knocking/knock.py" >/dev/null
ansible srv-honey -b -m shell -a 'cd /opt/stacks/vigia/cuarentena 2>/dev/null && tar -cf /tmp/vs-muestras.tar . && chown honeypot /tmp/vs-muestras.tar && chmod 600 /tmp/vs-muestras.tar' >/dev/null
ansible srv-honey -m fetch -a "src=/tmp/vs-muestras.tar dest=$DEST/ flat=yes" >/dev/null
ansible srv-honey -b -m file -a "path=/tmp/vs-muestras.tar state=absent" >/dev/null
tar -xf "$DEST/vs-muestras.tar" -C "$DEST" && rm -f "$DEST/vs-muestras.tar"
echo "✓ $(ls "$DEST"/*.zip 2>/dev/null | wc -l) muestras en $DEST (contraseña de los ZIP: infected)"
