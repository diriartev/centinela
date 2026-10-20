#!/usr/bin/env bash
# Auditoría Lynis (toca la puerta sola). Reporte en hardening-ubuntu/reportes/
cd "$(dirname "$0")/../hardening-ubuntu" && ansible-playbook lynis.yml -e fase=despues
