#!/usr/bin/env bash
# Auditoría CIS Docker Benchmark (docker-bench-security) sobre el server.
# El reporte queda en <repo>/hardening-ubuntu/reportes/
set -euo pipefail
A="$(cd "$(dirname "$0")/../hardening-ubuntu" && pwd)"; cd "$A"
python3 ../knocking/knock.py >/dev/null; sleep 1
ansible honeypot -m shell -a 'set -e
  if [ ! -d /opt/docker-bench ]; then git clone -q --depth 1 https://github.com/docker/docker-bench-security /opt/docker-bench; else git -C /opt/docker-bench pull -q; fi
  rm -f /root/docker-bench.log; cd /opt/docker-bench && ./docker-bench-security.sh -b -l /root/docker-bench.log >/dev/null 2>&1 || true
  sed -r "s/\x1B\[[0-9;]*m//g" /root/docker-bench.log' 2>/dev/null | sed 1d > reportes/docker-bench.txt
grep -E '^\[(WARN|PASS|INFO|NOTE)\]' reportes/docker-bench.txt | awk '{print $1}' | sort | uniq -c
grep -E 'Score|Checks' reportes/docker-bench.txt
