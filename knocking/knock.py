#!/usr/bin/env python3
"""
Port knocking para el server del honeypot (Linux, macOS y Windows; solo Python 3).

  python3 knock.py                 # usa la secuencia de ../hardening-ubuntu/secretos/generados.yml
  python3 knock.py HOST p1:tcp p2:udp p3:tcp p4:tcp p5:udp   # secuencia a mano

Envía un SYN (TCP) o un datagrama (UDP) a cada puerto, en orden. knockd los ve
con libpcap aunque el firewall los descarte, y abre el SSH SOLO para tu IP
durante 5 minutos (las sesiones ya abiertas siguen vivas al cerrarse).
"""
import os, re, socket, sys, time

def host_del_inventario():
    """La IP del servidor sale de hardening-ubuntu/inventory.ini (ansible_host=...)."""
    inv = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "hardening-ubuntu", "inventory.ini")
    try:
        m = re.search(r"ansible_host=(\S+)", open(inv, encoding="utf-8").read())
        return m.group(1) if m else None
    except OSError:
        return None


DEFAULT_HOST = host_del_inventario()
SECRETOS = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "..", "hardening-ubuntu", "secretos", "generados.yml")


def leer_secretos():
    txt = open(SECRETOS, encoding="utf-8").read()
    sec = re.search(r"^knock_secuencia:\s*\[(.*)\]", txt, re.M).group(1)
    puertos = [p.strip().strip("'\"") for p in sec.split(",")]
    ssh = re.search(r"^ssh_puerto:\s*(\d+)", txt, re.M)
    return puertos, (int(ssh.group(1)) if ssh else 22)


def tocar(host, puerto, proto):
    fam = socket.AF_INET6 if ":" in host else socket.AF_INET
    if proto == "udp":
        with socket.socket(fam, socket.SOCK_DGRAM) as s:
            s.sendto(os.urandom(8), (host, puerto))
    else:
        s = socket.socket(fam, socket.SOCK_STREAM)
        s.setblocking(False)
        try:
            s.connect_ex((host, puerto))  # solo hace falta que salga el SYN
            time.sleep(0.05)
        finally:
            s.close()


def main():
    args = sys.argv[1:]
    if len(args) >= 2:
        host, sec = args[0], args[1:]
    else:
        host = args[0] if args else DEFAULT_HOST
        sec, _ = leer_secretos()
    # IPv4: el server no tiene IPv6 público
    host = socket.getaddrinfo(host, None, socket.AF_INET)[0][4][0]
    for item in sec:
        puerto, _, proto = item.partition(":")
        tocar(host, int(puerto), (proto or "tcp").lower())
        time.sleep(0.25)
    print(f"✓ Knock enviado a {host} ({len(sec)} puertos). SSH abierto para tu IP ~5 min.")


if __name__ == "__main__":
    main()
