#!/usr/bin/env python3
"""Centinela · Integridad de archivos (AIDE) y auditoría del kernel (auditd).

  centinela-integridad aide                 revisión de AIDE (cada hora, temporizador systemd)
  centinela-integridad aide --aceptar TEXTO acepta los cambios actuales como nueva línea base
                                         (lo llama Ansible al terminar un despliegue)
  centinela-integridad audit [MINUTOS]      eventos relevantes de auditd en JSON (lo usa centinela-estado)

Deja:
  · métricas para Prometheus/Grafana en /var/lib/centinela/textfile/{integridad,auditoria}.prom
  · eventos para el vigía (bot de Telegram) en /var/lib/centinela/integridad/eventos.json
Solo librería estándar. Corre como root (AIDE y el log de auditd lo exigen).
"""
import fcntl, glob, gzip, json, os, pwd, re, shutil, subprocess, sys, time
from datetime import datetime, timedelta, timezone

CONF = "/etc/aide/centinela.conf"
BASE = "/var/lib/centinela/aide"
DB, DB_NUEVA = f"{BASE}/aide.db.gz", f"{BASE}/aide.db.new.gz"
DIR = "/var/lib/centinela/integridad"
EVENTOS = f"{DIR}/eventos.json"
ESTADO = f"{DIR}/estado.json"
TEXTFILE = "/var/lib/centinela/textfile"
DESPLIEGUE = "/run/centinela/despliegue"   # existe mientras Ansible está desplegando
GUARDAR_BASES = 10

# Claves de auditd que merecen aviso (solo si el origen es "manual": ni Ansible, ni apt, ni Docker) → (severidad, explicación). 4 = crítica (llega aunque el bot esté silenciado)
CLAVES = {
    "identidad":  (4, "usuarios o grupos (passwd/shadow/group)"),
    "sudoers":    (4, "permisos de sudo"),
    "sshd":       (4, "configuración del SSH"),
    "llaves_ssh": (4, "llaves SSH autorizadas"),
    "pam":        (4, "autenticación del sistema (PAM)"),
    "preload":    (4, "precarga de librerías (técnica de rootkit)"),
    "modulos":    (4, "módulos del kernel"),
    "binarios":   (4, "programas en /usr/local"),
    "knockd":     (4, "secuencia de port knocking"),
    "firewall":   (3, "firewall (UFW/Fail2Ban)"),
    "cron":       (3, "tareas programadas (cron)"),
    "systemd":    (3, "servicios de systemd"),
    "apparmor":   (3, "perfiles de AppArmor"),
    "red":        (3, "red / hosts / hostname"),
    "docker_cfg": (3, "configuración de Docker"),
}
RE_CAMPO = re.compile(r'(\w+)=("([^"]*)"|\S+)')
RE_MSG = re.compile(r"msg=audit\((\d+)\.(\d+):(\d+)\)")


def ahora():
    return datetime.now(timezone.utc)


def iso(ts):
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def leer_json(ruta, defecto):
    try:
        with open(ruta) as f:
            return json.load(f)
    except Exception:
        return defecto


def escribir(ruta, contenido, modo=0o644):
    os.makedirs(os.path.dirname(ruta), exist_ok=True)
    tmp = f"{ruta}.{os.getpid()}.tmp"
    with open(tmp, "w") as f:
        f.write(contenido if isinstance(contenido, str) else json.dumps(contenido, ensure_ascii=False, indent=1))
    os.chmod(tmp, modo)
    os.replace(tmp, ruta)


def metricas(nombre, lineas):
    escribir(f"{TEXTFILE}/{nombre}.prom", "\n".join(lineas) + "\n")


# ════════════════════════════ AIDE ═══════════════════════════════════
def aide(*args):
    if os.path.exists(DB_NUEVA):
        os.remove(DB_NUEVA)
    return subprocess.run(["nice", "-n19", "ionice", "-c3", "aide", "-c", CONF, *args],
                          capture_output=True, text=True, cwd="/")


def parsear(salida):
    """Reporte de AIDE (report_grouped + summarize) → lista de {ruta, cambio, atributos}."""
    tipos = {"Added entries:": "añadido", "Removed entries:": "eliminado", "Changed entries:": "modificado"}
    seccion, cambios = None, []
    for linea in salida.splitlines():
        s = linea.strip()
        if s in tipos:
            seccion = tipos[s]
            continue
        if s.startswith("Detailed information") or s.startswith("The attributes of the"):
            seccion = None
        m = re.match(r"^([a-z!?])([^:]{8,}): (/.*)$", linea)
        if seccion and m:
            cambios.append({"ruta": m.group(3), "cambio": seccion, "atributos": m.group(2).strip(" +-")})
    return cambios


def paquetes_actualizados(desde):
    """Paquetes que apt/dpkg instaló o actualizó desde `desde` (epoch) → {archivo: paquete}."""
    pkgs = set()
    for log in sorted(glob.glob("/var/log/dpkg.log*")):
        abrir = gzip.open if log.endswith(".gz") else open
        try:
            with abrir(log, "rt", errors="replace") as f:
                for l in f:
                    p = l.split()
                    if len(p) >= 5 and p[2] in ("status", "install", "upgrade", "remove", "purge"):
                        try:
                            t = datetime.strptime(f"{p[0]} {p[1]}", "%Y-%m-%d %H:%M:%S").timestamp()
                        except ValueError:
                            continue
                        if t >= desde - 120:
                            pkgs.add((p[4] if p[2] == "status" else p[3]).split(":")[0])
        except OSError:
            pass
    archivos = {}
    for pkg in pkgs:
        for lista in glob.glob(f"/var/lib/dpkg/info/{pkg}.list") + glob.glob(f"/var/lib/dpkg/info/{pkg}:*.list"):
            try:
                for ruta in open(lista):
                    archivos[ruta.strip()] = pkg
            except OSError:
                pass
    return archivos


def rotar_base():
    if os.path.exists(DB):
        shutil.copy2(DB, f"{BASE}/aide.db.{ahora().strftime('%Y%m%d-%H%M%S')}.gz")
        viejas = sorted(glob.glob(f"{BASE}/aide.db.2*.gz"))
        for v in viejas[:-GUARDAR_BASES]:
            os.remove(v)
    os.replace(DB_NUEVA, DB)
    os.chmod(DB, 0o600)


def cmd_aide(aceptar=None):
    os.makedirs(BASE, mode=0o700, exist_ok=True)
    os.makedirs(DIR, exist_ok=True)
    cerrojo = open(f"{BASE}/.lock", "w")
    try:
        fcntl.flock(cerrojo, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        print("ya hay una revisión en curso"); return 0
    est = leer_json(ESTADO, {"base_desde": 0, "revisiones": 0, "inesperados_total": 0, "cambios_total": 0})
    t0 = time.time()

    # Durante un despliegue de Ansible no se revisa (los cambios se aceptan al terminar)
    if not aceptar and os.path.exists(DESPLIEGUE) and time.time() - os.path.getmtime(DESPLIEGUE) < 3 * 3600:
        print("despliegue de Ansible en curso; se omite"); return 0

    if not os.path.exists(DB):
        r = aide("--init")
        if r.returncode != 0 or not os.path.exists(DB_NUEVA):
            return fin_aide(est, t0, error=f"init falló ({r.returncode})")
        rotar_base(); est["base_desde"] = time.time()
        return fin_aide(est, t0, total=contar_entradas(r.stdout))

    r = aide("--update")   # compara con la base Y genera la nueva en una sola pasada
    if r.returncode >= 14 or not os.path.exists(DB_NUEVA):
        return fin_aide(est, t0, error=(r.stderr or r.stdout).strip()[-200:] or f"código {r.returncode}")
    cambios = parsear(r.stdout)
    total = contar_entradas(r.stdout)
    if not cambios:
        os.remove(DB_NUEVA)
        return fin_aide(est, t0, total=total)

    # ¿Explicables? apt/dpkg actualizó el paquete dueño del archivo, o un despliegue de Ansible
    por_apt = paquetes_actualizados(est.get("base_desde") or 0)
    for c in cambios:
        if aceptar:
            c["origen"] = aceptar
        elif c["ruta"] in por_apt:
            c["origen"] = f"actualización apt ({por_apt[c['ruta']]})"
    inesperados = [c for c in cambios if not c.get("origen")]
    evento = {"tipo": "integridad", "fecha": iso(time.time()), "total": len(cambios),
              "inesperados": len(inesperados), "aceptado": aceptar or "",
              "por_tipo": {t: sum(1 for c in cambios if c["cambio"] == t) for t in ("añadido", "eliminado", "modificado")},
              # primero lo inesperado y lo más sensible
              "archivos": sorted(cambios, key=lambda c: (bool(c.get("origen")), not c["ruta"].startswith(("/etc", "/usr", "/boot", "/root")), c["ruta"]))[:40]}
    eventos = [e for e in leer_json(EVENTOS, []) if e.get("fecha", "") >= iso(time.time() - 7 * 86400)][-30:]
    eventos.append(evento)
    escribir(EVENTOS, eventos, 0o600)
    escribir(f"{DIR}/reporte-{ahora().strftime('%Y%m%d-%H%M%S')}.txt", r.stdout, 0o600)
    for viejo in sorted(glob.glob(f"{DIR}/reporte-*.txt"))[:-50]:
        os.remove(viejo)
    # La base avanza: cada cambio se avisa UNA vez (el reporte completo queda guardado arriba)
    rotar_base()
    est["base_desde"] = time.time()
    est["cambios_total"] += len(cambios); est["inesperados_total"] += len(inesperados)
    return fin_aide(est, t0, total=total, ultimo=evento)


def contar_entradas(salida):
    m = re.search(r"(?:Total number of entries|Number of entries):\s*(\d+)", salida)
    return int(m.group(1)) if m else 0


def fin_aide(est, t0, total=0, ultimo=None, error=None):
    est["revisiones"] += 1
    if total:
        est["archivos"] = total
    est["ultima"] = time.time(); est["duracion"] = round(time.time() - t0, 1); est["error"] = error or ""
    if ultimo is not None or error is None:
        est["ultimo_inesperados"] = ultimo["inesperados"] if ultimo else 0
        est["ultimo_cambios"] = ultimo["total"] if ultimo else 0
    escribir(ESTADO, est, 0o600)
    m = ["# HELP centinela_integridad_ultima_revision Fin de la última revisión de AIDE (epoch)",
         "# TYPE centinela_integridad_ultima_revision gauge", f"centinela_integridad_ultima_revision {int(est['ultima'])}",
         "# TYPE centinela_integridad_duracion_segundos gauge", f"centinela_integridad_duracion_segundos {est['duracion']}",
         "# TYPE centinela_integridad_archivos gauge", f"centinela_integridad_archivos {est.get('archivos', 0)}",
         "# TYPE centinela_integridad_error gauge", f"centinela_integridad_error {1 if error else 0}",
         "# HELP centinela_integridad_cambios Archivos cambiados en la última revisión",
         "# TYPE centinela_integridad_cambios gauge", f"centinela_integridad_cambios {est.get('ultimo_cambios', 0)}",
         "# HELP centinela_integridad_inesperados Cambios sin explicación (ni apt ni Ansible) en la última revisión",
         "# TYPE centinela_integridad_inesperados gauge", f"centinela_integridad_inesperados {est.get('ultimo_inesperados', 0)}",
         "# TYPE centinela_integridad_cambios_total counter", f"centinela_integridad_cambios_total {est['cambios_total']}",
         "# TYPE centinela_integridad_inesperados_total counter", f"centinela_integridad_inesperados_total {est['inesperados_total']}"]
    metricas("integridad", m)
    print(json.dumps({"error": error, "archivos": est.get("archivos"), "cambios": est.get("ultimo_cambios"),
                      "inesperados": est.get("ultimo_inesperados"), "segundos": est["duracion"]}, ensure_ascii=False))
    return 1 if error else 0


# ════════════════════════════ auditd ═════════════════════════════════
_usuarios = {}


def usuario(uid):
    if uid in (None, "", "4294967295", "-1", "unset"):
        return "sistema"
    if uid not in _usuarios:
        try:
            _usuarios[uid] = pwd.getpwuid(int(uid)).pw_name
        except (KeyError, ValueError):
            _usuarios[uid] = uid
    return _usuarios[uid]


def texto(v):
    """auditd guarda en hexadecimal los valores con espacios (proctitle, rutas raras)."""
    if v and re.fullmatch(r"[0-9A-F]+", v) and len(v) % 2 == 0 and len(v) > 6:
        try:
            return bytes.fromhex(v).replace(b"\x00", b" ").decode(errors="replace").strip()
        except ValueError:
            pass
    return v or ""


def parsear_audit(salida):
    eventos = []
    for bloque in salida.split("----"):
        sc, rutas, titulo, ts, serie = {}, [], "", 0, ""
        for linea in bloque.strip().splitlines():
            m = RE_MSG.search(linea)
            if m:
                ts, serie = int(m.group(1)), m.group(3)
            campos = {k: (q if v.startswith('"') else v) for k, v, q in RE_CAMPO.findall(linea)}
            tipo = campos.get("type")
            if tipo == "SYSCALL":
                sc = campos
            elif tipo == "PATH" and campos.get("nametype") not in ("PARENT", "UNKNOWN"):
                rutas.append(texto(campos.get("name")))
            elif tipo == "PROCTITLE":
                titulo = texto(campos.get("proctitle"))
        clave = sc.get("key", "")
        if not sc or clave not in CLAVES:
            continue
        exe = sc.get("exe", ""); comm = sc.get("comm", "")
        auid = usuario(sc.get("auid"))
        # Port knocking: knockd abre/cierra el SSH con ufw; eso ya se avisa como "knock"
        if clave == "firewall" and auid == "sistema" and re.search(r"ufw (prepend |insert \d+ )?(allow|delete)", titulo):
            continue
        if "AnsiballZ_" in titulo or "/.ansible/" in titulo or any("/.ansible_tmp" in r for r in rutas):
            origen = f"Ansible ({auid})"
        elif auid == "sistema" and comm == "modprobe" and exe.endswith("/kmod") and re.fullmatch(r"/sbin/modprobe -(q|abq) (-- )?[\w-]+", titulo):
            origen = "sistema (el kernel cargó un módulo solo)"
        elif auid == "sistema" and clave == "red" and titulo.startswith("/usr/bin/python3 /usr/bin/cloud-init ") and all("/etc/netplan/50-cloud-init.yaml" in r for r in rutas if r):
            origen = "sistema (cloud-init al arrancar)"
        elif exe.endswith("/runc") or comm.startswith("runc"):
            origen = "Docker (arranque de contenedor)"
        elif comm in ("dpkg", "apt", "apt-get", "unattended-upgr") or exe.endswith("/dpkg") or "unattended-upgrade" in titulo:
            origen = "actualización apt"
        else:
            origen = ""
        eventos.append({"tipo": "audit", "fecha": iso(ts), "ts": ts, "serie": serie, "clave": clave, "que": CLAVES[clave][1],
                        "severidad": CLAVES[clave][0], "rutas": sorted(set(p for p in rutas if p))[:6],
                        "usuario": auid, "como": usuario(sc.get("uid")), "exito": sc.get("success") != "no",
                        "programa": exe, "comando": titulo[:200], "origen": origen, "pid": sc.get("pid")})
    # Con pipelining, Ansible corre el módulo por stdin (sin AnsiballZ en el título): si el mismo
    # proceso dejó archivos .ansible_tmp, todo lo que hizo ese proceso es de Ansible
    ansible = {(e["pid"], e["usuario"]) for e in eventos if e["origen"].startswith("Ansible")}
    for e in eventos:
        if not e["origen"] and (e.pop("pid", None), e["usuario"]) in ansible:
            e["origen"] = f"Ansible ({e['usuario']})"
        e.pop("pid", None)
    return eventos


def nuevos_audit():
    """Solo lo que llegó desde la última lectura (punto de control de ausearch)."""
    ckpt = f"{DIR}/audit.ckpt"
    env = {"LC_ALL": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"}
    base = ["ausearch", "--input-logs", "--checkpoint", ckpt]
    r = subprocess.run(base + ([] if os.path.exists(ckpt) else ["-ts", "recent"]), capture_output=True, text=True, env=env)
    if r.returncode in (10, 11, 12):   # log rotado o punto de control inválido: se reinicia desde hace 10 min
        os.remove(ckpt)
        r = subprocess.run(base + ["-ts", "recent"], capture_output=True, text=True, env=env)
    return parsear_audit(r.stdout)


def cmd_audit(minutos=15):
    os.makedirs(DIR, exist_ok=True)
    cerrojo = open(f"{DIR}/.audit.lock", "w")
    fcntl.flock(cerrojo, fcntl.LOCK_EX)
    ruta = f"{DIR}/audit_recientes.json"
    limite = time.time() - 86400
    recientes = [e for e in leer_json(ruta, []) if e.get("ts", 0) > limite]
    vistos = {e["serie"] + e["fecha"] for e in recientes}
    recientes += [e for e in nuevos_audit() if e["serie"] + e["fecha"] not in vistos]
    recientes = recientes[-3000:]
    escribir(ruta, recientes, 0o600)

    activo = subprocess.run(["systemctl", "is-active", "--quiet", "auditd"]).returncode == 0
    st = subprocess.run(["auditctl", "-s"], capture_output=True, text=True).stdout
    num = lambda k: int((re.search(rf"^{k} (\d+)", st, re.M) or [0, 0])[1])
    m = ["# HELP centinela_auditd_activo auditd corriendo (1) o no (0)", "# TYPE centinela_auditd_activo gauge", f"centinela_auditd_activo {int(activo)}",
         "# HELP centinela_audit_perdidos Eventos que el kernel no pudo registrar (desde el arranque)",
         "# TYPE centinela_audit_perdidos counter", f"centinela_audit_perdidos {num('lost')}",
         "# TYPE centinela_audit_backlog gauge", f"centinela_audit_backlog {num('backlog')}",
         "# TYPE centinela_audit_reglas gauge", f"centinela_audit_reglas {len(subprocess.run(['auditctl', '-l'], capture_output=True, text=True).stdout.splitlines())}",
         "# HELP centinela_audit_eventos_24h Cambios sensibles vistos por auditd en 24 h, por clave y origen",
         "# TYPE centinela_audit_eventos_24h gauge"]
    cuenta = {}
    for e in recientes:
        o = ("ansible" if e["origen"].startswith("Ansible") else "docker" if e["origen"].startswith("Docker")
             else "sistema" if e["origen"].startswith("sistema") else "apt" if e["origen"] else "manual")
        cuenta[(e["clave"], o)] = cuenta.get((e["clave"], o), 0) + 1
    for clave in CLAVES:
        for o in ("manual", "ansible", "apt", "docker", "sistema"):
            m.append(f'centinela_audit_eventos_24h{{clave="{clave}",origen="{o}"}} {cuenta.get((clave, o), 0)}')
    metricas("auditoria", m)
    desde = time.time() - minutos * 60
    print(json.dumps([{k: v for k, v in e.items() if k != "ts"} for e in recientes if e["ts"] > desde], ensure_ascii=False))


def main():
    a = sys.argv[1:]
    if not a or a[0] not in ("aide", "audit"):
        print(__doc__); return 2
    if a[0] == "aide":
        aceptar = a[a.index("--aceptar") + 1] if "--aceptar" in a and len(a) > a.index("--aceptar") + 1 else None
        return cmd_aide(aceptar)
    return cmd_audit(int(a[1]) if len(a) > 1 and a[1].isdigit() else 15) or 0


if __name__ == "__main__":
    sys.exit(main())
