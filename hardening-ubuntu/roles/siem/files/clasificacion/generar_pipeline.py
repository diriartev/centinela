#!/usr/bin/env python3
"""Genera ../pipeline_honeypot.api.json (lo que se sube a Elasticsearch) a partir de:
  - ../pipeline_honeypot.json      pipeline legible (scripts painless entre triple comillas)
  - clasificar.painless            clasificador de ataques
  - reglas_ataques.yml             reglas propias (en español)
  - trampas_h0neytr4p.json         catálogo de trampas de CVEs de T-Pot/h0neytr4p
Uso: python3 generar_pipeline.py   (luego: ansible-playbook site.yml --tags siem)
"""
import json, os, re, sys
import yaml

AQUI = os.path.dirname(os.path.abspath(__file__))
FILES = os.path.dirname(AQUI)

TECNICAS = {  # nombres de técnicas MITRE que aparecen en las trampas de h0neytr4p
    "T1190": "Exploit Public-Facing Application", "T1110": "Brute Force", "T1078": "Valid Accounts",
    "T1059": "Command and Scripting Interpreter", "T1566": "Phishing", "T1584": "Compromise Infrastructure",
    "T1499": "Endpoint Denial of Service", "T1505.003": "Server Software Component: Web Shell",
    "T1556": "Modify Authentication Process", "T1552.001": "Unsecured Credentials: Credentials In Files",
}


def regla_propia(r):
    c = {"id": r["id"], "n": r["nombre"], "c": r["categoria"], "s": int(r["severidad"]),
         "ta": r["tactica"], "ti": r["tecnica_id"], "te": r["tecnica"],
         "ex": " ".join(r["explicacion"].split()), "re": r.get("recomendacion", ""), "f": "Centinela"}
    if r.get("cve"): c["cve"] = r["cve"]
    if r.get("en"): c["en"] = list(r["en"])
    if r.get("cualquiera"): c["any"] = [t.lower() for t in r["cualquiera"]]
    if r.get("grupos"): c["grp"] = [[t.lower() for t in g] for g in r["grupos"]]
    if r.get("campo"): c["campo"] = r["campo"]
    if r.get("honeypots"): c["hp"] = list(r["honeypots"])
    if r.get("puertos"): c["pt"] = [int(p) for p in r["puertos"]]
    validos = {"url", "cuerpo", "cmd", "ua", "cabeceras", "accion"}
    assert set(c.get("en", [])) <= validos, (r["id"], c.get("en"))
    assert 1 <= c["s"] <= 4, r["id"]
    return c


def regla_trampa(t):
    riesgo = float(t["riesgo"]) if t.get("riesgo") not in (None, "", "None") else None
    sev = 4 if (riesgo or 0) >= 9 else 3 if (riesgo or 0) >= 7 else 2
    tags = [x.strip() for x in (t.get("mitre") or "").split(",") if x.strip()]
    ti = tags[0] if tags else "T1190"
    es_cve = t["nombre"].upper().startswith("CVE-")
    nombre = (f"Explotación de {t['nombre']}" if es_cve else f"Trampa T-Pot: {t['nombre']}")
    expl = ("Intento de explotar una vulnerabilidad publicada (" + t["nombre"] + ")"
            + (f", con riesgo {riesgo}/10" if riesgo else "") + ". Detectado con el catálogo de trampas de T-Pot (h0neytr4p). "
            + "Descripción original: " + " ".join((t.get("descripcion") or "").split()))[:900]
    globs, metodos = [], set()
    for p in t["patrones"]:
        u = p["url"].lower()
        globs.append(u if u.startswith(("/", "*")) else "*" + u)
        metodos.add(p["metodo"])
    c = {"id": "t-" + re.sub(r"[^a-z0-9]+", "-", t["nombre"].lower()).strip("-"), "n": nombre,
         "c": "Explotación de vulnerabilidad" if es_cve else "Exposición de secretos",
         "s": sev, "ta": "Initial Access", "ti": ti, "te": TECNICAS.get(ti, "Exploit Public-Facing Application"),
         "ex": expl, "re": "Revisar las referencias del CVE y confirmar que ningún sistema real use esa versión.",
         "hp": ["web"], "glob": sorted(set(globs)), "f": "T-Pot h0neytr4p"}
    if len(metodos) == 1 and "*" not in metodos: c["me"] = metodos.pop()
    if es_cve: c["cve"] = t["nombre"].upper()
    if t.get("referencias"): c["ref"] = t["referencias"][:500]
    return c


def triple_a_json(texto):
    # Convierte "source": """ ... """ en cadenas JSON válidas
    return re.sub(r'"""(.*?)"""', lambda m: json.dumps(m.group(1)), texto, flags=re.S)


def main():
    reglas = [regla_propia(r) for r in yaml.safe_load(open(os.path.join(AQUI, "reglas_ataques.yml")))["reglas"]]
    trampas = [regla_trampa(t) for t in json.load(open(os.path.join(AQUI, "trampas_h0neytr4p.json")))]
    ids = [r["id"] for r in reglas + trampas]
    dup = {i for i in ids if ids.count(i) > 1}
    if dup:
        # trampas con el mismo nombre en dos carpetas: se unen sus patrones
        unidas = {}
        for t in trampas:
            if t["id"] in unidas:
                unidas[t["id"]]["glob"] = sorted(set(unidas[t["id"]]["glob"] + t["glob"]))
                unidas[t["id"]].pop("me", None)
            else:
                unidas[t["id"]] = t
        trampas = list(unidas.values())
    pipeline = json.loads(triple_a_json(open(os.path.join(FILES, "pipeline_honeypot.json")).read()))
    script = open(os.path.join(AQUI, "clasificar.painless")).read()
    proc = {"script": {"lang": "painless", "tag": "clasificar", "ignore_failure": True,
                       "description": "Clasifica el ataque (reglas Centinela + trampas T-Pot) y lo explica en español",
                       "source": script, "params": {"reglas": reglas + trampas}}}
    procs = [p for p in pipeline["processors"] if p.get("script", {}).get("tag") != "clasificar"]
    i = next(n for n, p in enumerate(procs) if "date" in p) + 1   # justo después de fijar @timestamp
    procs.insert(i, proc)
    pipeline["processors"] = procs
    destino = os.path.join(FILES, "pipeline_honeypot.api.json")
    json.dump(pipeline, open(destino, "w"), ensure_ascii=False, indent=1)
    # Catálogo legible para el panel (sin los patrones)
    catalogo = [{k: r[k] for k in ("id", "n", "c", "s", "ta", "ti", "te", "ex", "re", "f") if k in r} | ({"cve": r["cve"]} if r.get("cve") else {})
                for r in reglas + trampas]
    json.dump(catalogo, open(os.path.join(AQUI, "catalogo_ataques.json"), "w"), ensure_ascii=False, indent=1)
    print(f"OK: {len(reglas)} reglas propias + {len(trampas)} trampas T-Pot → {destino}")


if __name__ == "__main__":
    sys.exit(main())
