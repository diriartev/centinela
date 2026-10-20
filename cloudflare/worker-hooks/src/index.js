// Centinela · Relay de alertas + bot de Telegram (Cloudflare Worker)
// -------------------------------------------------------------------
// El servidor NO habla con Telegram: firma cada mensaje (HMAC-SHA256) y lo manda aquí por HTTPS
// (la única salida que tiene es hacia Cloudflare). Este Worker:
//   · reenvía alertas a TU chat de Telegram (y solo al tuyo)
//   · responde comandos (/estado, /resumen, /ataques, /ultimos, /muestras, /silenciar…) con el
//     último resumen que mandó el servidor (el bot nunca se conecta al servidor)
//   · descarga muestras de malware desde la red de Cloudflare (nunca desde la IP de la institución); el vigía
//     las cifra (ZIP, contraseña "infected") y te llegan con su hash y enlaces a VirusTotal / MalwareBazaar
//   · avisa si el servidor deja de reportar (vigilancia tipo "hombre muerto", cada 10 min)
//
// Secretos (wrangler secret put): TG_TOKEN, TG_CHAT_ID, TG_WEBHOOK_SECRET, RELAY_KEY
import { DurableObject } from "cloudflare:workers";

const MAX_MUESTRA = 4 * 1024 * 1024;     // 4 MB por muestra (el vigía la cifra)
const MUESTRAS_POR_HORA = 20;
const VENTANA_FIRMA = 300;               // segundos de tolerancia del reloj
const SIN_REPORTE_MIN = 20;              // minutos sin resumen → alerta de servidor caído
const enc = new TextEncoder();

// ── utilidades ───────────────────────────────────────────────────────
const json = (d, s = 200) => new Response(JSON.stringify(d), { status: s, headers: { "content-type": "application/json" } });
const nada = () => new Response("Not found", { status: 404 });
const esc = (t) => String(t ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
const defang = (u) => String(u).replace(/^http/i, "hxxp").replace(/\./g, "[.]");
const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
async function sha256(datos) { return hex(await crypto.subtle.digest("SHA-256", typeof datos === "string" ? enc.encode(datos) : datos)); }
async function hmac(clave, texto) {
  const k = await crypto.subtle.importKey("raw", enc.encode(clave), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return hex(await crypto.subtle.sign("HMAC", k, enc.encode(texto)));
}
function igual(a, b) {   // comparación en tiempo constante
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let r = 0; for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}
function hace(iso) {
  if (!iso) return "nunca";
  const s = Math.max(0, (Date.now() - Date.parse(iso)) / 1000);
  if (s < 90) return `${Math.round(s)} s`; if (s < 5400) return `${Math.round(s / 60)} min`;
  if (s < 172800) return `${Math.round(s / 3600)} h`; return `${Math.round(s / 86400)} días`;
}
const SEV = { 1: "⚪️ baja", 2: "🟡 media", 3: "🟠 alta", 4: "🔴 crítica" };
const BANDERA = (cc) => (cc && /^[A-Za-z]{2}$/.test(cc) ? String.fromCodePoint(...[...cc.toUpperCase()].map((c) => 127397 + c.charCodeAt(0))) : "🏳️");
const bytes = (n) => (n > 1048576 ? (n / 1048576).toFixed(1) + " MB" : n > 1024 ? (n / 1024).toFixed(1) + " KB" : n + " B");

// ── Telegram ─────────────────────────────────────────────────────────
async function tg(env, metodo, cuerpo) {
  const r = await fetch(`https://api.telegram.org/bot${env.TG_TOKEN}/${metodo}`, cuerpo instanceof FormData
    ? { method: "POST", body: cuerpo } : { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(cuerpo) });
  const d = await r.json().catch(() => ({}));
  if (!d.ok) console.log("telegram", metodo, r.status, d.description);
  return d;
}
// Destino de las alertas: el grupo vinculado con /vincular (guardado en el Durable Object) o, si no hay,
// el chat privado del dueño (TG_CHAT_ID). El dueño es siempre TG_CHAT_ID: solo él administra el bot.
async function destino(env) { return (await estado(env).leer("chat_destino")) || String(env.TG_CHAT_ID); }
async function aChat(env, chat, metodo, cuerpo) {
  let r = await tg(env, metodo, cuerpo(chat));
  const nuevo = r?.parameters?.migrate_to_chat_id;
  if (!r.ok && nuevo) {   // el grupo pasó a supergrupo: Telegram avisa el ID nuevo
    await estado(env).guardar("chat_destino", String(nuevo));
    r = await tg(env, metodo, cuerpo(String(nuevo)));
  }
  return r;
}
async function enviar(env, texto, extra = {}, chat = null) {
  const dest = chat || await destino(env);
  const cuerpo = (c) => ({ chat_id: c, text: texto.slice(0, 4000), parse_mode: "HTML", disable_web_page_preview: true, ...extra });
  let r = await aChat(env, dest, "sendMessage", cuerpo);
  // Si sacaron al bot del grupo (o no puede escribir), la alerta llega igual al dueño por privado
  if (!r.ok && !chat && dest !== String(env.TG_CHAT_ID)) {
    const r2 = await tg(env, "sendMessage", cuerpo(String(env.TG_CHAT_ID)));
    if (!(await estado(env).yaVista("aviso_grupo", 1))) await tg(env, "sendMessage", { chat_id: String(env.TG_CHAT_ID), parse_mode: "HTML",
      text: `⚠️ No pude escribir en el grupo vinculado (${esc(r.description || "error")}). Te mando las alertas por aquí. Usa /vincular en el grupo para reconectarlo.` });
    return r2;
  }
  return r;
}

// ── Estado persistente (Durable Object con SQLite) ───────────────────
export class Estado extends DurableObject {
  async leer(k) { return (await this.ctx.storage.get(k)) ?? null; }
  async guardar(k, v) { await this.ctx.storage.put(k, v); }
  // Anti-repetición: cada firma se acepta una sola vez (se olvidan tras 10 min)
  async firmaNueva(firma) {
    const k = "n:" + firma;
    if (await this.ctx.storage.get(k)) return false;
    await this.ctx.storage.put(k, Date.now());
    if (Math.random() < 0.05) {   // limpieza ocasional
      const viejas = await this.ctx.storage.list({ prefix: "n:" });
      const borrar = [...viejas].filter(([, t]) => Date.now() - t > 600000).map(([k2]) => k2);
      if (borrar.length) await this.ctx.storage.delete(borrar.slice(0, 128));
    }
    return true;
  }
  // Límite de descargas por hora
  async cupoMuestra() {
    const h = "c:" + Math.floor(Date.now() / 3600000);
    const n = ((await this.ctx.storage.get(h)) ?? 0) + 1;
    await this.ctx.storage.put(h, n);
    return n <= MUESTRAS_POR_HORA;
  }
  async yaVista(clave, ttlHoras = 24) {
    const k = "v:" + clave; const t = await this.ctx.storage.get(k);
    if (t && Date.now() - t < ttlHoras * 3600000) return true;
    await this.ctx.storage.put(k, Date.now()); return false;
  }
  async agregarMuestra(m) {
    const l = (await this.ctx.storage.get("muestras")) ?? [];
    l.unshift(m); await this.ctx.storage.put("muestras", l.slice(0, 50));
  }
}
const estado = (env) => env.ESTADO.get(env.ESTADO.idFromName("principal"));

// ── Entrada desde el servidor (firmada) ──────────────────────────────
async function verificarServidor(req, env, ruta, cuerpo) {
  const fecha = req.headers.get("x-vs-fecha") || "", firma = req.headers.get("x-vs-firma") || "";
  const ahora = Math.floor(Date.now() / 1000);
  if (!/^\d{10}$/.test(fecha) || Math.abs(ahora - Number(fecha)) > VENTANA_FIRMA) return false;
  const esperada = await hmac(env.RELAY_KEY, `${fecha}\n${ruta}\n${await sha256(cuerpo)}`);
  if (!igual(firma, esperada)) return false;
  return await estado(env).firmaNueva(firma);
}

async function evento(env, d) {
  const sev = Number(d.severidad || 3);
  const silencio = await estado(env).leer("silencio_hasta");
  if (sev < 4 && silencio && Date.now() < silencio) return { ok: true, silenciado: true };
  const extra = d.boton ? { reply_markup: { inline_keyboard: [[{ text: d.boton.texto, url: d.boton.url }]] } } : {};
  if (sev <= 2) extra.disable_notification = true;   // informativo: llega sin sonar
  const r = await enviar(env, String(d.texto || ""), extra);
  return r.ok ? { ok: true } : { ok: false, error: r.description || "telegram" };
}

// Descarga una muestra de malware desde la red de Cloudflare (nunca desde la IP de la institución) y la DEVUELVE
// al vigía, que la cifra en un ZIP con contraseña "infected" (estándar de la industria) y la manda con /v1/archivo.
async function muestra(env, d) {
  let url;
  try { url = new URL(String(d.url)); } catch { return json({ ok: false, error: "url inválida" }); }
  if (!["http:", "https:"].includes(url.protocol)) return json({ ok: false, error: "protocolo no descargable" });
  const propio = env.DOMINIO && (url.hostname === env.DOMINIO || url.hostname.endsWith("." + env.DOMINIO));
  if (propio || /^(localhost|.*\.local|.*\.internal)$/i.test(url.hostname) ||
      /^(10|127|0)\.|^192\.168\.|^172\.(1[6-9]|2\d|3[01])\.|^169\.254\.|^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|^\[/.test(url.hostname))
    return json({ ok: false, error: "destino privado" });
  const st = estado(env);
  if (await st.yaVista("u:" + url.href)) return json({ ok: true, repetida: true });
  if (!(await st.cupoMuestra())) return json({ ok: false, error: "límite por hora" });
  let r, actual = url;
  try {
    for (let salto = 0; salto < 4; salto++) {
      r = await fetch(actual.href, { method: "GET", redirect: "manual", signal: AbortSignal.timeout(15000),
        headers: { "user-agent": "Wget/1.21.2", accept: "*/*" }, cf: { cacheTtl: 0 } });
      if (r.status >= 300 && r.status < 400 && r.headers.get("location")) {
        actual = new URL(r.headers.get("location"), actual);
        if (!["http:", "https:"].includes(actual.protocol)) break;
        continue;
      }
      break;
    }
  } catch (e) {
    await enviar(env, `🧪 <b>No se pudo capturar la muestra</b>\n<code>${esc(defang(url.href))}</code>\nMotivo: ${esc(e.name || "error de red")} (el servidor del atacante no respondió o usa un puerto que Cloudflare no permite).`);
    return json({ ok: false, error: "descarga fallida" });
  }
  if (!r || !r.ok || !r.body) return json({ ok: false, error: "http " + (r && r.status) });
  const partes = []; let total = 0; const lector = r.body.getReader();
  while (true) {
    const { done, value } = await lector.read(); if (done) break;
    total += value.byteLength; if (total > MAX_MUESTRA) { lector.cancel(); break; }
    partes.push(value);
  }
  const datos = new Uint8Array(Math.min(total, MAX_MUESTRA)); let o = 0;
  for (const p of partes) { const n = Math.min(p.byteLength, datos.length - o); datos.set(p.subarray(0, n), o); o += n; if (o >= datos.length) break; }
  return new Response(datos, { headers: { "content-type": "application/octet-stream", "x-vs-url-final": actual.href,
    "x-vs-truncada": total > MAX_MUESTRA ? "1" : "0" } });
}

// Muestra ya empaquetada por el vigía (ZIP cifrado, contraseña "infected") → Telegram
async function archivo(env, form) {
  const f = form.get("archivo"), meta = JSON.parse(form.get("meta") || "{}");
  if (!(f instanceof File) || f.size > 20 * 1024 * 1024) return { ok: false, error: "archivo inválido" };
  const hash = /^[0-9a-f]{64}$/.test(meta.sha256 || "") ? meta.sha256 : "desconocido";
  const st = estado(env);
  if (hash !== "desconocido" && await st.yaVista("h:" + hash, 24 * 30)) return { ok: true, repetida: true, sha256: hash };
  const pie = `🧬 <b>Muestra capturada</b> · ${esc(meta.tipo || "datos")} · ${bytes(meta.tam || 0)}${meta.truncada ? " (truncada)" : ""}\n` +
    (meta.url ? `🔗 <code>${esc(defang(meta.url))}</code>\n` : "") + (meta.origen ? `📂 ${esc(meta.origen)}\n` : "") +
    `#️⃣ <code>${esc(hash)}</code>\n` +
    (meta.ip ? `👤 ${BANDERA(meta.pais_iso)} <code>${esc(meta.ip)}</code>${meta.asn ? " · " + esc(meta.asn) : ""}\n` : "") +
    (meta.ataque ? `🎯 ${esc(meta.ataque)}${meta.sensor ? " · " + esc(meta.sensor) : ""}\n` : "") +
    `\n🔐 ZIP cifrado · contraseña: <code>infected</code>\n⚠️ Malware real: ábrelo solo en una VM o sandbox (ANY.RUN, Triage, REMnux).\n` +
    (hash !== "desconocido" ? `<a href="https://www.virustotal.com/gui/file/${hash}">VirusTotal</a> · <a href="https://bazaar.abuse.ch/browse.php?search=sha256%3A${hash}">MalwareBazaar</a> · <a href="https://tria.ge/s?q=${hash}">Triage</a>` : "");
  const fd = new FormData();
  const zip = await f.arrayBuffer();
  const t = await aChat(env, await destino(env), "sendDocument", (c) => {
    const fd = new FormData();
    fd.append("chat_id", c); fd.append("caption", pie.slice(0, 1020)); fd.append("parse_mode", "HTML");
    fd.append("document", new Blob([zip], { type: "application/zip" }), `${hash.slice(0, 16)}.zip`);
    return fd;
  });
  await st.agregarMuestra({ fecha: new Date().toISOString(), sha256: hash, url: meta.url || meta.origen || "subida", tipo: meta.tipo || "datos",
                            tam: meta.tam || f.size, ip: meta.ip || null, ataque: meta.ataque || null });
  return { ok: !!t.ok, sha256: hash };
}

// ── Comandos del bot ─────────────────────────────────────────────────
const AYUDA = `🌋 <b>Centinela · Centro de alertas</b>

/estado — salud del servidor y los sensores
/resumen — actividad de las últimas 24 h
/ataques — tipos de ataque de hoy, explicados
/ultimos — últimos ataques graves
/top — IPs, países y contraseñas más usadas
/ip <code>1.2.3.4</code> — qué hizo esa IP
/muestras — malware capturado
/silenciar <code>60</code> — pausar alertas no críticas (min) · solo admin
/activar — volver a recibir todo · solo admin
/vincular — (admin, dentro de un grupo) mandar las alertas a ese grupo
/desvincular — (admin) volver a recibirlas por privado

Las alertas 🔴 críticas llegan siempre.`;

async function comando(env, texto) {
  const [c0, ...args] = texto.trim().split(/\s+/); const c = c0.split("@")[0].toLowerCase();
  const st = estado(env); const s = await st.leer("snapshot");
  const viejo = s ? `\n\n<i>Datos de hace ${hace(s.generado)}.</i>` : "";
  if (c === "/start" || c === "/ayuda" || c === "/help") return AYUDA;
  if (c === "/silenciar") {
    const min = Math.min(Math.max(parseInt(args[0] || "60", 10) || 60, 5), 1440);
    await st.guardar("silencio_hasta", Date.now() + min * 60000);
    return `🔕 Alertas no críticas en pausa por <b>${min} min</b>. Las 🔴 críticas siguen llegando. /activar para reanudar.`;
  }
  if (c === "/activar") { await st.guardar("silencio_hasta", 0); return "🔔 Alertas reanudadas."; }
  if (c === "/muestras") {
    const l = (await st.leer("muestras")) || [];
    if (!l.length) return "🧬 Aún no se ha capturado ninguna muestra de malware.";
    return "🧬 <b>Últimas muestras capturadas</b>\n\n" + l.slice(0, 10).map((m) =>
      `• ${hace(m.fecha)} · ${esc(m.tipo)} · ${bytes(m.tam)}\n  <code>${m.sha256.slice(0, 32)}…</code>\n  ${esc(defang(m.url)).slice(0, 90)}`).join("\n");
  }
  if (!s) return "⏳ El servidor todavía no ha enviado su primer resumen. Espera unos minutos.";
  if (c === "/estado") {
    const h = s.host || {}; const mal = (s.contenedores || []).filter((x) => x.estado !== "running" || x.salud === "unhealthy");
    const lineas = (s.contenedores || []).map((x) => `${x.estado !== "running" ? "🔴" : x.salud === "unhealthy" ? "🟠" : "🟢"} ${esc(x.nombre)}`);
    return `🖥 <b>Estado del servidor</b>\n\n` +
      `${mal.length ? "⚠️ " + mal.length + " contenedor(es) con problemas" : "✅ Todo funcionando"}\n` +
      `CPU (carga): <b>${h.carga5 ?? "?"}</b> / ${h.cpus ?? "?"} núcleos\nRAM: <b>${h.ram_pct ?? "?"}%</b> · Disco Docker: <b>${h.docker_pct ?? "?"}%</b> · Raíz: <b>${h.raiz_pct ?? "?"}%</b>\n` +
      `Elasticsearch: <b>${esc(s.es_estado || "?")}</b>\n\n${lineas.join("\n")}` + viejo;
  }
  const r = s.resumen24 || {};
  if (c === "/resumen") {
    return `📊 <b>Últimas 24 h</b>\n\n` +
      `Eventos: <b>${r.eventos ?? 0}</b> · IPs: <b>${r.ips ?? 0}</b> · Países: <b>${r.paises ?? 0}</b>\n` +
      `Graves (🟠/🔴): <b>${r.graves ?? 0}</b> · Credenciales probadas: <b>${r.credenciales ?? 0}</b>\n\n` +
      `<b>Por sensor</b>\n${(r.por_sensor || []).map((x) => `• ${esc(x.valor)}: ${x.n}`).join("\n") || "—"}\n\n` +
      `<b>Países</b>\n${(r.paises_top || []).map((x) => `${BANDERA(x.iso)} ${esc(x.valor)}: ${x.n}`).join("\n") || "—"}` + viejo;
  }
  if (c === "/ataques") {
    const l = r.ataques || [];
    if (!l.length) return "🛡 Sin ataques clasificados en las últimas 24 h." + viejo;
    return "🎯 <b>Ataques de las últimas 24 h</b>\n\n" + l.slice(0, 8).map((a) =>
      `${SEV[a.severidad] || ""} <b>${esc(a.nombre)}</b> — ${a.n} ev. · ${a.ips} IP\n` +
      `<i>${esc(a.tecnica_id || "")} ${esc(a.tecnica || "")}${a.cve ? " · " + esc(a.cve) : ""}</i>\n${esc((a.explicacion || "").slice(0, 280))}`).join("\n\n") + viejo;
  }
  if (c === "/ultimos") {
    const l = s.ultimos_graves || [];
    if (!l.length) return "🛡 Sin ataques graves recientes." + viejo;
    return "🚨 <b>Últimos ataques graves</b>\n\n" + l.slice(0, 10).map((e) =>
      `${SEV[e.severidad]?.slice(0, 2) || "•"} ${hace(e.fecha)} · ${BANDERA(e.pais_iso)} <code>${esc(e.ip)}</code>\n   ${esc(e.ataque)} · ${esc(e.sensor || "")}${e.detalle ? "\n   <code>" + esc(e.detalle).slice(0, 100) + "</code>" : ""}`).join("\n") + viejo;
  }
  if (c === "/top") {
    const f = (l) => (l || []).slice(0, 6).map((x) => `• <code>${esc(String(x.valor)).slice(0, 40)}</code> · ${x.n}`).join("\n") || "—";
    return `🏆 <b>Top 24 h</b>\n\n<b>IPs</b>\n${f(r.ips_top)}\n\n<b>Usuarios probados</b>\n${f(r.usuarios_top)}\n\n<b>Contraseñas probadas</b>\n${f(r.claves_top)}\n\n<b>Rutas web</b>\n${f(r.rutas_top)}` + viejo;
  }
  if (c === "/ip") {
    const ip = (args[0] || "").trim();
    if (!/^[0-9a-fA-F:.]{3,45}$/.test(ip)) return "Uso: /ip <code>1.2.3.4</code>";
    const d = (s.ips_detalle || {})[ip];
    if (!d) return `🔎 <code>${esc(ip)}</code> no aparece entre las IPs más activas de las últimas 24 h.` + viejo;
    return `🔎 <b>${esc(ip)}</b> ${BANDERA(d.pais_iso)} ${esc(d.pais || "")}${d.asn ? " · " + esc(d.asn) : ""}\n\n` +
      `Eventos: <b>${d.eventos}</b> · Primera vez: ${hace(d.primero)} · Última: ${hace(d.ultimo)}\n` +
      `Sensores: ${esc((d.sensores || []).join(", "))}\n\n<b>Ataques</b>\n${(d.ataques || []).map((a) => "• " + esc(a)).join("\n") || "—"}\n\n` +
      `<a href="https://www.abuseipdb.com/check/${encodeURIComponent(ip)}">AbuseIPDB</a> · <a href="https://www.shodan.io/host/${encodeURIComponent(ip)}">Shodan</a> · <a href="https://viz.greynoise.io/ip/${encodeURIComponent(ip)}">GreyNoise</a>` + viejo;
  }
  return "No conozco ese comando. /ayuda";
}

async function webhookTelegram(req, env) {
  if (!igual(req.headers.get("x-telegram-bot-api-secret-token") || "", env.TG_WEBHOOK_SECRET || "-")) return nada();
  const u = await req.json().catch(() => null);
  const m = u?.message;
  if (!m || !m.chat) return json({ ok: true });
  const st = estado(env), dueno = String(env.TG_CHAT_ID), chat = String(m.chat.id), quien = String(m.from?.id || "");
  const dest = await destino(env), esGrupo = ["group", "supergroup"].includes(m.chat.type);
  // El grupo vinculado pasó a supergrupo: seguir al ID nuevo
  if (m.migrate_to_chat_id && chat === dest) { await st.guardar("chat_destino", String(m.migrate_to_chat_id)); return json({ ok: true }); }
  if (m.migrate_from_chat_id && String(m.migrate_from_chat_id) === dest) { await st.guardar("chat_destino", chat); return json({ ok: true }); }
  // Vinculación automática: si todavía no hay grupo vinculado y el bot ve actividad en un grupo
  // donde el DUEÑO es creador o administrador, ese grupo pasa a ser el destino (no hace falta /vincular).
  if (esGrupo && dest === dueno && chat !== dueno) {
    const mb = await tg(env, "getChatMember", { chat_id: chat, user_id: Number(dueno) });
    if (mb.ok && ["creator", "administrator"].includes(mb.result?.status)) {
      await st.guardar("chat_destino", chat);
      await enviar(env, `✅ <b>Grupo vinculado automáticamente.</b>\nDesde ahora las alertas de Centinela llegan aquí (${esc(m.chat.title || "grupo")}) y ya no al privado.\nSi el grupo se convierte en supergrupo, el bot lo sigue solo. /ayuda`, {}, chat);
      if (typeof m.text !== "string" || !m.text.startsWith("/") || /^\/vincular\b/i.test(m.text)) return json({ ok: true });
      return webhookComando(env, m, chat, chat, quien === dueno);
    }
  }
  if (typeof m.text !== "string" || !m.text.startsWith("/")) return json({ ok: true });
  const cmd = m.text.trim().split(/\s+/)[0].split("@")[0].toLowerCase();
  const esDueno = quien === dueno;
  // Vincular / desvincular: SOLO el dueño
  if (cmd === "/vincular") {
    if (!esDueno) return json({ ok: true });
    if (!esGrupo) { await enviar(env, "Escribe /vincular <b>dentro del grupo</b> donde quieres recibir las alertas.", {}, chat); return json({ ok: true }); }
    await st.guardar("chat_destino", chat);
    await enviar(env, `✅ <b>Grupo vinculado.</b>\nDesde ahora las alertas de Centinela llegan aquí (${esc(m.chat.title || "grupo")}) y ya no al privado.\nSi el grupo se convierte en supergrupo, el bot lo sigue solo. /ayuda`, {}, chat);
    return json({ ok: true });
  }
  if (cmd === "/desvincular") {
    if (!esDueno) return json({ ok: true });
    await st.guardar("chat_destino", "");
    await enviar(env, "↩️ Grupo desvinculado: las alertas vuelven a tu chat privado.", {}, dueno);
    return json({ ok: true });
  }
  // ¿Quién puede usar comandos? El dueño por privado, y cualquier miembro del grupo vinculado
  const autorizado = (chat === dueno && esDueno) || (esGrupo && chat === dest);
  if (!autorizado) return json({ ok: true });
  return webhookComando(env, m, chat, dest, esDueno);
}

async function webhookComando(env, m, chat, dest, esDueno) {
  const cmd = m.text.trim().split(/\s+/)[0].split("@")[0].toLowerCase();
  if (["/silenciar", "/activar"].includes(cmd) && !esDueno) {
    await enviar(env, "🔒 Solo el administrador puede pausar o reanudar las alertas.", {}, chat); return json({ ok: true });
  }
  await enviar(env, await comando(env, m.text.slice(0, 200)), {}, chat);
  return json({ ok: true });
}

// ── Vigilancia: ¿el servidor sigue reportando? ───────────────────────
async function vigilar(env) {
  const st = estado(env); const s = await st.leer("snapshot"); const avisado = await st.leer("aviso_caido");
  if (!s) return;
  const min = (Date.now() - Date.parse(s.generado)) / 60000;
  if (min > SIN_REPORTE_MIN && !avisado) {
    await enviar(env, `🚨 <b>El servidor dejó de reportar</b>\nÚltimo resumen hace ${Math.round(min)} min.\nPuede ser el túnel de Cloudflare, el contenedor del vigía o el servidor completo. Revisa con el port knocking: <code>./knocking/ssh-honeypot.sh</code>`);
    await st.guardar("aviso_caido", Date.now());
  }
}

export default {
  async fetch(req, env) {
    const u = new URL(req.url);
    if (req.method !== "POST") return nada();
    if (!env.TG_TOKEN || !env.TG_CHAT_ID || !env.RELAY_KEY || !env.TG_WEBHOOK_SECRET) return nada();
    if (u.pathname === "/tg/webhook") return webhookTelegram(req, env);
    if (!u.pathname.startsWith("/v1/")) return nada();
    const crudo = await req.arrayBuffer();
    if (crudo.byteLength > 25 * 1024 * 1024) return json({ error: "demasiado grande" }, 413);
    if (!(await verificarServidor(req, env, u.pathname, crudo))) return nada();   // sin firma válida: como si no existiera
    try {
      if (u.pathname === "/v1/evento") return json(await evento(env, JSON.parse(new TextDecoder().decode(crudo))));
      if (u.pathname === "/v1/snapshot") {
        const s = JSON.parse(new TextDecoder().decode(crudo)); s.generado = new Date().toISOString();
        const st = estado(env);
        if (await st.leer("aviso_caido")) { await st.guardar("aviso_caido", 0); await enviar(env, "✅ <b>El servidor volvió a reportar.</b>"); }
        await st.guardar("snapshot", s); return json({ ok: true });
      }
      if (u.pathname === "/v1/muestra") return await muestra(env, JSON.parse(new TextDecoder().decode(crudo)));
      if (u.pathname === "/v1/archivo") {
        const form = await new Request(req.url, { method: "POST", headers: { "content-type": req.headers.get("content-type") }, body: crudo }).formData();
        return json(await archivo(env, form));
      }
    } catch (e) {
      console.log("error", u.pathname, e.message);
      return json({ error: "solicitud inválida" }, 400);
    }
    return nada();
  },
  async scheduled(_ev, env, ctx) { if (env.TG_TOKEN && env.TG_CHAT_ID) ctx.waitUntil(vigilar(env)); },
};
