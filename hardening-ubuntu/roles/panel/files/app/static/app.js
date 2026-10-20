/* Centinela · Centro de mando (frontend). Solo lectura.
   Las secciones se actualizan "en sitio": solo cambia lo que cambió (sin parpadeos). */
(function () {
  'use strict';
  var rango = '24h';
  var COLORES = ['#F97316', '#E94343', '#F59E0B', '#FB923C', '#FCA5A5', '#FDBA74', '#C2410C', '#9F1239', '#A78BFA', '#60A5FA'];
  var SEVC = { 0: '#64748B', 1: '#94A3B8', 2: '#F59E0B', 3: '#F97316', 4: '#E94343' };
  var SEVT = { 1: 'Baja', 2: 'Media', 3: 'Alta', 4: 'Crítica' };
  var NOMBRES = { cowrie: 'SSH / Telnet', dionaea: 'Multiprotocolo', conpot: 'ICS / SCADA', elasticpot: 'Elasticsearch', redishoneypot: 'Redis',
                  mailoney: 'SMTP', adbhoney: 'Android ADB', web: 'Web señuelo', wordpot: 'WordPress · blog.', honeyaml: 'API REST · api.',
                  citrixhoneypot: 'Citrix VPN · vpn.', log4pot: 'SAP / Log4j · sso.', h0neytr4p: 'Trampas de CVE', red: 'Sensores de red' };
  // [contenedor, tipo, ¿en internet?, descripción, dónde]
  var SENSORES = [
    ['hp-web', 'web', 1, 'Sitio y portal falsos de “Centinela Cloud”. Además es el gateway: registra la IP real y reparte el tráfico a los sensores web.', 'example.com · www.'],
    ['hp-wordpot', 'wordpot', 1, 'WordPress 5.8.1 falso (T-Pot). Captura logins, enumeración de usuarios y búsqueda de plugins vulnerables.', 'blog.example.com'],
    ['hp-honeyaml', 'honeyaml', 1, 'API REST falsa (T-Pot). Captura tokens robados, fuerza bruta y abuso de endpoints.', 'api.example.com'],
    ['hp-citrix', 'citrixhoneypot', 1, 'Portal NetScaler Gateway. Detecta la explotación de CVE-2019-19781 y captura credenciales de VPN.', 'vpn.example.com'],
    ['hp-log4pot', 'log4pot', 1, 'Portal SAP NetWeaver (Java). Detecta y desofusca intentos de Log4Shell (CVE-2021-44228).', 'sso.example.com'],
    ['hp-h0neytr4p', 'h0neytr4p', 1, 'Unas 40 trampas de CVEs y archivos expuestos; responde a rutas desconocidas del sitio principal.', 'rutas del sitio principal'],
    ['hp-cowrie', 'cowrie', 0, 'Terminal SSH/Telnet falsa: graba contraseñas, comandos y descargas.', 'sin exponer · espera el VPS señuelo'],
    ['hp-dionaea', 'dionaea', 0, 'SMB, FTP, MySQL, MSSQL, TFTP… captura binarios de gusanos.', 'sin exponer · espera el VPS señuelo'],
    ['hp-conpot', 'conpot', 0, 'Sistema industrial (medidor de tanques Guardian AST).', 'sin exponer · espera el VPS señuelo'],
    ['hp-elasticpot', 'elasticpot', 0, 'Elasticsearch falso: robo y secuestro de datos.', 'sin exponer · espera el VPS señuelo'],
    ['hp-redis', 'redishoneypot', 0, 'Redis sin contraseña: escritura de cron/llaves y mineros.', 'sin exponer · espera el VPS señuelo'],
    ['hp-mailoney', 'mailoney', 0, 'Servidor de correo abierto: spam y phishing.', 'sin exponer · espera el VPS señuelo'],
    ['hp-adbhoney', 'adbhoney', 0, 'Android Debug Bridge: botnets y mineros para TV boxes.', 'sin exponer · espera el VPS señuelo']];
  var TOPS = [['ips', 'IPs atacantes'], ['paises', 'Países'], ['asn', 'Redes (ASN)'], ['tecnicas', 'Técnicas MITRE ATT&CK'],
              ['usuarios', 'Usuarios probados'], ['claves', 'Contraseñas probadas'], ['comandos', 'Comandos ejecutados'], ['rutas', 'Rutas web atacadas']];
  var vistos = {}, firmas = {}, abiertas = {}, sensorAbierto = null;

  function $(id) { return document.getElementById(id); }
  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); }
  function num(n) { return Math.round(n || 0).toLocaleString('es-CO'); }
  function bytes(b) { var u = ['B', 'KB', 'MB', 'GB', 'TB'], i = 0; b = b || 0; while (b >= 1024 && i < 4) { b /= 1024; i++; } return b.toFixed(i ? 1 : 0) + ' ' + u[i]; }
  function bandera(iso) { return iso && iso.length === 2 ? String.fromCodePoint.apply(null, iso.toUpperCase().split('').map(function (c) { return 127397 + c.charCodeAt(0); })) : '🏳️'; }
  function hora(t) { if (!t) return '—'; var d = new Date(t); return d.toLocaleTimeString('es-CO', { hour12: false }) + (rango !== '1h' && rango !== '24h' ? ' ' + d.toLocaleDateString('es-CO', { day: '2-digit', month: '2-digit' }) : ''); }
  function hace(t) { if (!t) return 'sin eventos'; var s = (Date.now() - new Date(t)) / 1000; if (s < 60) return 'hace ' + Math.round(s) + ' s'; if (s < 3600) return 'hace ' + Math.round(s / 60) + ' min'; if (s < 86400) return 'hace ' + Math.round(s / 3600) + ' h'; return 'hace ' + Math.round(s / 86400) + ' d'; }
  function defang(u) { return String(u).replace(/^http/i, 'hxxp').replace(/\./g, '[.]'); }
  function api(ruta) { return fetch('/api/' + ruta + (ruta.indexOf('?') < 0 ? '?' : '&') + 'rango=' + rango, { credentials: 'same-origin' }).then(function (r) { if (!r.ok) throw new Error(r.status); return r.json(); }); }
  // Ejecuta "pintar" solo si los datos cambiaron desde la última vez
  function siCambio(clave, datos, pintar) { var f = JSON.stringify(datos); if (firmas[clave] === f) return; firmas[clave] = f; pintar(datos); }

  function contar(el, valor, fmt) {
    if (!el) return;
    var desde = Number(el.dataset.v || 0); fmt = fmt || num;
    if (desde === valor && el.textContent) return;
    var t0 = performance.now(); el.dataset.v = valor;
    if (desde !== valor && el.dataset.v0) { el.classList.remove('pulso'); void el.offsetWidth; el.classList.add('pulso'); }
    el.dataset.v0 = 1;
    (function paso(t) { var p = Math.min(1, (t - t0) / 800), e = 1 - Math.pow(1 - p, 3); el.textContent = fmt(desde + (valor - desde) * e); if (p < 1) requestAnimationFrame(paso); })(t0);
  }

  // ── Mapa (ECharts + contorno mundial alojado en el panel) ──
  var CASA = [-75.5138, 5.0703];
  var eMapa = echarts.init($('mapa'));
  var mapaListo = fetch('lib/world.json').then(function (r) { return r.json(); }).then(function (g) { echarts.registerMap('mundo', g); });
  var tip = { backgroundColor: 'rgba(17,17,36,.96)', borderColor: 'rgba(249,115,22,.35)', borderWidth: 1, padding: [10, 12], textStyle: { color: '#EEF0F6', fontSize: 12.5 },
              extraCssText: 'border-radius:12px;box-shadow:0 12px 30px rgba(0,0,0,.45)' };
  function pintarMapa(puntos) {
    mapaListo.then(function () {
      var max = Math.max.apply(null, puntos.map(function (p) { return p.n; }).concat([1]));
      var datos = puntos.map(function (p) {
        return { name: (p.ciudad ? p.ciudad + ', ' : '') + p.pais, value: [p.lon, p.lat, p.n], ips: p.ips, tile: p.tile, sev: p.sev,
                 itemStyle: { color: SEVC[p.sev] || '#E94343', shadowColor: SEVC[p.sev] || '#F97316' } };
      });
      var lineas = puntos.slice().sort(function (a, b) { return b.n - a.n; }).slice(0, 40).map(function (p) {
        return { coords: [[p.lon, p.lat], CASA], lineStyle: { color: SEVC[p.sev] || '#F97316' } };
      });
      eMapa.setOption({
        backgroundColor: 'transparent', animationDurationUpdate: 900, animationEasingUpdate: 'cubicOut',
        tooltip: Object.assign({ trigger: 'item', formatter: function (x) {
          if (x.seriesName === 'Sensores') return '<b>🛰 Sensores Centinela</b><br><span style="color:#9AA3B8">Todo el tráfico entra por Cloudflare<br>y llega al servidor por el túnel.</span>';
          if (x.seriesName === 'Orígenes') return '<b>' + esc(x.name) + '</b><br>' + num(x.value[2]) + ' eventos · ' + num(x.data.ips) + ' IP' + (x.data.ips === 1 ? '' : 's') +
            (x.data.sev ? '<br>Peor ataque: <b style="color:' + SEVC[x.data.sev] + '">' + SEVT[x.data.sev] + '</b>' : '') + '<br><span style="color:#FDBA74">Clic para ver el detalle →</span>';
          return '';
        } }, tip),
        geo: { map: 'mundo', roam: true, scaleLimit: { min: 1, max: 12 }, zoom: 1.15, center: [10, 15], silent: true,
               itemStyle: { areaColor: '#1a1a35', borderColor: '#2f2f55', borderWidth: 0.6 }, emphasis: { disabled: true } },
        series: [
          { name: 'Rutas', type: 'lines', coordinateSystem: 'geo', zlevel: 2, silent: true, data: lineas,
            effect: { show: true, period: 4, trailLength: 0.4, symbol: 'circle', symbolSize: 3, color: '#FDBA74' },
            lineStyle: { width: 1, opacity: 0.35, curveness: 0.25 } },
          { name: 'Orígenes', type: 'effectScatter', coordinateSystem: 'geo', zlevel: 3, data: datos, rippleEffect: { scale: 3.5, brushType: 'stroke' },
            symbolSize: function (v) { return 7 + 18 * Math.sqrt(v[2] / max); }, itemStyle: { shadowBlur: 12 }, cursor: 'pointer',
            emphasis: { scale: 1.6 } },
          { name: 'Sensores', type: 'effectScatter', coordinateSystem: 'geo', zlevel: 4, data: [{ name: 'Sensores', value: CASA.concat([0]) }],
            symbol: 'diamond', symbolSize: 13, rippleEffect: { scale: 5, color: '#22C55E' }, itemStyle: { color: '#22C55E', shadowBlur: 16, shadowColor: '#22C55E' } }
        ]
      });
      $('m-n').textContent = puntos.length ? puntos.length + ' orígenes · clic en un punto para ver qué hicieron' : 'sin orígenes en este rango';
    });
  }
  eMapa.on('click', function (p) { if (p.seriesName === 'Orígenes' && p.data && p.data.tile) abrirZona(p.data.tile, p.name); });

  // ── Cajón lateral: detalle de un punto del mapa ──
  function cerrarCajon() { document.body.classList.remove('cajon-abierto'); $('cajon').setAttribute('aria-hidden', 'true'); }
  $('cajon').addEventListener('click', function (e) { if (e.target.classList.contains('cajon-fondo') || e.target.closest('.cerrar')) cerrarCajon(); });
  document.addEventListener('keydown', function (e) { if (e.key === 'Escape') cerrarCajon(); });
  function abrirZona(tile, nombre) {
    $('cajon-c').innerHTML = '<div class="cargando"><i></i><i></i><i></i><span>Consultando el SIEM…</span></div>';
    document.body.classList.add('cajon-abierto'); $('cajon').setAttribute('aria-hidden', 'false');
    api('zona?tile=' + encodeURIComponent(tile)).then(function (z) {
      var c = '<header class="cz"><div class="cz-band">' + bandera(z.iso) + '</div><div><h3>' + esc(z.ciudad ? z.ciudad + ', ' : '') + esc(z.pais || nombre) + '</h3>' +
        '<small>' + num(z.eventos) + ' eventos · ' + num(z.ips.length) + ' IP' + (z.ips.length === 1 ? '' : 's') + ' · rango ' + esc(rango) + '</small></div></header>';
      if (z.ataques.length) {
        c += '<h4>Qué intentaron</h4>' + z.ataques.map(function (a) {
          return '<div class="cz-atq v' + a.severidad + '"><div class="cab"><b>' + esc(a.nombre) + '</b><span class="chip sev' + a.severidad + '">' + SEVT[a.severidad] + ' · ' + num(a.n) + '</span></div>' +
            '<div class="meta">' + (a.tecnica_id ? '<span class="chip mitre">' + esc(a.tecnica_id) + ' · ' + esc(a.tecnica || '') + '</span>' : '') + (a.cve ? '<span class="chip cve">' + esc(a.cve) + '</span>' : '') + '</div>' +
            '<p>' + esc(a.explicacion || '') + '</p>' + (a.recomendacion ? '<p class="rec">✅ ' + esc(a.recomendacion) + '</p>' : '') + '</div>';
        }).join('');
      }
      c += '<h4>Direcciones IP</h4>' + z.ips.map(function (i) {
        return '<div class="cz-ip"><div class="cab"><span class="sev-dot s' + (i.severidad || 1) + '"></span><code>' + esc(i.ip) + '</code><span class="n">' + num(i.eventos) + '</span></div>' +
          '<small>' + esc(i.asn || 'ASN desconocido') + (i.ciudad ? ' · ' + esc(i.ciudad) : '') + ' · primera ' + hace(i.primero) + ' · última ' + hace(i.ultimo) + '</small>' +
          '<div class="meta">' + i.ataques.map(function (a) { return '<span class="chip sev' + a.severidad + '">' + esc(a.nombre) + ' · ' + a.n + '</span>'; }).join('') +
          i.sensores.map(function (s) { return '<span class="chip">' + esc(NOMBRES[s] || s) + '</span>'; }).join('') + '</div>' +
          (i.ejemplos.length ? '<div class="ejs">' + i.ejemplos.map(function (e) { return '<code>' + esc(e.texto) + '</code>'; }).join('') + '</div>' : '') +
          '<div class="links"><a href="https://www.abuseipdb.com/check/' + encodeURIComponent(i.ip) + '" target="_blank" rel="noopener noreferrer">AbuseIPDB</a>' +
          '<a href="https://viz.greynoise.io/ip/' + encodeURIComponent(i.ip) + '" target="_blank" rel="noopener noreferrer">GreyNoise</a>' +
          '<a href="https://www.shodan.io/host/' + encodeURIComponent(i.ip) + '" target="_blank" rel="noopener noreferrer">Shodan</a></div></div>';
      }).join('');
      $('cajon-c').innerHTML = c;
    }).catch(function () { $('cajon-c').innerHTML = '<div class="vacio">No se pudo consultar el detalle.</div>'; });
  }

  // ── Gráficos ──
  var eSerie = echarts.init($('serie')), eDona = echarts.init($('dona')), eCf = echarts.init($('cf-serie'));
  var base = { backgroundColor: 'transparent', animationDurationUpdate: 700, textStyle: { color: '#9AA3B8', fontFamily: 'Inter, Segoe UI, sans-serif' },
               tooltip: Object.assign({ trigger: 'axis' }, tip) };
  var redim; window.addEventListener('resize', function () { clearTimeout(redim); redim = setTimeout(function () { [eSerie, eDona, eCf, eMapa].forEach(function (g) { g.resize(); }); }, 120); });

  function pintarSerie(datos) {
    var tipos = {};
    datos.forEach(function (d) { Object.keys(d).forEach(function (k) { if (k !== 't') tipos[k] = 1; }); });
    var lista = Object.keys(tipos);
    eSerie.setOption(Object.assign({}, base, {
      color: COLORES, grid: { left: 40, right: 16, top: 34, bottom: 30 },
      legend: { top: 0, type: 'scroll', textStyle: { color: '#9AA3B8' }, pageIconColor: '#F97316', data: lista.map(function (t) { return NOMBRES[t] || t; }) },
      xAxis: { type: 'time', axisLine: { lineStyle: { color: '#2a2a48' } }, splitLine: { show: false } },
      yAxis: { type: 'value', splitLine: { lineStyle: { color: 'rgba(255,255,255,.05)' } } },
      series: lista.map(function (t) {
        return { name: NOMBRES[t] || t, type: 'line', stack: 'x', smooth: true, symbol: 'none', areaStyle: { opacity: 0.35 }, lineStyle: { width: 1.5 },
                 data: datos.map(function (d) { return [d.t, d[t] || 0]; }) };
      })
    }), { replaceMerge: ['series'] });
  }
  function pintarDona(porHp) {
    eDona.setOption(Object.assign({}, base, {
      color: COLORES, tooltip: Object.assign({ trigger: 'item' }, tip),
      series: [{ type: 'pie', radius: ['52%', '78%'], itemStyle: { borderColor: '#0B0B16', borderWidth: 3, borderRadius: 6 },
                 label: { color: '#9AA3B8', formatter: '{b}\n{d}%' }, emphasis: { scaleSize: 6 },
                 data: porHp.map(function (h) { return { name: NOMBRES[h.tipo] || h.tipo, value: h.eventos }; }) }]
    }));
  }

  // ── Sensores (clic: se despliega el detalle) ──
  function pintarSensores(estado, res) {
    var cont = {}; (estado.contenedores || []).forEach(function (c) { cont[c.nombre] = c; });
    var ev = {}; (res.por_honeypot || []).forEach(function (h) { if (h.tipo !== 'web') ev[h.tipo] = h; });
    (res.por_sensor || []).forEach(function (h) { ev[h.tipo] = h; });
    var filas = SENSORES.map(function (s) {
      var c = cont[s[0]] || {}, e = ev[s[1]] || {}, ok = c.estado === 'running' && c.salud !== 'unhealthy';
      return { id: s[0], clase: c.estado ? (ok ? 'ok' : 'mal') : '', nombre: (NOMBRES[s[1]] || s[1]) + (s[2] ? ' 🌐' : ''),
               sub: (c.estado ? (ok ? (s[2] ? 'en internet' : 'activo, sin exponer') : c.estado) : 'sin datos') + ' · ' + hace(e.ultimo),
               n: e.eventos || 0, desc: s[3], donde: s[4], detalle: c.detalle || '', imagen: c.imagen || '' };
    });
    filas.push({ id: 'cloudflared', clase: (cont.cloudflared || {}).estado === 'running' ? 'ok' : 'mal', nombre: 'Túnel Cloudflare', sub: 'cloudflared · única entrada y salida', n: '⇅',
                 desc: 'Conexión saliente hacia Cloudflare: publica los sensores y las consolas sin abrir puertos en la IP de la institución.', donde: 'red edge 10.213.250.10', detalle: (cont.cloudflared || {}).detalle || '' });
    filas.push({ id: 'vigia', clase: (cont.vigia || {}).estado === 'running' ? 'ok' : (cont.vigia ? 'mal' : ''), nombre: 'Vigía → Telegram', sub: 'alertas firmadas vía Cloudflare', n: '✈',
                 desc: 'Revisa ataques graves, honeytokens, salud y accesos cada minuto y te avisa por el bot privado.', donde: 'red edge 10.213.250.12', detalle: (cont.vigia || {}).detalle || '' });
    var caja = $('sensores');
    filas.forEach(function (f) {
      var el = caja.querySelector('[data-id="' + f.id + '"]');
      if (!el) {
        el = document.createElement('div'); el.className = 'sensor'; el.dataset.id = f.id; el.tabIndex = 0;
        el.innerHTML = '<div class="fila-s"><i></i><div class="tx"><b></b><small></small></div><span class="n"></span><span class="flecha">›</span></div><div class="det"><div class="det-in"><p></p><dl></dl></div></div>';
        caja.appendChild(el);
      }
      el.querySelector('i').className = f.clase; el.querySelector('b').textContent = f.nombre; el.querySelector('small').textContent = f.sub;
      el.querySelector('.n').textContent = typeof f.n === 'number' ? num(f.n) : f.n; el.querySelector('.det p').textContent = f.desc;
      el.querySelector('dl').innerHTML = '<dt>Dónde</dt><dd>' + esc(f.donde) + '</dd>' + (f.detalle ? '<dt>Estado</dt><dd>' + esc(f.detalle) + '</dd>' : '') +
        (f.imagen ? '<dt>Imagen</dt><dd class="mono">' + esc(f.imagen) + '</dd>' : '');
      el.classList.toggle('abierto', sensorAbierto === f.id);
    });
  }
  $('sensores').addEventListener('click', function (e) {
    var s = e.target.closest('.sensor'); if (!s) return;
    sensorAbierto = sensorAbierto === s.dataset.id ? null : s.dataset.id;
    $('sensores').querySelectorAll('.sensor').forEach(function (x) { x.classList.toggle('abierto', x.dataset.id === sensorAbierto); });
  });
  $('sensores').addEventListener('keydown', function (e) { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); e.target.click(); } });

  // ── Flujo en vivo ──
  function detalle(e) {
    var h = e.honeypot || {};
    if (h.password) return '🔑 ' + esc((e.user || {}).name || '?') + ' / <span class="mono">' + esc(h.password) + '</span>';
    if (h.command) return '⌘ <span class="mono">' + esc(h.command) + '</span>';
    if (e.url && e.url.path) return esc(((e.http || {}).request || {}).method || 'GET') + ' <span class="mono">' + esc((e.url.domain && e.url.domain !== 'example.com' ? e.url.domain : '') + e.url.path) + '</span>';
    return esc((e.event || {}).action || '');
  }
  function pintarFeed(evs) {
    var tb = $('feed').querySelector('tbody'), nuevos = {}, primera = !Object.keys(vistos).length;
    tb.innerHTML = evs.map(function (e) {
      var s = e.source || {}, g = s.geo || {}, id = e['@timestamp'] + (s.ip || '') + (((e.event || {}).action) || '') + ((e.url || {}).path || '');
      var cls = (vistos[id] || primera) ? '' : ' class="nuevo"'; nuevos[id] = 1;
      var h = e.honeypot || {}, sen = (h.type === 'web' && h.sensor) ? h.sensor : h.type, at = e.ataque || {};
      return '<tr' + cls + '><td>' + hora(e['@timestamp']) + '</td><td class="c-sen"><span class="chip">' + esc(NOMBRES[sen] || sen) + '</span></td>' +
        '<td class="mono">' + esc(s.ip || '—') + '</td><td class="c-pais">' + bandera(g.country_iso_code) + ' ' + esc(g.country_name || '') + '</td><td>' +
        (at.nombre ? '<span class="sev-dot s' + (at.severidad || 1) + '"></span>' + esc(at.nombre) + (h.honeytoken ? ' 🪤' : '') : '<span style="color:var(--dim)">—</span>') +
        '</td><td class="c-det">' + detalle(e) + '</td></tr>';
    }).join('') || '<tr><td colspan="6" class="vacio">Sin eventos en este rango.</td></tr>';
    vistos = nuevos;
  }

  // ── Tops ──
  $('tops').innerHTML = TOPS.map(function (t) { return '<article class="panel"><h2>' + t[1] + '</h2><ol class="lista" id="top-' + t[0] + '"></ol></article>'; }).join('');
  function pintarTop(id, filas) {
    var max = Math.max.apply(null, filas.map(function (f) { return f.n; }).concat([1])), ol = $(id);
    if (!filas.length) { ol.innerHTML = '<li class="vacio">Sin datos todavía</li>'; return; }
    if (ol.children.length !== filas.length || ol.querySelector('.vacio')) {
      ol.innerHTML = filas.map(function () { return '<li><span class="v mono"></span><span class="c"></span><span class="barra-n"><i style="width:0"></i></span></li>'; }).join('');
    }
    filas.forEach(function (f, i) {
      var li = ol.children[i]; li.querySelector('.v').textContent = f.valor; li.querySelector('.v').title = f.valor;
      li.querySelector('.c').textContent = num(f.n);
      requestAnimationFrame(function () { li.querySelector('i').style.width = (100 * f.n / max) + '%'; });
    });
  }

  // ── Ataques explicados (actualización en sitio, sin parpadeo) ──
  function htmlAtaque(a) {
    return '<div class="cab"><h4>' + esc(a.nombre) + '</h4><span class="n"></span></div>' +
      '<div class="meta"><span class="chip sev' + a.severidad + '">' + SEVT[a.severidad] + '</span>' + (a.cve ? '<span class="chip cve">' + esc(a.cve) + '</span>' : '') +
      (a.tecnica_id ? '<span class="chip mitre" title="' + esc(a.tactica || '') + '">' + esc(a.tecnica_id) + ' · ' + esc(a.tecnica || '') + '</span>' : '') +
      '<span class="chip">' + esc(a.categoria || '') + '</span></div>' +
      '<p>' + esc(a.explicacion || '') + '</p>' +
      '<div class="mas"><div class="mas-in">' + (a.ejemplo ? '<b>Ejemplo real</b><code class="ej mono">' + esc(a.ejemplo) + '</code>' : '') +
      '<b>Qué hacer</b><p>' + esc(a.recomendacion || '') + '</p>' +
      '<p class="fuente">Táctica MITRE: <em>' + esc(a.tactica || '—') + '</em> · Sensores: ' + esc((a.sensores || []).map(function (x) { return NOMBRES[x] || x; }).join(', ')) +
      ' · Regla: ' + esc(a.fuente || '') + '</p></div></div><div class="pie"><span class="pie-i"></span><span class="pie-t"></span></div>';
  }
  function pintarAtaques(lista, res) {
    var ps = res.por_severidad || {}, tot = 0; [1, 2, 3, 4].forEach(function (k) { tot += ps[k] || 0; });
    var barra = $('sev-barra');
    if (!barra.children.length) barra.innerHTML = [1, 2, 3, 4].map(function (k) { return '<i class="s' + k + '" style="width:0"></i>'; }).join('');
    [1, 2, 3, 4].forEach(function (k, i) { var el = barra.children[i]; el.style.width = (tot ? 100 * (ps[k] || 0) / tot : 0) + '%'; el.title = SEVT[k] + ': ' + num(ps[k] || 0); });
    $('a-n').textContent = lista.length ? lista.length + ' tipos · clic en una tarjeta para ver el detalle' : '';
    var caja = $('ataques'), ids = {};
    if (!lista.length) { caja.innerHTML = '<div class="vacio">Sin ataques clasificados en este rango.</div>'; return; }
    var vacio = caja.querySelector('.vacio'); if (vacio) vacio.remove();
    lista.forEach(function (a, i) {
      ids[a.id] = 1;
      var el = caja.querySelector('.atq[data-id="' + CSS.escape(a.id) + '"]'), firma = JSON.stringify([a.nombre, a.severidad, a.cve, a.tecnica_id, a.categoria, a.explicacion, a.ejemplo, a.recomendacion, a.sensores]);
      if (!el) { el = document.createElement('div'); el.dataset.id = a.id; el.className = 'atq entra'; (function (x) { setTimeout(function () { x.classList.remove('entra'); }, 600); })(el); }
      if (el.dataset.f !== firma) { el.innerHTML = htmlAtaque(a); el.dataset.f = firma; }
      el.classList.remove('v1', 'v2', 'v3', 'v4'); el.classList.add('v' + a.severidad); el.classList.toggle('abierta', !!abiertas[a.id]);
      contar(el.querySelector('.n'), a.eventos);
      el.querySelector('.pie-i').textContent = num(a.ips) + ' IP' + (a.ips === 1 ? '' : 's') + ' · ' + (a.paises || []).map(bandera).join(' ');
      el.querySelector('.pie-t').textContent = hace(a.ultimo);
      if (caja.children[i] !== el) caja.insertBefore(el, caja.children[i] || null);
    });
    Array.prototype.slice.call(caja.querySelectorAll('.atq')).forEach(function (el) { if (!ids[el.dataset.id]) el.remove(); });
  }
  $('ataques').addEventListener('click', function (ev) {
    var c = ev.target.closest('.atq'); if (!c || ev.target.closest('code')) return;
    c.classList.toggle('abierta'); abiertas[c.dataset.id] = c.classList.contains('abierta');
  });

  // ── Muestras ──
  function pintarMuestras(l) {
    $('muestras').querySelector('tbody').innerHTML = l.map(function (e) {
      var s = e.source || {}, h = e.honeypot || {}, a = e.ataque || {};
      var q = h.file_hash ? '<span class="mono">#' + esc(h.file_hash) + '</span>' : '';
      var u = (a.urls || []).map(function (x) { return '<span class="mono url-mal">' + esc(defang(x)) + '</span>'; }).join('<br>');
      return '<tr><td>' + hora(e['@timestamp']) + '</td><td>' + bandera((s.geo || {}).country_iso_code) + ' <span class="mono">' + esc(s.ip || '') + '</span></td><td>' + esc(a.nombre || '') +
        '</td><td class="ajusta">' + [q, u].filter(Boolean).join('<br>') + '</td></tr>';
    }).join('') || '<tr><td colspan="4" class="vacio">Aún no se ha capturado malware en este rango.</td></tr>';
  }

  // ── Cloudflare ──
  function pintarCf(cf) {
    contar($('cf-req'), cf.solicitudes); contar($('cf-thr'), cf.amenazas); contar($('cf-cache'), cf.cache); contar($('cf-bytes'), cf.bytes, bytes);
    siCambio('cf-serie', cf.serie, function () {
      eCf.setOption(Object.assign({}, base, {
        color: ['#F97316', '#E94343'], grid: { left: 44, right: 12, top: 28, bottom: 28 }, legend: { top: 0, textStyle: { color: '#9AA3B8' } },
        xAxis: { type: 'time', axisLine: { lineStyle: { color: '#2a2a48' } } }, yAxis: { type: 'value', splitLine: { lineStyle: { color: 'rgba(255,255,255,.05)' } } },
        series: [{ name: 'Solicitudes', type: 'bar', data: cf.serie.map(function (d) { return [d.t, d.req]; }), itemStyle: { borderRadius: [4, 4, 0, 0] } },
                 { name: 'Amenazas', type: 'line', smooth: true, data: cf.serie.map(function (d) { return [d.t, d.thr]; }) }]
      }));
    });
    siCambio('cf-paises', cf.paises, function (d) { pintarTop('cf-paises', d); });
    siCambio('cf-ev', cf.eventos, function () {
      $('cf-ev').querySelector('tbody').innerHTML = (cf.eventos || []).map(function (e) {
        var c = e.cf || {};
        return '<tr><td>' + hora(e['@timestamp']) + '</td><td><span class="chip">' + esc(c.kind) + '</span></td><td>' + esc(c.action || (c.allowed === false ? 'bloqueado' : c.allowed ? 'permitido' : '')) +
          '</td><td class="mono">' + esc((e.source || {}).ip || c.user_email || '') + ' ' + bandera(c.country) + '</td><td class="mono">' + esc((c.host || c.app || '') + (c.path || '')) + '</td></tr>';
      }).join('') || '<tr><td colspan="5" class="vacio">Sin eventos de Cloudflare en este rango.</td></tr>';
    });
  }

  // ── Servidor ──
  function pintarHost(h) {
    if (!h || !h.ram_total) { $('host').innerHTML = '<div class="vacio">Sin datos del servidor.</div>'; return; }
    var m = [['CPU (carga 5 min)', h.carga5 + ' / ' + h.cpus, 100 * h.carga5 / h.cpus], ['Memoria', bytes(h.ram_usada) + ' / ' + bytes(h.ram_total), 100 * h.ram_usada / h.ram_total],
             ['Disco Docker', bytes(h.docker_usado) + ' / ' + bytes(h.docker_total), 100 * h.docker_usado / h.docker_total], ['Disco sistema', bytes(h.raiz_usado) + ' / ' + bytes(h.raiz_total), 100 * h.raiz_usado / h.raiz_total]];
    var caja = $('host');
    if (caja.children.length !== 4) caja.innerHTML = m.map(function () { return '<div class="medidor"><span></span><b></b><div class="pista"><i style="width:0"></i></div></div>'; }).join('');
    m.forEach(function (x, i) {
      var d = caja.children[i]; d.querySelector('span').textContent = x[0]; d.querySelector('b').textContent = x[1];
      d.querySelector('i').style.width = Math.min(100, x[2]).toFixed(1) + '%'; d.classList.toggle('alto', x[2] > 85);
    });
  }

  // ── Ciclo de actualización ──
  var ocupado = false;
  function actualizar() {
    if (ocupado || document.hidden) return; ocupado = true;
    Promise.all([api('resumen'), api('serie'), api('mapa'), api('feed?n=40'), api('estado'), api('cloudflare'), api('ataques'), api('muestras')].concat(TOPS.map(function (t) { return api('top?campo=' + t[0]); })))
      .then(function (r) {
        var res = r[0];
        contar($('k-eventos'), res.eventos); contar($('k-ips'), res.ips); contar($('k-paises'), res.paises); contar($('k-creds'), res.credenciales); contar($('k-cmds'), res.comandos);
        contar($('k-graves'), res.graves); $('k-graves-d').textContent = num(res.criticos) + ' críticos · ' + num(res.honeytokens) + ' honeytokens';
        pintarAtaques(r[6], res);
        siCambio('muestras', r[7], pintarMuestras);
        siCambio('serie', r[1], pintarSerie);
        siCambio('dona', res.por_honeypot, pintarDona);
        siCambio('mapa', r[2], pintarMapa);
        siCambio('feed', r[3], pintarFeed);
        pintarSensores(r[4], res); pintarCf(r[5]); pintarHost(r[4].host);
        TOPS.forEach(function (t, i) { siCambio('top-' + t[0], r[8 + i], function (d) { pintarTop('top-' + t[0], d); }); });
        document.querySelector('.vivo').classList.remove('err'); $('vivo-txt').textContent = 'En vivo · ' + new Date().toLocaleTimeString('es-CO', { hour12: false });
        document.body.classList.remove('cargando-ini');
      })
      .catch(function () { document.querySelector('.vivo').classList.add('err'); $('vivo-txt').textContent = 'Sin conexión con el SIEM'; })
      .then(function () { ocupado = false; });
  }
  document.querySelectorAll('#rango button').forEach(function (b) {
    b.addEventListener('click', function () {
      document.querySelectorAll('#rango button').forEach(function (x) { x.classList.remove('act'); }); b.classList.add('act');
      rango = b.dataset.r; vistos = {}; firmas = {}; actualizar();
    });
  });
  document.addEventListener('visibilitychange', function () { if (!document.hidden) actualizar(); });
  fetch('/api/yo').then(function (r) { return r.json(); }).then(function (y) { $('yo').textContent = y.correo || ''; }).catch(function () {});
  actualizar(); setInterval(actualizar, 15000);
})();
