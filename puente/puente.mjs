// Heimdall · Puente PRTG
// Corre en una PC de la red que llega a PRTG. Cada 5 s (INTERVALO_SEGUNDOS) hace UNA consulta de solo lectura
// (sensores con problema) y publica el estado cifrado para el mapa:
//   - GET /eventos  flujo en vivo (Server-Sent Events)
//   - GET /estado   último estado
// Se expone a internet con un túnel de Cloudflare y anuncia su dirección, cifrada, en ntfy.sh.
// Sin dependencias: Node.js 20 o superior.

import { spawn } from "node:child_process";
import dns from "node:dns/promises";
import { appendFileSync, existsSync, readFileSync, renameSync, statSync, writeFileSync } from "node:fs";
import http from "node:http";
import https from "node:https";
import path from "node:path";
import { fileURLToPath } from "node:url";

const DIR = path.dirname(fileURLToPath(import.meta.url));
try { process.loadEnvFile(path.join(DIR, ".env")); } catch { /* sin .env */ }

const CFG = {
  prtgUrl: (process.env.PRTG_URL ?? "https://168.196.125.68").replace(/\/$/, ""),
  prtgUsuario: process.env.PRTG_USUARIO ?? "",
  prtgPassword: process.env.PRTG_PASSWORD ?? "",
  sitio: (process.env.HEIMDALL_SITIO ?? "https://demberos.github.io").replace(/\/$/, ""),
  usuario: process.env.HEIMDALL_USUARIO ?? "",
  contrasena: process.env.HEIMDALL_CONTRASENA ?? "",
  intervalo: Math.max(1, Number(process.env.INTERVALO_SEGUNDOS ?? 5)) * 1000,
  puerto: Number(process.env.PUERTO ?? 8787),
  cloudflared: process.env.CLOUDFLARED ?? (existsSync(path.join(DIR, "cloudflared.exe")) ? path.join(DIR, "cloudflared.exe") : "cloudflared"),
  sinTunel: process.env.SIN_TUNEL === "1",
  ntfy: process.env.NTFY ?? "https://ntfy.sh",
  // id de la carpeta de Drive con los backups de los switches (compartida por enlace). Vacío = no se lee
  driveRespaldos: (process.env.DRIVE_RESPALDOS ?? "").replace(/^.*folders\//, "").replace(/[?#].*$/, "").trim(),
};
const ORIGENES = new Set([CFG.sitio, "http://localhost:3000", "http://localhost:4000"]);

// ---------- Registro ----------
const LOG = path.join(DIR, "puente.log");
function log(...partes) {
  const linea = `${new Date().toISOString()} ${partes.join(" ")}`;
  console.log(linea);
  try {
    if (existsSync(LOG) && statSync(LOG).size > 5 * 1024 * 1024) writeFileSync(LOG, "");
    appendFileSync(LOG, linea + "\n");
  } catch { /* sin registro en disco */ }
}

// ---------- Cifrado (igual que src/lib/cifrado.ts y src/lib/canal.ts) ----------
const enc = new TextEncoder();
const dec = new TextDecoder();
const b64 = (u) => Buffer.from(u).toString("base64");
const deb64 = (s) => new Uint8Array(Buffer.from(s, "base64"));
const { subtle } = globalThis.crypto;

async function abrirClave(paquete, usuario, contrasena) {
  const h = await subtle.digest("SHA-256", enc.encode(`heimdall:${usuario.trim().toLowerCase()}`));
  const e = paquete.usuarios.find((x) => x.id === b64(new Uint8Array(h)));
  if (!e) return null;
  const base = await subtle.importKey("raw", enc.encode(contrasena), "PBKDF2", false, ["deriveKey"]);
  const kek = await subtle.deriveKey({ name: "PBKDF2", hash: "SHA-256", salt: deb64(e.salt), iterations: paquete.iteraciones },
    base, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
  try {
    return b64(new Uint8Array(await subtle.decrypt({ name: "AES-GCM", iv: deb64(e.iv) }, kek, deb64(e.clave))));
  } catch {
    return null;
  }
}

async function derivarCanal(claveB64) {
  const base = await subtle.importKey("raw", deb64(claveB64), "HKDF", false, ["deriveKey", "deriveBits"]);
  const clave = await subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt: enc.encode("heimdall-estado"), info: enc.encode("v1") },
    base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  const bits = await subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: enc.encode("heimdall-canal"), info: enc.encode("v1") }, base, 160);
  return { topico: `hmdl-${Buffer.from(bits).toString("hex")}`, clave };
}

async function cifrarMensaje(canal, obj) {
  const stream = new Blob([enc.encode(JSON.stringify(obj))]).stream().pipeThrough(new CompressionStream("deflate-raw"));
  const comprimido = new Uint8Array(await new Response(stream).arrayBuffer());
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv }, canal.clave, comprimido));
  return b64(Buffer.concat([iv, ct]));
}

// ---------- PRTG (solo lectura) ----------
const agente = new https.Agent({ rejectUnauthorized: false, keepAlive: true, maxSockets: 1 });
let passhash = process.env.PRTG_PASSHASH ?? "";

function obtener(url, { inseguro = false, timeout = 20000 } = {}) {
  return new Promise((resolve, reject) => {
    const mod = url.startsWith("https:") ? https : http;
    const req = mod.get(url, { agent: inseguro && mod === https ? agente : undefined, timeout }, (res) => {
      let cuerpo = "";
      res.setEncoding("utf8");
      res.on("data", (d) => (cuerpo += d));
      res.on("end", () => (res.statusCode && res.statusCode < 400 ? resolve(cuerpo) : reject(new Error(`HTTP ${res.statusCode}`))));
    });
    req.on("timeout", () => req.destroy(new Error("tiempo de espera agotado")));
    req.on("error", reject);
  });
}

async function prtg(ruta, params) {
  if (!passhash) {
    const q = new URLSearchParams({ username: CFG.prtgUsuario, password: CFG.prtgPassword });
    passhash = (await obtener(`${CFG.prtgUrl}/api/getpasshash.htm?${q}`, { inseguro: true })).trim();
    if (!/^\d+$/.test(passhash)) { passhash = ""; throw new Error("PRTG rechazó el usuario o la contraseña"); }
  }
  const q = new URLSearchParams(params);
  q.set("username", CFG.prtgUsuario);
  q.set("passhash", passhash);
  try {
    return JSON.parse(await obtener(`${CFG.prtgUrl}${ruta}?${q}`, { inseguro: true }));
  } catch (e) {
    if (/HTTP 401/.test(String(e))) passhash = "";
    throw e;
  }
}

const limpiar = (s) => String(s ?? "").replace(/<[^>]+>/g, "").replace(/&nbsp;/g, " ").replace(/&amp;/g, "&").replace(/\s+/g, " ").trim();
let equipos = [];
let equiposEn = 0;

async function leerEquipos() {
  const r = await prtg("/api/table.json", { content: "devices", columns: "objid,device,host,group,status_raw", count: "2000" });
  equipos = (r.devices ?? []).map((d) => ({ id: d.objid, n: limpiar(d.device), ip: limpiar(d.host), g: limpiar(d.group), s: d.status_raw }));
  equiposEn = Date.now();
}

async function leerAlertas() {
  // Una sola consulta: solo sensores en Advertencia (4), Caído (5), Caído reconocido (13) o Caído parcial (14)
  const q = new URLSearchParams({ content: "sensors", columns: "objid,parentid,sensor,type,status_raw,message,downtimesince", count: "2500" });
  for (const s of [4, 5, 13, 14]) q.append("filter_status", String(s));
  const r = await prtg("/api/table.json", q);
  return (r.sensors ?? []).map((s) => ({
    id: s.objid, eq: s.parentid, sn: limpiar(s.sensor), t: limpiar(s.type), s: s.status_raw, m: limpiar(s.message), d: limpiar(s.downtimesince),
  }));
}

// ---------- Servicios de internet (páginas de estado oficiales + pruebas desde esta red) ----------
// No toca PRTG. Fuentes oficiales cada 2 min; prueba DNS + HTTPS a cada servicio cada 60 s.

const CATALOGO = [
  // id, nombre, importante, host a probar
  ["google", "Google", true, "www.google.com"],
  ["youtube", "YouTube", true, "www.youtube.com"],
  ["whatsapp", "WhatsApp", true, "web.whatsapp.com"],
  ["facebook", "Facebook", true, "www.facebook.com"],
  ["instagram", "Instagram", true, "www.instagram.com"],
  ["messenger", "Messenger", false, "www.messenger.com"],
  ["gworkspace", "Gmail y Google Workspace", true, "mail.google.com"],
  ["netflix", "Netflix", true, "www.netflix.com"],
  ["tiktok", "TikTok", true, "www.tiktok.com"],
  ["microsoft", "Microsoft y Azure", true, "www.microsoft.com"],
  ["outlook", "Outlook", false, "outlook.live.com"],
  ["cloudflare", "Cloudflare", true, "www.cloudflare.com"],
  ["aws", "Amazon Web Services", true, "aws.amazon.com"],
  ["amazon", "Amazon", false, "www.amazon.com"],
  ["apple", "Apple e iCloud", false, "www.icloud.com"],
  ["gcloud", "Google Cloud", false, "cloud.google.com"],
  ["x", "X (Twitter)", false, "x.com"],
  ["spotify", "Spotify", false, "open.spotify.com"],
  ["discord", "Discord", false, "discord.com"],
  ["zoom", "Zoom", false, "zoom.us"],
  ["openai", "ChatGPT", false, "chatgpt.com"],
  ["github", "GitHub", false, "github.com"],
  ["reddit", "Reddit", false, "www.reddit.com"],
  ["dropbox", "Dropbox", false, "www.dropbox.com"],
];
const STATUSPAGE = {
  cloudflare: "https://www.cloudflarestatus.com", discord: "https://discordstatus.com", github: "https://www.githubstatus.com",
  zoom: "https://www.zoomstatus.com", openai: "https://status.openai.com", reddit: "https://www.redditstatus.com", dropbox: "https://status.dropbox.com",
};
const oficial = new Map(); // id -> { s: "menor"|"mayor", det, desde, url }
const pruebas = new Map(); // id -> { ok, ms, err }
let serviciosTs = "";

const NIVEL = { menor: 1, mayor: 2 };
const peor = (a, b) => (!a ? b : !b ? a : NIVEL[b.s] > NIVEL[a.s] ? b : a);
const corto = (t, n = 180) => { const x = limpiar(t); return x.length > n ? x.slice(0, n - 1) + "…" : x; };

async function traer(url, como = "json") {
  const r = await fetch(url, { signal: AbortSignal.timeout(15000), headers: { "User-Agent": "Mozilla/5.0 Heimdall-NOC" } });
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  if (como === "json") return r.json();
  const b = new Uint8Array(await r.arrayBuffer());
  if (b[0] === 0xff && b[1] === 0xfe) return new TextDecoder("utf-16le").decode(b.subarray(2));
  if (b[0] === 0xfe && b[1] === 0xff) return new TextDecoder("utf-16be").decode(b.subarray(2));
  return new TextDecoder().decode(b);
}

async function leerOficiales() {
  const nuevo = new Map();
  // Eventos abiertos hace más de 3 días (AWS deja algunos meses) no cuentan como falla actual
  const marcar = (id, e) => { if (!(Date.parse(e.desde) < Date.now() - 3 * 864e5)) nuevo.set(id, peor(nuevo.get(id), e)); };
  const tareas = [];

  // Google Workspace y Google Cloud: incidentes sin "end" están activos
  const google = (url, id, pagina) => tareas.push(traer(url).then((lista) => {
    for (const i of lista) {
      if (i.end) continue;
      const s = /high/i.test(i.severity ?? "") || /outage/i.test(i.status_impact ?? "") ? "mayor" : "menor";
      const prod = i.service_name ?? i.affected_products?.map((p) => p.title).join(", ") ?? "";
      marcar(id, { s, det: corto(`${prod}: ${i.most_recent_update?.text ?? i.external_desc ?? ""}`), desde: i.begin ?? "", url: pagina });
    }
  }));
  google("https://www.google.com/appsstatus/dashboard/incidents.json", "gworkspace", "https://www.google.com/appsstatus/dashboard/");
  google("https://status.cloud.google.com/incidents.json", "gcloud", "https://status.cloud.google.com/");

  // Statuspage (Cloudflare, Discord, GitHub, Zoom, OpenAI, Reddit, Dropbox)
  for (const [id, base] of Object.entries(STATUSPAGE)) tareas.push(traer(`${base}/api/v2/summary.json`).then((j) => {
    const inc = (j.incidents ?? []).filter((i) => i.status !== "resolved" && i.status !== "postmortem");
    const ind = j.status?.indicator ?? "none";
    if (!inc.length && (ind === "none" || ind === "maintenance")) return;
    // Se juzga por los incidentes: el indicador general de páginas grandes (Cloudflare) casi siempre marca alguna región
    const s = inc.some((i) => i.impact === "major" || i.impact === "critical") ? "mayor" : "menor";
    marcar(id, { s, det: corto(inc[0]?.name ?? j.status?.description ?? ""), desde: inc[0]?.started_at ?? inc[0]?.created_at ?? "", url: base });
  }));

  // AWS: eventos actuales (UTF-16)
  tareas.push(traer("https://health.aws.amazon.com/public/currentevents", "texto").then((t) => {
    const ev = JSON.parse(t.trim() || "[]");
    const activos = (Array.isArray(ev) ? ev : []).filter((e) => String(e.status ?? "1") !== "0");
    if (activos.length) marcar("aws", { s: activos.some((e) => String(e.status) === "3") ? "mayor" : "menor",
      det: corto(`${activos[0].service_name ?? activos[0].service ?? ""}: ${activos[0].summary ?? ""}`), desde: activos[0].date ? new Date(Number(activos[0].date) * 1000).toISOString() : "", url: "https://health.aws.amazon.com/health/status" });
  }));

  // Apple
  tareas.push(traer("https://www.apple.com/support/systemstatus/data/system_status_en_US.js", "texto").then((t) => {
    const j = JSON.parse(t.slice(t.indexOf("{"), t.lastIndexOf("}") + 1));
    for (const sv of j.services ?? []) for (const e of sv.events ?? []) {
      if (e.eventStatus !== "ongoing" || /maintenance/i.test(e.statusType ?? "")) continue;
      marcar("apple", { s: /outage/i.test(e.statusType ?? "") ? "mayor" : "menor", det: corto(`${sv.serviceName}: ${e.message ?? e.statusType ?? ""}`), desde: e.startDate ?? "", url: "https://www.apple.com/support/systemstatus/" });
    }
  }));

  // Azure (RSS: cada <item> es un incidente activo)
  tareas.push(traer("https://azure.status.microsoft/en-us/status/feed/", "texto").then((t) => {
    const items = [...t.matchAll(/<item>[\s\S]*?<title>([\s\S]*?)<\/title>[\s\S]*?(?:<pubDate>([\s\S]*?)<\/pubDate>)?[\s\S]*?<\/item>/g)];
    if (items.length) marcar("microsoft", { s: "mayor", det: corto(items[0][1].replace(/<!\[CDATA\[|\]\]>/g, "")), desde: items[0][2] ? new Date(items[0][2]).toISOString() : "", url: "https://azure.status.microsoft/" });
  }));

  // Meta (plataformas de WhatsApp, Messenger, Instagram y Facebook)
  tareas.push(traer("https://metastatus.com/data/orgs.json").then((j) => {
    const productos = [];
    const recorrer = (o) => {
      if (Array.isArray(o)) return o.forEach(recorrer);
      if (!o || typeof o !== "object") return;
      if (typeof o.name === "string" && Array.isArray(o.services)) productos.push(o);
      Object.values(o).forEach(recorrer);
    };
    recorrer(j);
    for (const p of productos) {
      const id = /whatsapp/i.test(p.name) ? "whatsapp" : /instagram/i.test(p.name) ? "instagram" : /messenger/i.test(p.name) ? "messenger" : /facebook|graph api/i.test(p.name) ? "facebook" : null;
      if (!id) continue;
      for (const sv of p.services) {
        const st = String(sv.status ?? "");
        if (!st || /no known issues|operational/i.test(st)) continue;
        marcar(id, { s: /outage|disruption/i.test(st) ? "mayor" : "menor", det: corto(`${p.name} · ${sv.name}: ${st}`), desde: sv.time ? new Date(isNaN(sv.time) ? sv.time : Number(sv.time) * 1000).toISOString() : "", url: "https://metastatus.com/" });
      }
    }
  }));

  const r = await Promise.allSettled(tareas);
  const fallos = r.filter((x) => x.status === "rejected").length;
  if (fallos) log(`Páginas de estado: ${fallos} de ${r.length} no respondieron`);
  oficial.clear();
  for (const [k, v] of nuevo) oficial.set(k, v);
}

function probar(host) {
  return new Promise((resolve) => {
    const t0 = performance.now();
    dns.lookup(host).then(() => {
      const req = https.get({ host, path: "/", timeout: 8000, headers: { "User-Agent": "Mozilla/5.0 Heimdall-NOC" } }, (res) => {
        const ms = Math.round(performance.now() - t0);
        res.destroy();
        resolve(res.statusCode < 500 ? { ok: true, ms } : { ok: false, ms, err: `HTTP ${res.statusCode}` });
      });
      req.on("timeout", () => req.destroy(new Error("sin respuesta")));
      req.on("error", (e) => resolve({ ok: false, ms: Math.round(performance.now() - t0), err: e.message === "sin respuesta" ? "Sin respuesta" : "Sin conexión" }));
    }, () => resolve({ ok: false, ms: Math.round(performance.now() - t0), err: "DNS no resuelve" }));
  });
}

async function leerPruebas() {
  const r = await Promise.all(CATALOGO.map(([id, , , host]) => probar(host).then((x) => [id, x])));
  for (const [id, x] of r) pruebas.set(id, x);
  serviciosTs = new Date().toISOString();
}

function servicios() {
  if (!serviciosTs) return null;
  return {
    ts: serviciosTs,
    lista: CATALOGO.map(([id, n, imp]) => ({ id, n, imp, of: oficial.get(id) ?? null, pr: pruebas.get(id) ?? null })),
  };
}

// ---------- Avisos por WhatsApp (CallMeBot) y Telegram ----------
// Se activan con WHATSAPP_TELEFONO y WHATSAPP_APIKEY, y/o TELEGRAM_TOKEN y TELEGRAM_CHAT_ID (varios separados por coma). Agrupa los cambios y manda como mucho un mensaje cada 30 s.
// Un sensor tiene que seguir caído (o recuperado) 2 lecturas seguidas para avisar, así no avisa por parpadeos.
const WA = { tel: (process.env.WHATSAPP_TELEFONO ?? process.env.WHATSAPP_NUMERO ?? "").replace(/[^\d+]/g, ""), clave: process.env.WHATSAPP_APIKEY ?? "" };
const TG = { token: process.env.TELEGRAM_TOKEN ?? "", chats: (process.env.TELEGRAM_CHAT_ID ?? "").split(",").map((x) => x.trim()).filter(Boolean) };
const avisosActivos = () => !!(WA.tel && WA.clave) || !!(TG.token && TG.chats.length);
const pendientes = [];
const caidosVistos = new Map(); // id sensor -> { n: lecturas seguidas, avisado, texto }
const serviciosAvisados = new Set();
let prtgFallos = 0, prtgAvisado = false, primeraLectura = true;

const nombreEquipo = (id) => equipos.find((e) => e.id === id)?.n ?? `equipo ${id}`;
const esCaidoNuevo = (s) => s === 5 || s === 14;

function vigilarAlertas(ok, alertas) {
  if (!ok) {
    if (++prtgFallos === 24 && !prtgAvisado) { pendientes.push("⚠️ PRTG no responde desde hace 2 minutos"); prtgAvisado = true; }
    return;
  }
  if (prtgAvisado) pendientes.push("✅ PRTG responde otra vez");
  prtgFallos = 0; prtgAvisado = false;
  const ahora = new Set();
  for (const a of alertas) {
    if (a.s === 13 && caidosVistos.has(a.id)) { ahora.add(a.id); caidosVistos.get(a.id).fuera = 0; continue; } // reconocido: sigue caído, sin avisar de nuevo
    if (!esCaidoNuevo(a.s)) continue;
    ahora.add(a.id);
    const v = caidosVistos.get(a.id) ?? { n: 0, fuera: 0, avisado: primeraLectura, desde: Date.now(), texto: `${nombreEquipo(a.eq)} · ${a.sn}`, m: a.m };
    v.n++; v.fuera = 0;
    if (v.n >= 2 && !v.avisado) { pendientes.push(`🔴 CAÍDO: ${v.texto}${v.m ? ` (${v.m})` : ""}`); v.avisado = true; }
    caidosVistos.set(a.id, v);
  }
  for (const [id, v] of caidosVistos) {
    if (ahora.has(id)) continue;
    if (++v.fuera >= 2) { if (v.avisado && v.n >= 2) pendientes.push(`🟢 Recuperado: ${v.texto}${duracion(v)}`); caidosVistos.delete(id); }
  }
  primeraLectura = false;
}

const duracion = (v) => { const m = Math.round((Date.now() - v.desde) / 60000); return m >= 1 ? ` tras ${m} min` : ""; };

function vigilarServicios() {
  const sv = servicios();
  if (!sv) return;
  const probadas = sv.lista.filter((x) => x.pr);
  const redCaida = probadas.length > 4 && probadas.filter((x) => !x.pr.ok).length / probadas.length > 0.6;
  if (redCaida) return;
  for (const x of sv.lista) {
    if (!x.imp) continue;
    const mal = x.of?.s === "mayor" || (x.pr && !x.pr.ok);
    if (mal && !serviciosAvisados.has(x.id)) {
      serviciosAvisados.add(x.id);
      pendientes.push(`🌐 ${x.n} con problemas: ${x.of?.det || `desde nuestra red ${x.pr?.err ?? "no responde"}`}`);
    } else if (!mal && serviciosAvisados.has(x.id)) {
      serviciosAvisados.delete(x.id);
      pendientes.push(`🌐 ${x.n} funciona otra vez`);
    }
  }
}

async function enviarAvisos() {
  if (!pendientes.length || !avisosActivos()) { pendientes.length = 0; return; }
  const lineas = pendientes.splice(0);
  let cuerpo = `${lineas.slice(0, 12).join("\n")}${lineas.length > 12 ? `\n… y ${lineas.length - 12} más` : ""}\n${CFG.sitio}`;
  if (cuerpo.length > 1500) cuerpo = cuerpo.slice(0, 1490) + "…";
  const n = `${lineas.length} aviso${lineas.length > 1 ? "s" : ""}`;
  if (WA.tel && WA.clave) {
    const q = new URLSearchParams({ phone: WA.tel, text: `*Heimdall*\n${cuerpo}`, apikey: WA.clave });
    try {
      const r = await fetch(`https://api.callmebot.com/whatsapp.php?${q}`, { signal: AbortSignal.timeout(20000) });
      log(r.ok ? `WhatsApp enviado (${n})` : `WhatsApp falló: HTTP ${r.status}`);
    } catch (e) { log("WhatsApp falló:", e.message); }
  }
  for (const chat of TG.token ? TG.chats : []) {
    try {
      const r = await fetch(`https://api.telegram.org/bot${TG.token}/sendMessage`, {
        method: "POST", headers: { "Content-Type": "application/json" }, signal: AbortSignal.timeout(20000),
        body: JSON.stringify({ chat_id: chat, text: `Heimdall\n${cuerpo}`, disable_web_page_preview: true }),
      });
      log(r.ok ? `Telegram enviado (${n})` : `Telegram falló: HTTP ${r.status}`);
    } catch (e) { log("Telegram falló:", e.message); }
  }
}

// ---------- Estado y clientes en vivo ----------
let canal = null;
let generadoSitio = "";
let ultimo = null; // { texto cifrado, resumen }
// ---------- Backups de los switches en Drive ----------
// Lee la vista pública de la carpeta (solo nombres, ids y fechas; nunca abre los archivos) cada 30 min.
// Cada archivo se asocia a su nodo por la IP de gestión que lleva en el nombre.
let respaldos = null;

const desHtml = (s) => limpiar(String(s).replace(/&#39;/g, "'").replace(/&quot;/g, '"'));

async function listarCarpeta(id, prefijo = "", nivel = 0) {
  const html = await traer(`https://drive.google.com/embeddedfolderview?id=${encodeURIComponent(id)}`, "texto");
  const out = [];
  for (const trozo of html.split('class="flip-entry"').slice(1)) {
    const enlace = trozo.match(/href="([^"]+)"/)?.[1] ?? "";
    const idArchivo = trozo.match(/id="entry-([\w-]+)"/)?.[1] ?? enlace.match(/\/(?:file\/d|folders)\/([\w-]+)/)?.[1];
    const nombre = desHtml(trozo.match(/class="flip-entry-title">([^<]*)</)?.[1] ?? "");
    const fecha = desHtml(trozo.match(/class="flip-entry-last-modified"><div>([^<]*)</)?.[1] ?? "");
    if (!idArchivo || !nombre) continue;
    if (/\/drive\/folders\//.test(enlace)) {
      // Subcarpeta (p. ej. una por mes): un nivel hacia adentro
      if (nivel < 1) out.push(...await listarCarpeta(idArchivo, `${nombre} / `, nivel + 1));
      continue;
    }
    const ip = nombre.match(/\b(\d{1,3}(?:\.\d{1,3}){3})\b/)?.[1];
    if (ip) out.push({ ip, n: prefijo + nombre.replace(/\.txt$/i, ""), id: idArchivo, f: fecha });
  }
  return out;
}

async function leerRespaldos() {
  if (!CFG.driveRespaldos) return;
  const lista = await listarCarpeta(CFG.driveRespaldos);
  if (!lista.length && respaldos) return; // Drive respondió vacío: se conserva la última lista buena
  if (respaldos?.lista.length !== lista.length) log(`Backups en Drive: ${lista.length} archivos`);
  respaldos = { ts: new Date().toISOString(), lista };
}

// ---------- Tráfico (sensores SNMP Traffic de PRTG) ----------
// Una sola consulta por minuto trae la velocidad actual de todos los sensores de tráfico.
// Con esas lecturas el puente acumula el consumo por día de cada sensor (archivo trafico-consumo.json).
// El detalle (gráfica y volumen exacto) se pide a PRTG solo cuando alguien abre un sensor, con caché y límite.
const ARCHIVO_CONSUMO = path.join(DIR, "trafico-consumo.json");
const ZONA = process.env.ZONA_HORARIA ?? "America/Santo_Domingo";
const diaLocal = (ms = Date.now()) => new Intl.DateTimeFormat("en-CA", { timeZone: ZONA, year: "numeric", month: "2-digit", day: "2-digit" }).format(ms);
let trafico = null; // { ts, s: [[id, equipo, sensor, bytes/s, estado]] }
let traficoEn = 0;
let traficoTexto = null; // respuesta cifrada en caché
let consumo = { dias: {} }; // dias["2026-10-25"][id] = bytes
let consumoSucio = false;
try { consumo = JSON.parse(readFileSync(ARCHIVO_CONSUMO, "utf8")); } catch { /* primera vez */ }

async function leerTrafico() {
  // lastvalue_raw de un sensor de tráfico es el volumen (bytes) del último intervalo, no la velocidad
  const columnas = "objid,parentid,sensor,type,lastvalue_raw,status_raw,interval";
  let r = await prtg("/api/table.json", { content: "sensors", columns: columnas, filter_type: "snmptraffic", count: "5000" });
  if (!(r.sensors ?? []).length) {
    // Algunas versiones no filtran por tipo: se trae todo y se filtra aquí
    r = await prtg("/api/table.json", { content: "sensors", columns: columnas, count: "5000" });
    r.sensors = (r.sensors ?? []).filter((x) => /traffic|tr[aá]fico/i.test(limpiar(x.type)));
  }
  const ahora = Date.now();
  const PAUSADO = new Set([7, 8, 9, 11, 12]);
  const s = (r.sensors ?? []).filter((x) => !PAUSADO.has(x.status_raw)).map((x) => {
    const v = x.lastvalue_raw === "" ? NaN : Number(x.lastvalue_raw);
    const intervalo = Number(x.interval_raw) || Number(String(x.interval ?? "").match(/\d+/)?.[0]) || 60;
    return [x.objid, x.parentid, limpiar(x.sensor), Number.isFinite(v) && v >= 0 ? Math.round(v / intervalo) : -1, x.status_raw];
  });
  // Consumo: velocidad × tiempo desde la lectura anterior (máx. 3 min, por si hubo un corte)
  if (trafico && traficoEn) {
    const dt = Math.min(180, (ahora - traficoEn) / 1000);
    const dia = (consumo.dias[diaLocal(ahora)] ??= {});
    for (const [id, , , bps] of s) if (bps > 0) dia[id] = Math.round((dia[id] ?? 0) + bps * dt);
    consumoSucio = true;
  }
  // Pings (latencia hacia gateways, DNS, caché y switches): en la misma vuelta, una consulta más
  let p = trafico?.p ?? [];
  try {
    const rp = await prtg("/api/table.json", { content: "sensors", columns: "objid,parentid,device,sensor,lastvalue_raw,status_raw", filter_type: "ping", count: "1000" });
    p = (rp.sensors ?? []).map((x) => {
      const v = x.lastvalue_raw === "" ? NaN : Number(x.lastvalue_raw);
      return [x.objid, x.parentid, limpiar(x.sensor), Number.isFinite(v) && v >= 0 ? Math.round(v * 10) / 10 : -1, x.status_raw, limpiar(x.device)];
    });
  } catch (e) { log("Lectura de pings falló:", e.message); }
  trafico = { ts: new Date(ahora).toISOString(), s, p };
  traficoEn = ahora;
  traficoTexto = null;
}

// Consumo exacto de días anteriores: se copia del historial diario de PRTG, un sensor cada 20 s
// (unas 3 consultas por minuto; una vuelta completa tarda unas horas y se repite cada día)
consumo.prtg ??= {}; // id → fecha de la última copia
const SIN_CONSUMO = /^\(\d+\)\s*(null\d*|vlan\s*\d+)\s*$/i;

async function rellenarConsumo() {
  if (!trafico?.s.length) return;
  const hoy = diaLocal();
  const pendiente = trafico.s
    .filter(([id, , nombre]) => !SIN_CONSUMO.test(nombre) && consumo.prtg[id] !== hoy)
    .sort((a, b) => b[3] - a[3])[0]; // primero los que tienen más tráfico
  if (!pendiente) return;
  const [id] = pendiente;
  const rel = await calibrarReloj(id);
  // Medianoche local de hace 32 días, en la hora que entiende PRTG
  const [y, m, d] = hoy.split("-").map(Number);
  const offsetZona = Date.parse(new Date(Date.UTC(y, m - 1, d)).toLocaleString("en-US", { timeZone: ZONA }) + " UTC") - Date.UTC(y, m - 1, d);
  const inicio = Date.UTC(y, m - 1, d - 32) - offsetZona;
  const r = await prtg("/api/historicdata.json", { id: String(id), avg: "86400", sdate: fechaPrtg(inicio + rel.pedir * 60000), edate: fechaPrtg(Date.now() + rel.pedir * 60000), usecaption: "1" });
  for (const f of r.histdata ?? []) {
    const t = leerFechaPrtg(f.datetime) - rel.mostrar * 60000;
    const dia = diaLocal(t + 3600e3); // +1 h por si el inicio cae justo en la medianoche anterior
    const total = Number(f["Traffic Total (volume)"] ?? f["Tráfico total (volumen)"]);
    if (!Number.isFinite(total) || dia >= hoy) continue;
    (consumo.dias[dia] ??= {})[id] = Math.round(total);
  }
  consumo.prtg[id] = hoy;
  consumoSucio = true;
}

function guardarConsumo() {
  if (!consumoSucio) return;
  const dias = Object.keys(consumo.dias).sort();
  for (const d of dias.slice(0, Math.max(0, dias.length - 70))) delete consumo.dias[d];
  writeFileSync(ARCHIVO_CONSUMO + ".tmp", JSON.stringify(consumo));
  renameSync(ARCHIVO_CONSUMO + ".tmp", ARCHIVO_CONSUMO);
  consumoSucio = false;
}

function resumenConsumo() {
  // Totales por sensor: hoy, 7 días, 30 días y mes en curso
  const hoy = diaLocal();
  const hace = (n) => diaLocal(Date.now() - n * 864e5);
  const d7 = hace(6), d30 = hace(29), mes = hoy.slice(0, 8) + "01";
  const out = {};
  for (const [dia, porId] of Object.entries(consumo.dias)) {
    for (const [id, b] of Object.entries(porId)) {
      const t = (out[id] ??= [0, 0, 0, 0]);
      if (dia === hoy) t[0] += b;
      if (dia >= d7) t[1] += b;
      if (dia >= d30) t[2] += b;
      if (dia >= mes) t[3] += b;
    }
  }
  const dias = Object.keys(consumo.dias).sort();
  return { desde: dias[0] ?? hoy, c: out };
}

async function respuestaTrafico() {
  if (!traficoTexto) traficoTexto = await cifrarMensaje(canal, { v: 1, ...trafico, consumo: resumenConsumo() });
  return traficoTexto;
}

// Historia de un sensor: PRTG historicdata, promediada según el rango
const RANGOS = { "2h": [2 * 3600, 60, 60], "24h": [86400, 300, 300], "7d": [7 * 86400, 3600, 1800], "30d": [30 * 86400, 14400, 1800] }; // [segundos, promedio, caché s]
const cacheHistoria = new Map();
let llamadasHistoria = [];

// PRTG muestra las fechas en la zona horaria de su usuario y puede interpretar sdate/edate en otra.
// Se calibran ambas una vez cada 6 h: "mostrar" con el reloj de PRTG y "pedir" con una consulta corta.
let reloj = null; // { mostrar: min, pedir: min, en: ms }
const fechaPrtg = (ms) => new Date(ms).toISOString().slice(0, 19).replace(/[T:]/g, "-");
function leerFechaPrtg(txt) {
  const m = String(txt ?? "").match(/(\d{1,2})\/(\d{1,2})\/(\d{4})\s+(\d{1,2}):(\d{2})(?::(\d{2}))?\s*(AM|PM)?/i);
  if (!m) return NaN;
  let h = Number(m[4]);
  if (m[7]) h = (h % 12) + (/pm/i.test(m[7]) ? 12 : 0);
  return Date.UTC(Number(m[3]), Number(m[1]) - 1, Number(m[2]), h, Number(m[5]), Number(m[6] ?? 0));
}
const cuarto = (ms) => Math.round(ms / 900000) * 15; // a múltiplos de 15 min

async function calibrarReloj(idMuestra) {
  if (reloj && Date.now() - reloj.en < 6 * 3600e3) return reloj;
  const st = await prtg("/api/getstatus.htm", { id: "0" });
  const mostrar = cuarto(leerFechaPrtg(st.Clock) - Date.now()) || 0;
  const s0 = Math.floor(Date.now() / 3600e3) * 3600e3 - 30 * 3600e3;
  const r = await prtg("/api/historicdata.json", { id: String(idMuestra), avg: "3600", sdate: fechaPrtg(s0), edate: fechaPrtg(s0 + 60 * 3600e3), usecaption: "1" });
  const primera = leerFechaPrtg(r.histdata?.[0]?.datetime) - mostrar * 60000;
  const pedir = Number.isFinite(primera) ? cuarto(s0 - primera) : mostrar;
  reloj = { mostrar, pedir, en: Date.now() };
  log(`Reloj de PRTG: muestra UTC${mostrar >= 0 ? "+" : ""}${mostrar / 60} h, interpreta fechas UTC${pedir >= 0 ? "+" : ""}${pedir / 60} h`);
  return reloj;
}

async function historia(id, rango, tipo = "trafico") {
  const [seg, avg, ttl] = RANGOS[rango];
  const clave = `${id}:${rango}`;
  const c = cacheHistoria.get(clave);
  if (c && Date.now() - c.en < ttl * 1000) return c.texto;
  // Límite: como mucho 10 consultas de historia por minuto entre todos los usuarios
  llamadasHistoria = llamadasHistoria.filter((t) => Date.now() - t < 60000);
  if (llamadasHistoria.length >= 10) { const e = new Error("Demasiadas consultas, intenta en un minuto"); e.codigo = 429; throw e; }
  llamadasHistoria.push(Date.now());
  const rel = await calibrarReloj(id);
  const ahora = Date.now();
  const desde = ahora - seg * 1000;
  const r = await prtg("/api/historicdata.json", { id: String(id), avg: String(avg), sdate: fechaPrtg(desde + rel.pedir * 60000), edate: fechaPrtg(ahora + rel.pedir * 60000), usecaption: "1" });
  // Columnas de PRTG con usecaption: "Traffic In (speed)" en bytes/s, "Traffic In (volume)" en bytes, "coverage": "100 %"
  const col = (f, re) => {
    const k = Object.keys(f).find((k) => re.test(k) && k.endsWith("_raw")) ?? Object.keys(f).find((k) => re.test(k));
    const v = k == null || f[k] === "" ? NaN : typeof f[k] === "number" ? f[k] : Number(String(f[k]).replace(/[^\d.\-]/g, ""));
    return Number.isFinite(v) ? v : null;
  };
  const n = (v) => (v == null ? null : Math.round(v));
  const d = (v) => (v == null ? null : Math.round(v * 10) / 10);
  // Ping: "Ping Time", "Minimum", "Maximum" en ms y "Packet Loss" en %
  const puntos = tipo === "ping" ? (r.histdata ?? []).map((f) => [
    leerFechaPrtg(f.datetime) - rel.mostrar * 60000,
    d(col(f, /^ping time|tiempo de ping/i)), d(col(f, /^minimum|m[ií]nimo/i)), d(col(f, /^maximum|m[aá]ximo/i)),
    d(col(f, /^packet loss|p[eé]rdida/i)), n(col(f, /^coverage|cobertura/i)),
  ]).filter((p) => Number.isFinite(p[0]) && p[5] !== 0) : (r.histdata ?? []).map((f) => [
    leerFechaPrtg(f.datetime) - rel.mostrar * 60000,
    n(col(f, /^traffic in \(speed\)|entrada.*velocidad/i)), n(col(f, /^traffic out \(speed\)|salida.*velocidad/i)),
    n(col(f, /^traffic in \(volume\)|entrada.*volumen/i)), n(col(f, /^traffic out \(volume\)|salida.*volumen/i)),
    n(col(f, /^coverage|cobertura/i)),
  ]).filter((p) => Number.isFinite(p[0]) && p[5] !== 0);
  const texto = await cifrarMensaje(canal, { v: 1, id, tipo, rango, avg, ts: new Date().toISOString(), puntos });
  cacheHistoria.set(clave, { en: Date.now(), texto });
  if (cacheHistoria.size > 300) cacheHistoria.delete(cacheHistoria.keys().next().value);
  return texto;
}

const clientes = new Set();

async function ciclo() {
  let estado;
  try {
    if (!equipos.length || Date.now() - equiposEn > 10 * 60 * 1000) await leerEquipos();
    const alertas = await leerAlertas();
    estado = { v: 1, ts: new Date().toISOString(), ok: true, equipos, alertas, servicios: servicios(), respaldos };
  } catch (e) {
    log("PRTG no respondió:", e.message);
    estado = { v: 1, ts: new Date().toISOString(), ok: false, error: "Sin respuesta de PRTG", equipos, alertas: ultimo?.alertas ?? [], servicios: servicios(), respaldos };
  }
  vigilarAlertas(estado.ok, estado.alertas);
  if (!canal) return;
  const resumen = estado.alertas.map((a) => `${a.id}:${a.s}`).sort().join(",");
  if (ultimo && resumen !== ultimo.resumen) log(`Cambio de estado: ${estado.alertas.filter((a) => a.s === 5).length} caídos, ${estado.alertas.length} con problema`);
  const texto = await cifrarMensaje(canal, estado);
  ultimo = { texto, resumen, alertas: estado.alertas };
  for (const res of clientes) res.write(`event: estado\ndata: ${texto}\n\n`);
}

function cors(req, res) {
  const o = req.headers.origin;
  if (o && ORIGENES.has(o)) res.setHeader("Access-Control-Allow-Origin", o);
  res.setHeader("Vary", "Origin");
}

const servidor = http.createServer((req, res) => {
  cors(req, res);
  const url = new URL(req.url ?? "/", "http://x");
  if (url.pathname === "/salud") { res.end("ok"); return; }
  if (url.pathname === "/estado") {
    res.setHeader("Cache-Control", "no-store");
    if (!ultimo) { res.statusCode = 503; res.end(); return; }
    res.end(ultimo.texto);
    return;
  }
  if (url.pathname === "/trafico") {
    res.setHeader("Cache-Control", "no-store");
    if (!trafico || !canal) { res.statusCode = 503; res.end(); return; }
    respuestaTrafico().then((t) => res.end(t), () => { res.statusCode = 500; res.end(); });
    return;
  }
  if (url.pathname === "/trafico/historia") {
    res.setHeader("Cache-Control", "no-store");
    const id = Number(url.searchParams.get("id"));
    const rango = url.searchParams.get("r") ?? "24h";
    // Solo sensores de tráfico o ping conocidos y rangos fijos: nadie puede usar el puente para otras consultas
    const tipo = trafico?.s.some((x) => x[0] === id) ? "trafico" : trafico?.p?.some((x) => x[0] === id) ? "ping" : null;
    if (!canal || !RANGOS[rango] || !tipo) { res.statusCode = 400; res.end(); return; }
    historia(id, rango, tipo).then((t) => res.end(t), (e) => { res.statusCode = e.codigo ?? 502; res.end(); if (!e.codigo) log("Historia de tráfico falló:", e.message); });
    return;
  }
  if (url.pathname === "/eventos") {
    res.writeHead(200, { "Content-Type": "text/event-stream", "Cache-Control": "no-store", Connection: "keep-alive", "X-Accel-Buffering": "no" });
    res.write("retry: 5000\n\n");
    if (ultimo) res.write(`event: estado\ndata: ${ultimo.texto}\n\n`);
    clientes.add(res);
    const latido = setInterval(() => res.write(": latido\n\n"), 20000);
    req.on("close", () => { clearInterval(latido); clientes.delete(res); });
    return;
  }
  res.statusCode = 404;
  res.end();
});

// ---------- Clave del sitio y anuncio ----------
let urlPublica = "";

async function actualizarClave() {
  const paquete = JSON.parse(await obtener(`${CFG.sitio}/datos/red.json?t=${Date.now()}`));
  if (paquete.generado === generadoSitio) return false;
  const clave = await abrirClave(paquete, CFG.usuario, CFG.contrasena);
  if (!clave) throw new Error("HEIMDALL_USUARIO o HEIMDALL_CONTRASENA no son válidos para el sitio publicado");
  canal = await derivarCanal(clave);
  generadoSitio = paquete.generado;
  log("Clave del sitio cargada (versión", paquete.generado + ")");
  return true;
}

async function anunciar() {
  if (!canal || !urlPublica) return;
  const cuerpo = await cifrarMensaje(canal, { url: urlPublica, ts: new Date().toISOString() });
  const r = await fetch(`${CFG.ntfy}/${canal.topico}`, { method: "POST", body: cuerpo, headers: { Cache: "yes", Title: "heimdall" } });
  if (!r.ok) throw new Error(`ntfy respondió ${r.status}`);
  log("Dirección anunciada");
}

function abrirTunel() {
  if (CFG.sinTunel) { urlPublica = process.env.URL_PUBLICA ?? `http://localhost:${CFG.puerto}`; anunciar().catch((e) => log("Anuncio falló:", e.message)); return; }
  log("Abriendo túnel con", CFG.cloudflared);
  const p = spawn(CFG.cloudflared, ["tunnel", "--no-autoupdate", "--url", `http://localhost:${CFG.puerto}`], { windowsHide: true });
  const leer = (d) => {
    const m = String(d).match(/https:\/\/[a-z0-9-]+\.trycloudflare\.com/);
    if (m && m[0] !== urlPublica) {
      urlPublica = m[0];
      log("Túnel listo:", urlPublica);
      anunciar().catch((e) => log("Anuncio falló:", e.message));
    }
  };
  p.stdout.on("data", leer);
  p.stderr.on("data", leer);
  p.on("error", (e) => log("No se pudo iniciar cloudflared:", e.message));
  p.on("exit", (c) => { log("El túnel se cerró (código", c + "). Reintento en 15 s"); urlPublica = ""; setTimeout(abrirTunel, 15000); });
}

// ---------- Arranque ----------
const faltan = ["PRTG_USUARIO", "PRTG_PASSWORD", "HEIMDALL_USUARIO", "HEIMDALL_CONTRASENA"].filter((k) => !process.env[k] && !(k === "PRTG_PASSWORD" && passhash));
if (faltan.length) {
  log("Faltan variables de entorno:", faltan.join(", "));
  process.exit(1);
}

servidor.listen(CFG.puerto, "127.0.0.1", () => log(`Puente escuchando en http://localhost:${CFG.puerto}`));
for (let i = 0; ; i++) {
  try { await actualizarClave(); break; } catch (e) {
    log("No pude cargar la clave del sitio:", e.message);
    if (/no son válidos/.test(e.message)) process.exit(1);
    await new Promise((r) => setTimeout(r, Math.min(60000, 5000 * (i + 1))));
  }
}
await ciclo();
setInterval(() => ciclo().catch((e) => log("Error en ciclo:", e.message)), CFG.intervalo);
abrirTunel();
// Servicios de internet: pruebas cada 60 s y páginas oficiales cada 2 min (no tocan PRTG)
const arrancarServicios = () => {
  leerPruebas().catch((e) => log("Pruebas de servicios fallaron:", e.message));
  leerOficiales().catch((e) => log("Páginas de estado fallaron:", e.message));
};
arrancarServicios();
setInterval(() => leerPruebas().then(vigilarServicios).catch((e) => log("Pruebas de servicios fallaron:", e.message)), 60 * 1000);
setInterval(() => enviarAvisos(), 30 * 1000);
if (avisosActivos()) {
  log(`Avisos activos:${WA.tel && WA.clave ? " WhatsApp" : ""}${TG.token && TG.chats.length ? " Telegram" : ""}`);
  pendientes.push("✅ Puente en marcha: los avisos están activos");
}
setInterval(() => leerOficiales().catch((e) => log("Páginas de estado fallaron:", e.message)), 2 * 60 * 1000);
// Tráfico: una consulta por minuto; el consumo acumulado se guarda cada 5 min
const cicloTrafico = () => leerTrafico().catch((e) => log("Tráfico falló:", e.message));
cicloTrafico();
setInterval(cicloTrafico, 60 * 1000);
setInterval(() => rellenarConsumo().catch((e) => log("Historial de consumo falló:", e.message)), 20 * 1000);
setInterval(() => { try { guardarConsumo(); } catch (e) { log("No se pudo guardar el consumo:", e.message); } }, 5 * 60 * 1000);
for (const sen of ["SIGINT", "SIGTERM"]) process.on(sen, () => { try { guardarConsumo(); } catch { /* nada */ } process.exit(0); });
// Backups de los switches: al arrancar y cada 30 min
leerRespaldos().catch((e) => log("Lista de backups falló:", e.message));
setInterval(() => leerRespaldos().catch((e) => log("Lista de backups falló:", e.message)), 30 * 60 * 1000);
// Revisa cada 10 min si el sitio se volvió a publicar (nueva clave) y reanuncia cada 6 h
setInterval(async () => {
  try { if (await actualizarClave()) { await ciclo(); await anunciar(); } } catch (e) { log("Revisión del sitio falló:", e.message); }
}, 10 * 60 * 1000);
setInterval(() => anunciar().catch((e) => log("Anuncio falló:", e.message)), 6 * 60 * 60 * 1000);
