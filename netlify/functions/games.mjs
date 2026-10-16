import { getStore } from "@netlify/blobs";
import { createHmac, timingSafeEqual } from "node:crypto";

const STORE = "arcadia-games";
const KEY = "catalog";
const ADMIN_USER = process.env.ARCADIA_ADMIN_USER || "Fidus";
const ADMIN_PASSWORD = process.env.ARCADIA_ADMIN_PASSWORD || "Fidus 123";
const TOKEN_SECRET = process.env.ARCADIA_TOKEN_SECRET || ADMIN_PASSWORD;
const json = (data, status = 200) => new Response(JSON.stringify(data), { status, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" } });
const sign = (value) => createHmac("sha256", TOKEN_SECRET).update(value).digest("hex");
function makeToken() { const issued = String(Date.now()); return `${issued}.${sign(issued)}`; }
function validToken(token) {
  if (!token || !token.includes(".")) return false;
  const [issued, signature] = token.split(".");
  if (!/^\d{13}$/.test(issued) || Date.now() - Number(issued) > 12 * 60 * 60 * 1000 || Number(issued) > Date.now() + 60_000) return false;
  const expected = sign(issued);
  try { return timingSafeEqual(Buffer.from(signature, "hex"), Buffer.from(expected, "hex")); } catch { return false; }
}
function validGame(game) {
  if (!game || typeof game.title !== "string" || !game.title.trim() || game.title.length > 120) return false;
  if (typeof game.url !== "string" || typeof game.thumb !== "string") return false;
  try { const u = new URL(game.url), t = new URL(game.thumb); return ["http:", "https:"].includes(u.protocol) && ["http:", "https:"].includes(t.protocol); } catch { return false; }
}
export default async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { status: 204 });
  const store = getStore(STORE);
  if (req.method === "GET") {
    try { const games = await store.get(KEY, { type: "json" }) || []; return json({ games }); }
    catch (e) { console.error(e); return json({ error: "Não foi possível ler o catálogo." }, 500); }
  }
  if (req.method !== "POST") return json({ error: "Método não permitido." }, 405);
  let body; try { body = await req.json(); } catch { return json({ error: "JSON inválido." }, 400); }
  if (body.action === "login") {
    const user = String(body.username || ""); const pass = String(body.password || "");
    const userOK = user.length === ADMIN_USER.length && timingSafeEqual(Buffer.from(user), Buffer.from(ADMIN_USER));
    const passOK = pass.length === ADMIN_PASSWORD.length && timingSafeEqual(Buffer.from(pass), Buffer.from(ADMIN_PASSWORD));
    if (!userOK || !passOK) return json({ error: "Usuário ou senha incorretos." }, 401);
    return json({ token: makeToken() });
  }
  const token = (req.headers.get("authorization") || "").replace(/^Bearer\s+/i, "");
  if (!validToken(token)) return json({ error: "Sessão inválida ou expirada. Entre novamente." }, 401);
  try {
    const games = await store.get(KEY, { type: "json" }) || [];
    if (body.action === "save") {
      if (!validGame(body.game)) return json({ error: "Confira o título, a capa e a URL do jogo." }, 400);
      const game = { title: body.game.title.trim(), category: String(body.game.category || "Outros").slice(0, 40), thumb: body.game.thumb, url: body.game.url, tags: String(body.game.tags || "personalizado").slice(0, 200), description: String(body.game.description || "").slice(0, 1000), custom: true, created_at: new Date().toISOString() };
      const idx = games.findIndex(g => g.url === game.url);
      if (idx >= 0) games[idx] = game; else games.unshift(game);
      await store.setJSON(KEY, games);
      return json({ ok: true, game });
    }
    if (body.action === "delete") {
      const url = String(body.url || ""); const filtered = games.filter(g => g.url !== url);
      if (filtered.length === games.length) return json({ error: "Jogo não encontrado." }, 404);
      await store.setJSON(KEY, filtered);
      return json({ ok: true });
    }
    return json({ error: "Ação desconhecida." }, 400);
  } catch (e) { console.error(e); return json({ error: "Erro ao salvar no armazenamento do Netlify." }, 500); }
};
