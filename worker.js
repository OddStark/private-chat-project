const encoder = new TextEncoder();
const MAX_MESSAGE_SIZE = 16_384;
const AUTH_TIMEOUT_MS = 10_000;

function response(text, status = 200) {
  return new Response(text, { status, headers: { "content-type": "text/plain; charset=utf-8" } });
}
function sendJson(socket, data) {
  try { socket.send(JSON.stringify(data)); } catch {}
}
async function sha256(text) {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(text));
  return Array.from(new Uint8Array(digest), b => b.toString(16).padStart(2, "0")).join("");
}
async function sameSecret(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  const x = await sha256(a), y = await sha256(b);
  let diff = 0;
  for (let i = 0; i < x.length; i++) diff |= x.charCodeAt(i) ^ y.charCodeAt(i);
  return diff === 0;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === "/health") return Response.json({ status: "ready" });
    if (url.pathname !== "/ws") return response("Private Chat relay is running.");
    if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket") return response("WebSocket required", 426);
    if (!env.ACCESS_LINK_TOKEN || !env.GUEST_CODE || !env.CHAT_ROOM) return response("Server configuration incomplete", 503);
    return env.CHAT_ROOM.getByName("private-room").fetch(request);
  }
};

export class ChatRoom {
  constructor(state, env) { this.state = state; this.env = env; }
  async fetch(request) {
    if (this.state.getWebSockets().length >= 4) return response("Room temporarily full", 503);
    const pair = new WebSocketPair();
    const client = pair[0], server = pair[1];
    const ipHash = await sha256(request.headers.get("CF-Connecting-IP") || "unknown");
    this.state.acceptWebSocket(server);
    server.serializeAttachment({ authenticated: false, role: null, ipHash, connectedAt: Date.now() });
    await this.state.storage.setAlarm(Date.now() + AUTH_TIMEOUT_MS);
    return new Response(null, { status: 101, webSocket: client });
  }
  getAttachment(socket) { try { return socket.deserializeAttachment() || {}; } catch { return {}; } }
  socketsFor(role) { return this.state.getWebSockets().filter(s => { const a = this.getAttachment(s); return a.authenticated && a.role === role; }); }
  sendToRole(role, data) { for (const s of this.socketsFor(role)) sendJson(s, data); }
  async allowAttempt(ipHash) {
    const key = `attempts:${ipHash}`, now = Date.now();
    return this.state.storage.transaction(async tx => {
      const recent = (await tx.get(key) || []).filter(t => now - t < 60_000);
      if (recent.length >= 8) { await tx.put(key, recent); return false; }
      recent.push(now); await tx.put(key, recent); return true;
    });
  }
  async webSocketMessage(socket, raw) {
    if (typeof raw !== "string" || raw.length > MAX_MESSAGE_SIZE) { socket.close(1009, "Message too large"); return; }
    let data;
    try { data = JSON.parse(raw); } catch { socket.close(1008, "Invalid message"); return; }
    const a = this.getAttachment(socket);
    if (!a.authenticated) {
      if (data.type !== "auth") { socket.close(1008, "Authentication required"); return; }
      if (!(await this.allowAttempt(a.ipHash))) { socket.close(1008, "Too many attempts"); return; }
      const roleOk = data.role === "owner" || data.role === "guest";
      const credentialOk = data.role === "owner"
        ? await sameSecret(data.accessToken, this.env.ACCESS_LINK_TOKEN)
        : data.role === "guest" && await sameSecret(data.code, this.env.GUEST_CODE);
      if (!roleOk || !credentialOk) { sendJson(socket, { type: "auth_error", message: "Invalid access credential" }); socket.close(1008, "Authentication failed"); return; }
      if (this.socketsFor(data.role).length > 0) { sendJson(socket, { type: "already_connected" }); socket.close(1008, "This role is already connected"); return; }
      socket.serializeAttachment({ ...a, authenticated: true, role: data.role });
      sendJson(socket, { type: "ready", role: data.role });
      if (data.role === "guest") this.sendToRole("owner", { type: "guest_status", online: true });
      else sendJson(socket, { type: "guest_status", online: this.socketsFor("guest").length > 0 });
      // Share the authenticated peer's public key if it arrived first.
      const peerRole = data.role === "owner" ? "guest" : "owner";
      for (const peer of this.socketsFor(peerRole)) {
        const pa = this.getAttachment(peer);
        if (pa.publicKey) sendJson(socket, { type: "pubkey", key: pa.publicKey });
      }
      return;
    }
    const role = a.role, peerRole = role === "owner" ? "guest" : "owner";
    const peers = this.socketsFor(peerRole);
    if (data.type === "ping") { sendJson(socket, { type: "pong" }); return; }
    if (data.type === "pubkey") {
      if (typeof data.key !== "string" || data.key.length > 256) { socket.close(1008, "Invalid public key"); return; }
      socket.serializeAttachment({ ...a, publicKey: data.key });
      for (const peer of peers) sendJson(peer, { type: "pubkey", key: data.key });
      return;
    }
    if (data.type === "message") {
      if (typeof data.id !== "string" || typeof data.ciphertext !== "string" || data.ciphertext.length > 12_000) { sendJson(socket, { type: "invalid_message" }); return; }
      if (!peers.length) { sendJson(socket, { type: "peer_offline", id: data.id }); return; }
      for (const peer of peers) sendJson(peer, { type: "message", id: data.id, ciphertext: data.ciphertext });
      return;
    }
    if (["typing", "seen", "clear", "session_end"].includes(data.type)) {
      const event = { type: data.type };
      if (data.type === "typing") event.active = data.active === true;
      if (data.type === "seen" || data.type === "clear") { if (typeof data.id === "string") event.id = data.id; else if (data.type === "seen") return; }
      for (const peer of peers) sendJson(peer, event);
    }
  }
  async alarm() {
    const now = Date.now(); let next = Infinity;
    for (const socket of this.state.getWebSockets()) {
      const a = this.getAttachment(socket);
      if (a.authenticated) continue;
      const deadline = a.connectedAt + AUTH_TIMEOUT_MS;
      if (now >= deadline) { try { socket.close(1008, "Authentication timeout"); } catch {} }
      else next = Math.min(next, deadline);
    }
    if (next !== Infinity) await this.state.storage.setAlarm(next);
  }
  async webSocketClose(socket) {
    const a = this.getAttachment(socket);
    if (a.role === "guest" && a.authenticated) this.sendToRole("owner", { type: "guest_status", online: this.socketsFor("guest").length > 1 });
  }
  webSocketError(socket) { try { socket.close(); } catch {} }
                                                                         }
