
const encoder = new TextEncoder();
const MAX_MESSAGE_SIZE = 16_384;
const AUTH_TIMEOUT_MS = 10_000;
const MAX_OPEN_SOCKETS = 20;

function response(text, status = 200) {
  return new Response(text, { status, headers: { "content-type": "text/plain; charset=utf-8" } });
}

function sendJson(socket, data) { 
  try { 
    socket.send(JSON.stringify(data)); 
  } catch {} 
}

async function sha256(text) {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(text));
  return Array.from(new Uint8Array(digest), b => b.toString(16).padStart(2, "0")).join("");
}

async function sameSecret(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  const x = await sha256(a);
  const y = await sha256(b);
  let diff = 0;
  for (let i = 0; i < x.length; i++) {
    diff |= x.charCodeAt(i) ^ y.charCodeAt(i);
  }
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
  constructor(state, env) {
    this.state = state;
    this.env = env;
    this.messageQueue = Promise.resolve();
  }

  async fetch(request) {
    const now = Date.now();
    let openCount = 0;
    
    // Actively prune dead, unauthenticated sockets before checking connection limits
    for (const socket of this.state.getWebSockets()) {
      const a = this.getAttachment(socket);
      if (!a.authenticated && a.connectedAt && now - a.connectedAt >= AUTH_TIMEOUT_MS) {
        try { socket.close(1008, "Authentication timeout"); } catch {}
      } else {
        openCount++;
      }
    }
    
    if (openCount >= MAX_OPEN_SOCKETS) {
      return response("Room temporarily busy. Close stale tabs and retry.", 503);
    }

    const pair = new WebSocketPair();
    const client = pair[0];
    const server = pair[1];
    const ipHash = await sha256(request.headers.get("CF-Connecting-IP") || "unknown");
    
    this.state.acceptWebSocket(server);
    server.serializeAttachment({ authenticated: false, role: null, ipHash, connectedAt: Date.now(), replaced: false });
    
    await this.state.storage.setAlarm(Date.now() + AUTH_TIMEOUT_MS);
    return new Response(null, { status: 101, webSocket: client });
  }

  getAttachment(socket) { 
    try { 
      return socket.deserializeAttachment() || {}; 
    } catch { 
      return {}; 
    } 
  }

  socketsFor(role) {
    return this.state.getWebSockets().filter(s => {
      const a = this.getAttachment(s);
      return a.authenticated === true && a.role === role;
    });
  }

  sendToRole(role, data) { 
    for (const s of this.socketsFor(role)) {
      sendJson(s, data); 
    }
  }

  async allowAttempt(ipHash) {
    const key = `attempts:${ipHash}`;
    const now = Date.now();
    return this.state.storage.transaction(async tx => {
      const recent = (await tx.get(key) || []).filter(t => now - t < 60_000);
      if (recent.length >= 8) { 
        await tx.put(key, recent); 
        return false; 
      }
      recent.push(now); 
      await tx.put(key, recent); 
      return true;
    });
  }

  webSocketMessage(socket, raw) {
    this.messageQueue = this.messageQueue.then(() => this.handleMessage(socket, raw)).catch(() => {
      try { socket.close(1011, "Internal relay error"); } catch {}
    });
    // Returning the promise chain ensures Cloudflare DO lifecycle respects the execution queue
    return this.messageQueue;
  }

  async handleMessage(socket, raw) {
    if (typeof raw !== "string" || raw.length > MAX_MESSAGE_SIZE) { 
      try { socket.close(1009, "Message too large"); } catch {} 
      return; 
    }
    
    let data;
    try { 
      data = JSON.parse(raw); 
    } catch { 
      try { socket.close(1008, "Invalid message"); } catch {} 
      return; 
    }
    
    const a = this.getAttachment(socket);

    if (!a.authenticated) {
      if (data.type !== "auth") { 
        try { socket.close(1008, "Authentication required"); } catch {} 
        return; 
      }
      if (!(await this.allowAttempt(a.ipHash))) { 
        try { socket.close(1008, "Too many attempts"); } catch {} 
        return; 
      }
      
      const roleOk = data.role === "owner" || data.role === "guest";
      const credentialOk = data.role === "owner"
        ? await sameSecret(data.accessToken, this.env.ACCESS_LINK_TOKEN)
        : data.role === "guest" && await sameSecret(data.code, this.env.GUEST_CODE);
        
      if (!roleOk || !credentialOk) {
        sendJson(socket, { type: "auth_error", message: "Invalid access credential" });
        try { socket.close(1008, "Authentication failed"); } catch {}
        return;
      }

      // Reconnect Fix: Safely retire older connections for this role before assigning the new one
      for (const oldSocket of this.socketsFor(data.role)) {
        const old = this.getAttachment(oldSocket);
        try { 
          oldSocket.serializeAttachment({ ...old, authenticated: false, role: null, replaced: true }); 
        } catch {}
        try { 
          oldSocket.close(4001, "Replaced by a newer authenticated connection"); 
        } catch {}
      }

      socket.serializeAttachment({ ...a, authenticated: true, role: data.role, replaced: false });
      sendJson(socket, { type: "ready", role: data.role });
      
      if (data.role === "guest") {
        this.sendToRole("owner", { type: "guest_status", online: true });
      } else {
        sendJson(socket, { type: "guest_status", online: this.socketsFor("guest").length > 0 });
      }

      const peerRole = data.role === "owner" ? "guest" : "owner";
      for (const peer of this.socketsFor(peerRole)) {
        const pa = this.getAttachment(peer);
        if (pa.publicKey) sendJson(socket, { type: "pubkey", key: pa.publicKey });
      }
      return;
    }

    const role = a.role;
    const peerRole = role === "owner" ? "guest" : "owner";
    const peers = this.socketsFor(peerRole);
    
    if (data.type === "ping") { 
      sendJson(socket, { type: "pong" }); 
      return; 
    }

    if (data.type === "pubkey") {
      if (typeof data.key !== "string" || data.key.length > 256) { 
        try { socket.close(1008, "Invalid public key"); } catch {} 
        return; 
      }
      socket.serializeAttachment({ ...a, publicKey: data.key });
      for (const peer of peers) sendJson(peer, { type: "pubkey", key: data.key });
      return;
    }

    if (data.type === "message") {
      if (typeof data.id !== "string" || typeof data.ciphertext !== "string" || data.ciphertext.length > 12_000) {
        sendJson(socket, { type: "invalid_message" }); 
        return;
      }
      if (!peers.length) { 
        sendJson(socket, { type: "peer_offline", id: data.id }); 
        return; 
      }
      for (const peer of peers) sendJson(peer, { type: "message", id: data.id, ciphertext: data.ciphertext });
      return;
    }

    if (["typing", "seen", "clear", "session_end"].includes(data.type)) {
      const event = { type: data.type };
      if (data.type === "typing") event.active = data.active === true;
      if (data.type === "seen" || data.type === "clear") {
        if (typeof data.id === "string") event.id = data.id;
        else if (data.type === "seen") return;
      }
      for (const peer of peers) sendJson(peer, event);
    }
  }

  async alarm() {
    const now = Date.now(); 
    let next = Infinity;
    
    for (const socket of this.state.getWebSockets()) {
      const a = this.getAttachment(socket);
      if (a.authenticated) continue;
      
      const deadline = (a.connectedAt || now) + AUTH_TIMEOUT_MS;
      if (now >= deadline) { 
        try { socket.close(1008, "Authentication timeout"); } catch {} 
      } else {
        next = Math.min(next, deadline);
      }
    }
    
    if (next !== Infinity) {
      await this.state.storage.setAlarm(next);
    }
  }

  async webSocketClose(socket) {
    const a = this.getAttachment(socket);
    // Crucial: Only notify peer of offline status if this socket hasn't been intentionally replaced
    if (a.role === "guest" && a.authenticated && !a.replaced) {
      this.sendToRole("owner", { 
        type: "guest_status", 
        online: this.socketsFor("guest").some(s => s !== socket) 
      });
    }
  }

  webSocketError(socket) { 
    try { socket.close(); } catch {} 
  }
}
