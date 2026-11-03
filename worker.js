
const encoder = new TextEncoder();
const MAX_MESSAGE_SIZE = 16_384;
const AUTH_TIMEOUT_MS = 10_000;

function response(text, status) {
  return new Response(text, { status });
}

function sendJson(socket, data) {
  try {
    socket.send(JSON.stringify(data));
  } catch {}
}

async function sha256(text) {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    encoder.encode(text)
  );
  return Array.from(new Uint8Array(digest))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

async function sameSecret(a, b) {
  if (typeof a !== "string" || typeof b !== "string") {
    return false;
  }

  const x = await sha256(a);
  const y = await sha256(b);

  let difference = 0;
  for (let i = 0; i < x.length; i++) {
    difference |= x.charCodeAt(i) ^ y.charCodeAt(i);
  }
  return difference === 0;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/health") {
      return Response.json({ status: "ready" });
    }

    if (url.pathname !== "/ws") {
      return response("Private Chat Server", 200);
    }

    if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket") {
      return response("WebSocket required", 426);
    }

    if (!env.ACCESS_LINK_TOKEN || !env.GUEST_CODE || !env.CHAT_ROOM) {
      return response("Server configuration incomplete", 503);
    }

    const room = env.CHAT_ROOM.getByName("private-room");
    return room.fetch(request);
  }
};

export class ChatRoom {
  constructor(state, env) {
    this.state = state;
    this.env = env;
  }

  async fetch(request) {
    if (this.state.getWebSockets().length >= 4) {
      return response("Room temporarily full", 503);
    }

    const pair = new WebSocketPair();
    const client = pair[0];
    const server = pair[1];

    const ip = request.headers.get("CF-Connecting-IP") || "unknown";
    const ipHash = await sha256(ip);

    this.state.acceptWebSocket(server);
    server.serializeAttachment({
      authenticated: false,
      role: null,
      ipHash,
      connectedAt: Date.now()
    });

    await this.state.storage.setAlarm(Date.now() + AUTH_TIMEOUT_MS);

    return new Response(null, {
      status: 101,
      webSocket: client
    });
  }

  async allowAttempt(ipHash) {
    const key = `attempts:${ipHash}`;
    const now = Date.now();

    return this.state.storage.transaction(async tx => {
      const saved = await tx.get(key) || [];
      const recent = saved.filter(t => now - t < 60_000);

      if (recent.length >= 5) {
        await tx.put(key, recent);
        return false;
      }

      recent.push(now);
      await tx.put(key, recent);
      return true;
    });
  }

  getAttachment(socket) {
    try {
      return socket.deserializeAttachment() || {};
    } catch {
      return {};
    }
  }

  socketsFor(role) {
    return this.state.getWebSockets().filter(socket => {
      const a = this.getAttachment(socket);
      return a.authenticated === true && a.role === role;
    });
  }

  sendToRole(role, data) {
    for (const socket of this.socketsFor(role)) {
      sendJson(socket, data);
    }
  }

  async webSocketMessage(socket, raw) {
    if (typeof raw !== "string" || raw.length > MAX_MESSAGE_SIZE) {
      socket.close(1009, "Message too large");
      return;
    }

    let data;
    try {
      data = JSON.parse(raw);
    } catch {
      socket.close(1008, "Invalid message");
      return;
    }

    const attachment = this.getAttachment(socket);

    if (!attachment.authenticated) {
      if (data.type !== "auth") {
        socket.close(1008, "Authentication required");
        return;
      }

      const allowed = await this.allowAttempt(attachment.ipHash);
      if (!allowed) {
        socket.close(1008, "Too many attempts");
        return;
      }

      const validLink = await sameSecret(
        data.accessToken,
        this.env.ACCESS_LINK_TOKEN
      );

      const validRole =
        data.role === "owner" || data.role === "guest";

      const validGuestCode =
        data.role !== "guest" ||
        await sameSecret(data.code, this.env.GUEST_CODE);

      if (!validLink || !validRole || !validGuestCode) {
        sendJson(socket, { type: "auth_error" });
        socket.close(1008, "Authentication failed");
        return;
      }

      if (this.socketsFor(data.role).length > 0) {
        sendJson(socket, { type: "already_connected" });
        socket.close(1008, "This role is already connected");
        return;
      }

      socket.serializeAttachment({
        ...attachment,
        authenticated: true,
        role: data.role
      });

      sendJson(socket, { type: "ready", role: data.role });

      if (data.role === "guest") {
        this.sendToRole("owner", {
          type: "guest_status",
          online: true
        });
      } else {
        sendJson(socket, {
          type: "guest_status",
          online: this.socketsFor("guest").length > 0
        });
      }
      return;
    }

    const role = attachment.role;
    if (data.type === "ping") {
      sendJson(socket, { type: "pong" });
      return;
    }

    const peerRole = role === "owner" ? "guest" : "owner";
    const peers = this.socketsFor(peerRole);

    if (data.type === "message") {
      if (
        typeof data.id !== "string" ||
        typeof data.ciphertext !== "string" ||
        data.ciphertext.length > 12_000
      ) {
        sendJson(socket, { type: "invalid_message" });
        return;
      }

      if (peers.length === 0) {
        sendJson(socket, { type: "peer_offline", id: data.id });
        return;
      }

      for (const peer of peers) {
        sendJson(peer, {
          type: "message",
          id: data.id,
          ciphertext: data.ciphertext
        });
      }
      return;
    }

    if (["typing", "seen", "clear", "session_end"].includes(data.type)) {
      const event = { type: data.type };

      if (data.type === "typing") {
        event.active = data.active === true;
      }

      if (data.type === "seen") {
        if (typeof data.id !== "string") return;
        event.id = data.id;
      }

      for (const peer of peers) {
        sendJson(peer, event);
      }
    }
  }

  async alarm() {
    const now = Date.now();
    let nextDeadline = Infinity;

    for (const socket of this.state.getWebSockets()) {
      const a = this.getAttachment(socket);

      if (a.authenticated) continue;

      const deadline = a.connectedAt + AUTH_TIMEOUT_MS;

      if (now >= deadline) {
        try {
          socket.close(1008, "Authentication timeout");
        } catch {}
      } else {
        nextDeadline = Math.min(nextDeadline, deadline);
      }
    }

    if (nextDeadline !== Infinity) {
      await this.state.storage.setAlarm(nextDeadline);
    }
  }

  async webSocketClose(socket) {
    const a = this.getAttachment(socket);

    if (a.role === "guest" && a.authenticated) {
      this.sendToRole("owner", {
        type: "guest_status",
        online: this.socketsFor("guest").length > 1
      });
    }
  }

  webSocketError(socket) {
    try {
      socket.close();
    } catch {}
  }
}
