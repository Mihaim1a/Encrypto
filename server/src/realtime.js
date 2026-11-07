
"use strict";

const { WebSocketServer, WebSocket } = require("ws");

const {
    authenticateCookieHeader,
    isSessionActive
} = require("./session");

const connections = new Map();

const allowedOrigins = new Set(
    (
        process.env.ENCRYPTO_ALLOWED_ORIGINS ||
        "http://localhost:3000,http://127.0.0.1:3000"
    )
        .split(",")
        .map(origin => origin.trim())
        .filter(Boolean)
);

function rejectUpgrade(socket, status, reason) {
    socket.end(
        `HTTP/1.1 ${status} ${reason}\r\n` +
        "Connection: close\r\n" +
        "Content-Length: 0\r\n\r\n"
    );
}

function setupRealtime(server) {
    const wss = new WebSocketServer({
        noServer: true,
        maxPayload: 1024,
        perMessageDeflate: false
    });

    server.on("upgrade", (req, socket, head) => {
        let pathname;

        try {
            const url = new URL(req.url, "http://localhost");

            if (url.search) {
                rejectUpgrade(socket, 400, "Bad Request");
                return;
            }

            pathname = url.pathname;
        } catch {
            rejectUpgrade(socket, 400, "Bad Request");
            return;
        }

        if (pathname !== "/ws") {
            rejectUpgrade(socket, 404, "Not Found");
            return;
        }

        if (req.method !== "GET") {
            rejectUpgrade(socket, 405, "Method Not Allowed");
            return;
        }

        // Prevent cross-origin websites from opening
        // authenticated WebSocket connections.
        if (!allowedOrigins.has(req.headers.origin)) {
            rejectUpgrade(socket, 403, "Forbidden");
            return;
        }

        let session;

        try {
            session = authenticateCookieHeader(
                req.headers.cookie
            );
        } catch {
            rejectUpgrade(socket, 500, "Internal Server Error");
            return;
        }

        if (!session) {
            rejectUpgrade(socket, 401, "Unauthorized");
            return;
        }

        wss.handleUpgrade(req, socket, head, ws => {
            ws.userId = session.user.id;
            ws.tokenHash = session.tokenHash;
            ws.isAlive = true;

            wss.emit("connection", ws);
        });
    });

    wss.on("connection", ws => {
        const userId = ws.userId;

        if (!connections.has(userId)) {
            connections.set(userId, new Set());
        }

        const userConnections = connections.get(userId);

        // Limit simultaneous WebSocket connections per user.
        if (userConnections.size >= 5) {
            ws.close(1008, "Too many connections");
            return;
        }

        userConnections.add(ws);

        ws.on("pong", () => {
            ws.isAlive = true;
        });

        // Clients send messages through authenticated HTTP.
        // This socket only delivers server notifications.
        ws.on("message", () => {
            ws.close(1008, "Notifications only");
        });

        ws.on("error", () => {});

        ws.on("close", () => {
            userConnections.delete(ws);

            if (userConnections.size === 0) {
                connections.delete(userId);
            }
        });

        ws.send(JSON.stringify({
            type: "connected"
        }));
    });

    // Detect disconnected sockets and revoked sessions.
    const heartbeat = setInterval(() => {
        for (const ws of wss.clients) {
            if (
                !isSessionActive(ws.userId, ws.tokenHash)
            ) {
                ws.close(1008, "Session expired");
                continue;
            }

            if (!ws.isAlive) {
                ws.terminate();
                continue;
            }

            ws.isAlive = false;
            ws.ping();
        }
    }, 30000);

    heartbeat.unref();

    server.on("close", () => {
        clearInterval(heartbeat);
        wss.close();
    });

    console.log("WebSocket notifications initialized");
}

function notifyMessageAvailable(recipientId, messageId) {
    const userConnections = connections.get(recipientId);

    if (!userConnections) {
        return;
    }

    const notification = JSON.stringify({
        type: "message_available",
        messageId
    });

    for (const ws of userConnections) {
        if (ws.readyState !== WebSocket.OPEN) {
            continue;
        }

        if (!isSessionActive(ws.userId, ws.tokenHash)) {
            ws.close(1008, "Session expired");
            continue;
        }

        ws.send(notification);
    }
}

module.exports = {
    setupRealtime,
    notifyMessageAvailable
};
