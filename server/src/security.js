
"use strict";

const isProduction = process.env.NODE_ENV === "production";

const configuredOrigins = process.env.ENCRYPTO_ALLOWED_ORIGINS;

if (isProduction && !configuredOrigins) {
    throw new Error(
        "ENCRYPTO_ALLOWED_ORIGINS must be configured in production"
    );
}

const allowedOrigins = new Set(
    (
        configuredOrigins ||
        "http://localhost:3000,http://127.0.0.1:3000"
    )
        .split(",")
        .map(origin => origin.trim())
        .filter(Boolean)
);

function rejectRequest(res) {
    return res.status(403).json({
        error: "Untrusted request origin"
    });
}

function enforceOrigin(req, res, next) {
    if (["GET", "HEAD", "OPTIONS"].includes(req.method)) {
        return next();
    }

    const fetchSite = req.get("sec-fetch-site");

    if (fetchSite === "cross-site") {
        return rejectRequest(res);
    }

    const origin = req.get("origin");

    if (origin) {
        if (!allowedOrigins.has(origin)) {
            return rejectRequest(res);
        }

        return next();
    }

    const referer = req.get("referer");

    if (referer) {
        try {
            const refererOrigin = new URL(referer).origin;

            if (!allowedOrigins.has(refererOrigin)) {
                return rejectRequest(res);
            }

            return next();
        } catch {
            return rejectRequest(res);
        }
    }

    // Local command-line integration tests do not send
    // browser Origin or Referer headers.
    // Production fails closed when both are absent.
    if (isProduction) {
        return rejectRequest(res);
    }

    return next();
}

module.exports = { enforceOrigin };
