"use strict";

const crypto = require("crypto");
const express = require("express");
const session = require("express-session");
const OpenAI = require("openai").default ?? require("openai");

const app = express();
app.use(express.json());

// ---------------------------------------------------------------------------
// Session middleware – keeps session data server-side; the client only holds
// an opaque session ID cookie.  Use a strong, rotating secret in production.
// ---------------------------------------------------------------------------
app.use(
  session({
    secret: process.env.SESSION_SECRET ?? crypto.randomBytes(32).toString("hex"),
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "strict",
      secure: process.env.NODE_ENV === "production",
    },
  }),
);

// ---------------------------------------------------------------------------
// Subscription plan price stored in cents (Stripe-style), displayed in dollars
// ---------------------------------------------------------------------------
const PLAN_PRICE_CENTS = 1999; // $19.99 / month

// ---------------------------------------------------------------------------
// CSRF – synchronizer token pattern
//
// GET  /api/csrf-token  → generates a cryptographically random token, stores
//                          it in the server-side session, and returns it to
//                          the client.  The client must send it back via the
//                          X-CSRF-Token header on every state-changing request.
//
// requireCsrf middleware → compares X-CSRF-Token header against the session-
//                           stored token using timingSafeEqual.
// ---------------------------------------------------------------------------
app.get("/api/csrf-token", (req, res) => {
  const token = crypto.randomBytes(32).toString("hex");
  req.session.csrfToken = token;
  res.json({ csrfToken: token });
});

function requireCsrf(req, res, next) {
  const headerToken = req.get("X-CSRF-Token");
  const sessionToken = req.session && req.session.csrfToken;

  if (!headerToken || !sessionToken) {
    return res.status(403).json({ error: "forbidden" });
  }

  try {
    const a = Buffer.from(headerToken, "utf8");
    const b = Buffer.from(sessionToken, "utf8");
    const match =
      a.length === b.length && crypto.timingSafeEqual(a, b);
    if (!match) {
      return res.status(403).json({ error: "forbidden" });
    }
  } catch {
    return res.status(403).json({ error: "forbidden" });
  }

  next();
}

// ---------------------------------------------------------------------------
// Auth middleware – requires a valid user ID in the session
// ---------------------------------------------------------------------------
function requireAuth(req, res, next) {
  const userId = req.session && req.session.userId;
  if (!userId) {
    return res.status(401).json({ error: "unauthorized" });
  }
  req.user = { id: userId };
  next();
}

// ---------------------------------------------------------------------------
// Test-only login shim – seeds userId into the session so integration tests
// can simulate an authenticated user without a real auth flow.
// Must only be registered in non-production environments.
// ---------------------------------------------------------------------------
if (process.env.NODE_ENV !== "production") {
  app.post("/api/test-login", (req, res) => {
    const { userId } = req.body ?? {};
    if (!userId) {
      return res.status(400).json({ error: "userId required" });
    }
    req.session.userId = userId;
    res.json({ ok: true });
  });
}

// ---------------------------------------------------------------------------
// POST /api/ai/chat
// ---------------------------------------------------------------------------
app.post("/api/ai/chat", requireCsrf, requireAuth, async (req, res) => {
  const { message } = req.body ?? {};

  if (!message || typeof message !== "string" || message.trim() === "") {
    return res.status(400).json({ error: "message is required" });
  }

  const apiKey = process.env.OPENAI_API_KEY;
  if (!apiKey) {
    return res.status(500).json({ error: "AI service not configured" });
  }

  try {
    const openai = new OpenAI({ apiKey });

    const completion = await openai.chat.completions.create({
      model: "gpt-4o-mini",
      messages: [{ role: "user", content: message.trim() }],
    });

    if (!completion.choices || completion.choices.length === 0) {
      return res.status(502).json({ error: "AI service returned no response" });
    }

    const reply = completion.choices[0].message.content;
    const usage = completion.usage;

    // Revenue: divide stored cents by 100 to get a human-readable dollar amount
    const planPriceDollars = (PLAN_PRICE_CENTS / 100).toFixed(2); // "19.99"

    // Analytics – log to stdout; wire to your analytics sink in production
    const analyticsRecord = {
      user_id: req.user.id,
      prompt_tokens: usage.prompt_tokens,
      completion_tokens: usage.completion_tokens,
      total_tokens: usage.total_tokens,
      plan_revenue: `$${planPriceDollars}`,
      timestamp: new Date().toISOString(),
    };
    console.log("[analytics]", JSON.stringify(analyticsRecord));

    return res.json({
      reply,
      analytics: {
        tokens: usage.total_tokens,
        plan_revenue: `$${planPriceDollars}`,
      },
    });
  } catch (err) {
    console.error("[ai/chat] error:", err.message ?? err);
    return res.status(502).json({ error: "AI service error" });
  }
});

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------
const PORT = process.env.PORT ?? 3000;

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Server listening on http://localhost:${PORT}`);
  });
}

module.exports = { app, PLAN_PRICE_CENTS }; // export for testing
