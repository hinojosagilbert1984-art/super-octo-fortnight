"use strict";

const express = require("express");
const cookieParser = require("cookie-parser");
const OpenAI = require("openai").default ?? require("openai");

const app = express();
app.use(express.json());
app.use(cookieParser());

// ---------------------------------------------------------------------------
// Subscription plan price stored in cents (Stripe-style), displayed in dollars
// ---------------------------------------------------------------------------
const PLAN_PRICE_CENTS = 1999; // $19.99 / month

// ---------------------------------------------------------------------------
// CSRF protection for cookie-authenticated JSON routes.
// For cross-origin state-changing requests, browsers send a CORS preflight
// when a custom header is present. Requiring this header ensures that
// same-site form submissions (which cannot set custom headers) are rejected.
// ---------------------------------------------------------------------------
function requireJsonCsrfHeader(req, res, next) {
  const header = req.get("X-Requested-With");
  if (header !== "XMLHttpRequest") {
    return res.status(403).json({ error: "forbidden" });
  }
  next();
}

// ---------------------------------------------------------------------------
// Auth middleware – requires a valid session cookie
// ---------------------------------------------------------------------------

// Regex for an opaque session token: 8–128 URL-safe characters
const SESSION_TOKEN_RE = /^[A-Za-z0-9._~-]{8,128}$/;

function requireAuth(req, res, next) {
  const sessionToken = req.cookies && req.cookies.session;
  if (!sessionToken || !SESSION_TOKEN_RE.test(sessionToken)) {
    return res.status(401).json({ error: "unauthorized" });
  }
  // In a real app, validate the session token against a DB / JWT secret
  // and resolve a full user object before attaching it here.
  req.user = { id: sessionToken };
  next();
}

// ---------------------------------------------------------------------------
// POST /api/ai/chat
// ---------------------------------------------------------------------------
app.post("/api/ai/chat", requireJsonCsrfHeader, requireAuth, async (req, res) => {
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
