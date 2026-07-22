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
// Auth middleware – requires a valid session cookie
// ---------------------------------------------------------------------------
function requireAuth(req, res, next) {
  const sessionToken = req.cookies && req.cookies.session;
  if (!sessionToken) {
    return res.status(401).json({ error: "unauthorized" });
  }
  // In a real app, validate the session token against a DB / JWT secret.
  // For now, treat the cookie value itself as the user id.
  req.user = { id: sessionToken };
  next();
}

// ---------------------------------------------------------------------------
// POST /api/ai/chat
// ---------------------------------------------------------------------------
app.post("/api/ai/chat", requireAuth, async (req, res) => {
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

module.exports = app; // export for testing
