"use strict";

const request = require("supertest");
const { app, PLAN_PRICE_CENTS } = require("../server");

// ---------------------------------------------------------------------------
// Helper: set up a session with a CSRF token and userId via the test-only
// login shim, then return an agent that carries the session cookie.
// ---------------------------------------------------------------------------
async function createAuthedAgent() {
  const agent = request.agent(app);

  // Seed session data via the test-login endpoint
  await agent.post("/api/test-login").send({ userId: "user-test-001" });

  // Obtain a CSRF token (stored in session by GET /api/csrf-token)
  const csrfRes = await agent.get("/api/csrf-token");
  const csrfToken = csrfRes.body.csrfToken;

  return { agent, csrfToken };
}

// ---------------------------------------------------------------------------
// POST /api/ai/chat – authentication
// ---------------------------------------------------------------------------
describe("POST /api/ai/chat – authentication", () => {
  it("returns 401 with {error:'unauthorized'} when no session exists", async () => {
    const freshAgent = request.agent(app);
    // Get a CSRF token on a fresh session (no userId)
    const csrfRes = await freshAgent.get("/api/csrf-token");
    const csrfToken = csrfRes.body.csrfToken;

    const res = await freshAgent
      .post("/api/ai/chat")
      .set("Content-Type", "application/json")
      .set("X-CSRF-Token", csrfToken)
      .send({ message: "hello" });

    expect(res.status).toBe(401);
    expect(res.body).toEqual({ error: "unauthorized" });
  });

  it("returns 403 when X-CSRF-Token header is absent", async () => {
    const { agent } = await createAuthedAgent();
    const res = await agent
      .post("/api/ai/chat")
      .set("Content-Type", "application/json")
      .send({ message: "hello" });

    expect(res.status).toBe(403);
    expect(res.body).toEqual({ error: "forbidden" });
  });

  it("returns 403 when X-CSRF-Token does not match session token", async () => {
    const { agent } = await createAuthedAgent();
    const res = await agent
      .post("/api/ai/chat")
      .set("Content-Type", "application/json")
      .set("X-CSRF-Token", "wrong-token")
      .send({ message: "hello" });

    expect(res.status).toBe(403);
    expect(res.body).toEqual({ error: "forbidden" });
  });

  it("returns 400 when message is missing", async () => {
    const { agent, csrfToken } = await createAuthedAgent();
    const res = await agent
      .post("/api/ai/chat")
      .set("Content-Type", "application/json")
      .set("X-CSRF-Token", csrfToken)
      .send({});

    expect(res.status).toBe(400);
    expect(res.body.error).toBe("message is required");
  });

  it("returns 400 when message is an empty string", async () => {
    const { agent, csrfToken } = await createAuthedAgent();
    const res = await agent
      .post("/api/ai/chat")
      .set("Content-Type", "application/json")
      .set("X-CSRF-Token", csrfToken)
      .send({ message: "   " });

    expect(res.status).toBe(400);
    expect(res.body.error).toBe("message is required");
  });
});

// ---------------------------------------------------------------------------
// GET /api/csrf-token
// ---------------------------------------------------------------------------
describe("GET /api/csrf-token", () => {
  it("returns a CSRF token in the response body", async () => {
    const res = await request(app).get("/api/csrf-token");

    expect(res.status).toBe(200);
    expect(typeof res.body.csrfToken).toBe("string");
    // 32 random bytes → 64 hex characters
    expect(res.body.csrfToken).toHaveLength(64);
  });
});

// ---------------------------------------------------------------------------
// Revenue number display
// ---------------------------------------------------------------------------
describe("Revenue number display", () => {
  it("exports PLAN_PRICE_CENTS as 1999", () => {
    expect(PLAN_PRICE_CENTS).toBe(1999);
  });

  it("converts PLAN_PRICE_CENTS to $19.99 (not $0.20)", () => {
    const planPriceDollars = (PLAN_PRICE_CENTS / 100).toFixed(2);

    expect(planPriceDollars).toBe("19.99");
    // Guard against the off-by-100 bug: dividing the dollar value again
    expect(Number(planPriceDollars)).toBeGreaterThan(1);
  });
});
