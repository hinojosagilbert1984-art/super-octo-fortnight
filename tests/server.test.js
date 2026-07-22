"use strict";

const request = require("supertest");
const { app, PLAN_PRICE_CENTS } = require("../server");

// Helper: build a POST request that satisfies CSRF + auth middleware
function authedPost(path) {
  return request(app)
    .post(path)
    .set("Content-Type", "application/json")
    .set("X-Requested-With", "XMLHttpRequest")
    .set("Cookie", "session=validToken12345678");
}

// ---------------------------------------------------------------------------
// Unit tests for POST /api/ai/chat
// ---------------------------------------------------------------------------

describe("POST /api/ai/chat – authentication", () => {
  it("returns 401 with {error:'unauthorized'} when no session cookie is sent", async () => {
    const res = await request(app)
      .post("/api/ai/chat")
      .set("Content-Type", "application/json")
      .set("X-Requested-With", "XMLHttpRequest")
      .send({ message: "hello" });

    expect(res.status).toBe(401);
    expect(res.body).toEqual({ error: "unauthorized" });
  });

  it("returns 403 when the CSRF header is absent", async () => {
    const res = await request(app)
      .post("/api/ai/chat")
      .set("Content-Type", "application/json")
      .set("Cookie", "session=validToken12345678")
      .send({ message: "hello" });

    expect(res.status).toBe(403);
    expect(res.body).toEqual({ error: "forbidden" });
  });

  it("returns 400 when message is missing (cookie + CSRF header present)", async () => {
    const res = await authedPost("/api/ai/chat").send({});

    expect(res.status).toBe(400);
    expect(res.body.error).toBe("message is required");
  });

  it("returns 400 when message is an empty string", async () => {
    const res = await authedPost("/api/ai/chat").send({ message: "   " });

    expect(res.status).toBe(400);
    expect(res.body.error).toBe("message is required");
  });
});

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
