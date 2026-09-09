import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { api } from "./client";

describe("api client", () => {
  beforeEach(() => {
    globalThis.fetch = vi.fn();
  });
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("sendChat posts to /api/chat with the right body", async () => {
    const mockResponse = { event_id: "evt_1", session_id: "ses_1", reply: "hi", tool_name: null, tool_result: null, security: {}, latency_ms: 1 };
    (globalThis.fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      ok: true,
      json: async () => mockResponse,
    });

    const result = await api.sendChat("usr_1", "hello", "ses_1");

    expect(globalThis.fetch).toHaveBeenCalledWith(
      "/api/chat",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({ user_id: "usr_1", message: "hello", session_id: "ses_1" }),
      }),
    );
    expect(result).toEqual(mockResponse);
  });

  it("throws a descriptive error on a non-ok response", async () => {
    (globalThis.fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      ok: false,
      status: 404,
      statusText: "Not Found",
      json: async () => ({ detail: "Unknown user_id: usr_x" }),
    });

    await expect(api.sendChat("usr_x", "hello")).rejects.toThrow(/Unknown user_id/);
  });

  it("listEvents builds query params correctly", async () => {
    (globalThis.fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({ ok: true, json: async () => [] });
    await api.listEvents({ limit: 10, session_id: "ses_42" });
    const calledUrl = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0][0] as string;
    expect(calledUrl).toContain("limit=10");
    expect(calledUrl).toContain("session_id=ses_42");
  });
});
