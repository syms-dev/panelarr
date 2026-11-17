import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { apiFetch, extractDetail, safeNextPath } from "./api";

function jsonResponse(status, body) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

describe("safeNextPath", () => {
  it("accepts same-origin relative paths", () => {
    expect(safeNextPath("/movies?x=1")).toBe("/movies?x=1");
  });

  it.each(["//evil.com", "/\\evil.com", "https://evil.com", "movies", "", null, undefined, "/login"])(
    "rejects %s",
    (v) => {
      expect(safeNextPath(v)).toBeNull();
    },
  );
});

describe("extractDetail", () => {
  it("handles strings, validation arrays and fallbacks", () => {
    expect(extractDetail("boom", "x")).toBe("boom");
    expect(extractDetail([{ msg: "bad cidr" }, { msg: "other" }], "x")).toBe("bad cidr; other");
    expect(extractDetail(undefined, "fallback")).toBe("fallback");
  });
});

describe("apiFetch redirects", () => {
  const assign = vi.fn();
  const originalLocation = window.location;

  beforeEach(() => {
    assign.mockReset();
    Object.defineProperty(window, "location", {
      configurable: true,
      value: { pathname: "/movies", search: "?q=a", hash: "", assign },
    });
  });

  afterEach(() => {
    Object.defineProperty(window, "location", { configurable: true, value: originalLocation });
    vi.restoreAllMocks();
  });

  it("redirects 401 to /login preserving the current path as next", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(jsonResponse(401, { detail: "no" }));
    await expect(apiFetch("/media/movies")).rejects.toMatchObject({ status: 401 });
    expect(assign).toHaveBeenCalledWith("/login?next=%2Fmovies%3Fq%3Da");
  });

  it("does not redirect 401 from /auth/ endpoints", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(jsonResponse(401, { detail: "Invalid credentials" }));
    await expect(apiFetch("/auth/login", { method: "POST", body: {} })).rejects.toThrow("Invalid credentials");
    expect(assign).not.toHaveBeenCalled();
  });

  it("routes 403 setup_required to /setup, not /login", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      jsonResponse(403, { detail: "Setup required", code: "setup_required" }),
    );
    await expect(apiFetch("/config")).rejects.toMatchObject({ status: 403, code: "setup_required" });
    expect(assign).toHaveBeenCalledWith("/setup");
  });

  it("surfaces backend detail for 422 responses", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      jsonResponse(422, { detail: "Re-enter the API key when changing the URL" }),
    );
    await expect(apiFetch("/config", { method: "PUT", body: {} })).rejects.toThrow(
      "Re-enter the API key when changing the URL",
    );
    expect(assign).not.toHaveBeenCalled();
  });

  it("merges custom headers", async () => {
    const spy = vi.spyOn(globalThis, "fetch").mockResolvedValue(jsonResponse(200, { ok: true }));
    await apiFetch("/setup/reset", { method: "POST", headers: { "X-Confirm-Reset": "true" } });
    expect(spy.mock.calls[0][1].headers).toMatchObject({
      "Content-Type": "application/json",
      "X-Confirm-Reset": "true",
    });
  });
});
