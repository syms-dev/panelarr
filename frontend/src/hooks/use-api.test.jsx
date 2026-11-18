import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, renderHook, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { toastManager } from "@/components/ui/toast";

import {
  useBlocklistDownload,
  useDeleteDownload,
  useQbitAction,
  useSetupReset,
} from "./use-api";

function wrapper({ children }) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return <QueryClientProvider client={qc}>{children}</QueryClientProvider>;
}

function jsonResponse(status, body) {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

describe("mutation result handling", () => {
  let add;
  beforeEach(() => {
    add = vi.spyOn(toastManager, "add").mockImplementation(() => "id");
  });
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("useSetupReset sends the X-Confirm-Reset header", async () => {
    const spy = vi.spyOn(globalThis, "fetch").mockResolvedValue(jsonResponse(200, { ok: true }));
    const { result } = renderHook(() => useSetupReset(), { wrapper });
    await act(() => result.current.mutateAsync());
    const [url, init] = spy.mock.calls[0];
    expect(url).toBe("/api/setup/reset");
    expect(init.method).toBe("POST");
    expect(init.headers["X-Confirm-Reset"]).toBe("true");
  });

  it("useDeleteDownload toasts an error when the backend returns ok:false", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(jsonResponse(200, { ok: false, message: "Sonarr refused" }));
    const { result } = renderHook(() => useDeleteDownload(), { wrapper });
    await act(() => result.current.mutateAsync({ source: "sonarr", id: 1 }));
    expect(add).toHaveBeenCalledWith(expect.objectContaining({ type: "error", description: "Sonarr refused" }));
    expect(add).not.toHaveBeenCalledWith(expect.objectContaining({ type: "success" }));
  });

  it("useDeleteDownload toasts success on ok:true", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(jsonResponse(200, { ok: true }));
    const { result } = renderHook(() => useDeleteDownload(), { wrapper });
    await act(() => result.current.mutateAsync({ source: "sonarr", id: 1 }));
    expect(add).toHaveBeenCalledWith(expect.objectContaining({ type: "success" }));
  });

  it("useBlocklistDownload toasts an error when ok:false", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(jsonResponse(200, { ok: false, message: "nope" }));
    const { result } = renderHook(() => useBlocklistDownload(), { wrapper });
    await act(() => result.current.mutateAsync({ source: "radarr", id: 2 }));
    expect(add).toHaveBeenCalledWith(expect.objectContaining({ type: "error", description: "nope" }));
  });

  it("useQbitAction toasts on ok:false and on HTTP failure", async () => {
    const spy = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(jsonResponse(200, { ok: false, message: "qbit down" }));
    const { result } = renderHook(() => useQbitAction(), { wrapper });
    await act(() => result.current.mutateAsync({ action: "resume", hashes: ["h"] }));
    expect(add).toHaveBeenCalledWith(expect.objectContaining({ type: "error", description: "qbit down" }));

    spy.mockResolvedValueOnce(jsonResponse(500, { detail: "boom" }));
    await act(async () => {
      await result.current.mutateAsync({ action: "pause", hashes: ["h"] }).catch(() => {});
    });
    await waitFor(() =>
      expect(add).toHaveBeenCalledWith(expect.objectContaining({ type: "error", description: "boom" })),
    );
  });
});
