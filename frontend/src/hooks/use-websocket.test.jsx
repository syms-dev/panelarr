import { act, renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { backoffDelay, MAX_DELAY_MS, terminalStatusFor, useWebSocket } from "./use-websocket";

class FakeSocket {
  static instances = [];
  static OPEN = 1;
  constructor(url) {
    this.url = url;
    this.readyState = 0;
    FakeSocket.instances.push(this);
  }
  close() {
    this.closed = true;
  }
  open() {
    this.readyState = 1;
    this.onopen?.();
  }
  serverClose(code) {
    this.onclose?.({ code });
  }
}

describe("close-code helpers", () => {
  it("treats auth/origin/bad-name/stopped as terminal", () => {
    expect(terminalStatusFor(4401)).toBe("session_expired");
    expect(terminalStatusFor(4403)).toBe("forbidden");
    expect(terminalStatusFor(4400)).toBe("bad_request");
    expect(terminalStatusFor(4000)).toBe("stopped");
    expect(terminalStatusFor(4429)).toBeNull();
    expect(terminalStatusFor(1006)).toBeNull();
  });

  it("backs off exponentially with a cap", () => {
    expect(backoffDelay(0, 1006)).toBe(1000);
    expect(backoffDelay(2, 1006)).toBe(4000);
    expect(backoffDelay(20, 1011)).toBe(MAX_DELAY_MS);
    expect(backoffDelay(0, 4429)).toBeGreaterThanOrEqual(5000);
  });
});

describe("useWebSocket", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    FakeSocket.instances = [];
    vi.stubGlobal("WebSocket", FakeSocket);
  });
  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });

  it("does not reconnect after 4401 and reports session_expired", () => {
    const { result } = renderHook(() => useWebSocket("/ws/logs/x"));
    act(() => FakeSocket.instances[0].open());
    act(() => FakeSocket.instances[0].serverClose(4401));
    act(() => vi.advanceTimersByTime(120_000));
    expect(FakeSocket.instances).toHaveLength(1);
    expect(result.current.status).toBe("session_expired");
  });

  it.each([4403, 4400])("does not reconnect after %i", (code) => {
    renderHook(() => useWebSocket("/ws/logs/x"));
    act(() => FakeSocket.instances[0].serverClose(code));
    act(() => vi.advanceTimersByTime(120_000));
    expect(FakeSocket.instances).toHaveLength(1);
  });

  it("keeps backing off on repeated accept-then-close 4429 (no storm)", () => {
    renderHook(() => useWebSocket("/ws/logs/x"));
    const delays = [];
    for (let i = 0; i < 4; i++) {
      const ws = FakeSocket.instances[FakeSocket.instances.length - 1];
      act(() => ws.open());
      const countBefore = FakeSocket.instances.length;
      act(() => ws.serverClose(4429));
      // Not reconnected immediately.
      expect(FakeSocket.instances).toHaveLength(countBefore);
      let waited = 0;
      while (FakeSocket.instances.length === countBefore && waited < MAX_DELAY_MS) {
        act(() => vi.advanceTimersByTime(500));
        waited += 500;
      }
      delays.push(waited);
    }
    expect(delays[0]).toBeGreaterThanOrEqual(5000);
    expect(delays[3]).toBeGreaterThan(delays[1]);
  });

  it("stops reconnecting on unmount", () => {
    const { unmount } = renderHook(() => useWebSocket("/ws/logs/x"));
    act(() => FakeSocket.instances[0].serverClose(1006));
    unmount();
    act(() => vi.advanceTimersByTime(120_000));
    expect(FakeSocket.instances).toHaveLength(1);
  });

  it("reconnects after 1006", () => {
    renderHook(() => useWebSocket("/ws/logs/x"));
    act(() => FakeSocket.instances[0].serverClose(1006));
    act(() => vi.advanceTimersByTime(1000));
    expect(FakeSocket.instances).toHaveLength(2);
  });
});
