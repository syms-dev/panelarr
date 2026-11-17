/**
 * WebSocket hook with close-code aware reconnection.
 *
 * Server close codes: 4401 auth failed, 4403 bad origin, 4400 bad container
 * name, 4429 too many streams, 4000 container stopped. 4401/4403/4400/4000
 * never reconnect; everything else (4429, 1006, 1011, ...) retries with
 * exponential backoff capped at MAX_DELAY_MS. The backoff counter resets only
 * after a message was received, because the server accepts then closes, so a
 * bare "open" event is not proof of a healthy stream.
 */
import { useCallback, useEffect, useRef, useState } from "react";

export const BASE_DELAY_MS = 1000;
export const MAX_DELAY_MS = 30_000;
const TOO_MANY_STREAMS_MIN_DELAY_MS = 5000;

/** Close codes after which reconnecting can never help. */
const TERMINAL_STATUS = {
  4400: "bad_request",
  4401: "session_expired",
  4403: "forbidden",
  4000: "stopped",
};

/**
 * Decide what to do after a close event.
 *
 * @param {number} code WebSocket close code.
 * @returns {string|null} Terminal status name, or null if a retry is allowed.
 */
export function terminalStatusFor(code) {
  return TERMINAL_STATUS[code] ?? null;
}

/**
 * Backoff delay for the given attempt (0-based).
 *
 * @param {number} attempt Consecutive failed attempts so far.
 * @param {number} code Close code that triggered the retry.
 * @returns {number} Delay in ms, capped at MAX_DELAY_MS.
 */
export function backoffDelay(attempt, code) {
  const floor = code === 4429 ? TOO_MANY_STREAMS_MIN_DELAY_MS : BASE_DELAY_MS;
  return Math.min(MAX_DELAY_MS, Math.max(floor, BASE_DELAY_MS * 2 ** attempt));
}

/**
 * @param {string|null} url Path such as `/ws/logs/name`; falsy disables.
 * @param {{onMessage?: (data: string) => void, enabled?: boolean}} [options]
 * @returns {{isConnected: boolean, status: string, closeCode: number|null,
 *   send: (data: string) => void, close: () => void}} status is one of
 *   idle | connecting | open | reconnecting | session_expired | forbidden |
 *   bad_request | stopped.
 */
export function useWebSocket(url, { onMessage, enabled = true } = {}) {
  const [status, setStatus] = useState("idle");
  const [closeCode, setCloseCode] = useState(null);
  const wsRef = useRef(null);
  const reconnectAttempt = useRef(0);
  const reconnectTimer = useRef(null);
  const onMessageRef = useRef(onMessage);
  onMessageRef.current = onMessage;

  useEffect(() => {
    if (!url || !enabled) {
      setStatus("idle");
      return undefined;
    }
    let isStopped = false;
    reconnectAttempt.current = 0;
    setCloseCode(null);

    function connect() {
      if (isStopped) return;
      setStatus(reconnectAttempt.current > 0 ? "reconnecting" : "connecting");
      const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
      const ws = new WebSocket(`${protocol}//${window.location.host}${url}`);
      wsRef.current = ws;

      ws.onopen = () => {
        if (!isStopped) setStatus("open");
      };

      ws.onmessage = (event) => {
        reconnectAttempt.current = 0;
        onMessageRef.current?.(event.data);
      };

      ws.onclose = (event) => {
        if (wsRef.current === ws) wsRef.current = null;
        if (isStopped) return;
        setCloseCode(event.code);
        const terminal = terminalStatusFor(event.code);
        if (terminal) {
          setStatus(terminal);
          return;
        }
        setStatus("reconnecting");
        const delay = backoffDelay(reconnectAttempt.current, event.code);
        reconnectAttempt.current += 1;
        reconnectTimer.current = setTimeout(connect, delay);
      };

      // onerror is always followed by onclose; reconnect is handled there.
      ws.onerror = () => {};
    }

    connect();
    return () => {
      isStopped = true;
      clearTimeout(reconnectTimer.current);
      const ws = wsRef.current;
      wsRef.current = null;
      if (ws) {
        ws.onclose = null;
        ws.onmessage = null;
        ws.close();
      }
    };
  }, [url, enabled]);

  const send = useCallback((data) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(data);
    }
  }, []);

  const close = useCallback(() => {
    clearTimeout(reconnectTimer.current);
    const ws = wsRef.current;
    wsRef.current = null;
    if (ws) {
      ws.onclose = null;
      ws.close();
    }
    setStatus("idle");
  }, []);

  return { isConnected: status === "open", status, closeCode, send, close };
}
