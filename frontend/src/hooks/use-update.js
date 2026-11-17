/**
 * Self-update orchestration.
 *
 * After triggering the update the old container keeps answering until it is
 * replaced, so a bare "health is OK" check reloads the OLD UI. Instead we poll
 * the public /api/setup/status endpoint and reload only once the reported
 * version differs from the pre-update version (or the server went down and
 * came back, which means the container was recreated). A timeout produces an
 * error state.
 */
import { useCallback, useSyncExternalStore } from "react";

import { useSelfUpdate } from "@/hooks/use-api";
import { toastManager } from "@/components/ui/toast";

export const POLL_INTERVAL_MS = 2000;
export const UPDATE_TIMEOUT_MS = 180_000;

/**
 * Read the running backend version from the public setup-status endpoint.
 *
 * @returns {Promise<string|null>} Version string, or null if unreachable/invalid.
 */
export async function fetchRunningVersion() {
  try {
    const resp = await fetch("/api/setup/status", { cache: "no-store" });
    if (!resp.ok) return null;
    const data = await resp.json();
    return typeof data?.version === "string" ? data.version : null;
  } catch {
    return null;
  }
}

/**
 * Poll until the backend is a new instance.
 *
 * @param {object} opts
 * @param {string|null} opts.preVersion Version before the update.
 * @param {() => Promise<string|null>} opts.fetchVersion Version probe.
 * @param {number} [opts.intervalMs] Poll interval.
 * @param {number} [opts.timeoutMs] Give up after this long.
 * @param {(ms: number) => Promise<void>} [opts.sleep] Injectable delay.
 * @param {() => boolean} [opts.isCancelled] Abort check.
 * @returns {Promise<"updated"|"timeout"|"cancelled">} Outcome.
 */
export async function waitForNewVersion({
  preVersion,
  fetchVersion,
  intervalMs = POLL_INTERVAL_MS,
  timeoutMs = UPDATE_TIMEOUT_MS,
  sleep = (ms) => new Promise((r) => setTimeout(r, ms)),
  isCancelled = () => false,
}) {
  let elapsed = 0;
  let hasSeenOutage = false;
  while (elapsed < timeoutMs) {
    await sleep(intervalMs);
    elapsed += intervalMs;
    if (isCancelled()) return "cancelled";
    const version = await fetchVersion();
    if (version === null) {
      hasSeenOutage = true;
      continue;
    }
    if (preVersion !== null && version !== preVersion) return "updated";
    if (hasSeenOutage) return "updated";
  }
  return "timeout";
}

let state = { isUpdating: false, error: null };
const listeners = new Set();

function subscribe(cb) {
  listeners.add(cb);
  return () => listeners.delete(cb);
}

function getSnapshot() {
  return state;
}

function setState(next) {
  state = { ...state, ...next };
  listeners.forEach((cb) => cb());
}

/** Reset module state (tests only). */
export function resetUpdateState() {
  state = { isUpdating: false, error: null };
}

/**
 * @returns {{isUpdating: boolean, updateError: string|null,
 *   triggerUpdate: () => Promise<void>}} Update controls and status.
 */
export function useUpdate() {
  const selfUpdate = useSelfUpdate();
  const snapshot = useSyncExternalStore(subscribe, getSnapshot);

  const triggerUpdate = useCallback(async () => {
    if (state.isUpdating) return;
    setState({ isUpdating: true, error: null });

    const fail = (message) => {
      setState({ isUpdating: false, error: message });
      toastManager.add({ type: "error", title: "Update failed", description: message });
    };

    const preVersion = await fetchRunningVersion();
    try {
      await selfUpdate.mutateAsync();
    } catch (err) {
      // An HTTP error (has a status) is a real failure. A network error means
      // the container died mid-response, which is expected during an update.
      if (typeof err?.status === "number") {
        fail(err.message || "The server rejected the update request");
        return;
      }
    }

    const outcome = await waitForNewVersion({
      preVersion,
      fetchVersion: fetchRunningVersion,
    });
    if (outcome === "updated") {
      window.location.reload();
      return;
    }
    fail("Timed out waiting for the new version to come up. Check the container logs.");
  }, [selfUpdate]);

  return {
    isUpdating: snapshot.isUpdating,
    updateError: snapshot.error,
    triggerUpdate,
  };
}
