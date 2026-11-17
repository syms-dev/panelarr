import { describe, expect, it } from "vitest";

import { waitForNewVersion } from "./use-update";

const noSleep = () => Promise.resolve();

function sequence(values) {
  let i = 0;
  return () => Promise.resolve(values[Math.min(i++, values.length - 1)]);
}

describe("waitForNewVersion", () => {
  it("does not finish while the OLD version still answers", async () => {
    const result = await waitForNewVersion({
      preVersion: "0.3.0",
      fetchVersion: sequence(["0.3.0", "0.3.0", "0.3.0"]),
      intervalMs: 1000,
      timeoutMs: 3000,
      sleep: noSleep,
    });
    expect(result).toBe("timeout");
  });

  it("finishes once the version changes", async () => {
    const result = await waitForNewVersion({
      preVersion: "0.3.0",
      fetchVersion: sequence(["0.3.0", "0.3.0", "0.4.0"]),
      intervalMs: 1000,
      timeoutMs: 10_000,
      sleep: noSleep,
    });
    expect(result).toBe("updated");
  });

  it("finishes when the server went down and came back", async () => {
    const result = await waitForNewVersion({
      preVersion: "0.3.0",
      fetchVersion: sequence(["0.3.0", null, null, "0.3.0"]),
      intervalMs: 1000,
      timeoutMs: 10_000,
      sleep: noSleep,
    });
    expect(result).toBe("updated");
  });

  it("can be cancelled", async () => {
    const result = await waitForNewVersion({
      preVersion: "1",
      fetchVersion: sequence(["1"]),
      sleep: noSleep,
      isCancelled: () => true,
    });
    expect(result).toBe("cancelled");
  });
});
