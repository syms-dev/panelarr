// Regression test for docs/audits/2026-11-17-frontend.md, finding F1 (fixed). The attack
// case reproduced the defect before the fix, when it was marked `it.fails`.
import { describe, expect, it } from "vitest";

import { stripSecrets } from "./use-setup";

const SECRET_PATH = ["hooks", "sweep" + "marker" + "0123456789"].join("/");

describe("stripSecrets (sweep 2026-11-17)", () => {
  it(
    "F1: drops the generic webhook URL, which is the channel credential",
    () => {
      const state = {
        notification: {
          type: "webhook",
          config: { url: `https://ntfy.example/${SECRET_PATH}` },
        },
      };
      expect(JSON.stringify(stripSecrets(state))).not.toContain(SECRET_PATH);
    },
  );

  it("guard: keeps the non-secret wizard state", () => {
    const state = {
      step: 3,
      notification: { type: "webhook", config: {} },
      thresholds: { disk_warn_pct: 80 },
    };
    const safe = stripSecrets(state);
    expect(safe.step).toBe(3);
    expect(safe.notification.type).toBe("webhook");
    expect(safe.thresholds.disk_warn_pct).toBe(80);
  });
});
