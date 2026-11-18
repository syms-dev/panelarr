import { describe, expect, it } from "vitest";

import { stripSecrets } from "./use-setup";

describe("stripSecrets", () => {
  it("removes passwords, API keys, tokens and notification secrets", () => {
    const state = {
      auth: { mode: "basic", username: "admin", password: "pw", confirmPassword: "pw", proxyHeader: "Remote-User" },
      services: {
        sonarr: { url: "http://sonarr:8989", api_key: "k" },
        plex: { url: "http://plex:32400", token: "t" },
      },
      notification: { type: "discord", name: "d", config: { webhook_url: "https://discord/x", bot_token: "b" } },
      selectedDisks: ["/data"],
    };
    const safe = stripSecrets(state);
    expect(safe.auth).toEqual({ mode: "basic", username: "admin", proxyHeader: "Remote-User" });
    expect(safe.services.sonarr).toEqual({ url: "http://sonarr:8989" });
    expect(safe.services.plex).toEqual({ url: "http://plex:32400" });
    expect(safe.notification.config).toEqual({});
    expect(safe.selectedDisks).toEqual(["/data"]);
    expect(JSON.stringify(safe)).not.toMatch(/pw|"k"|discord\/x/);
  });
});
