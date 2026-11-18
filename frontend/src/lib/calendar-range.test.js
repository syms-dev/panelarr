import { describe, expect, it } from "vitest";

import { buildFeedUrl, localDayRange, monthRange } from "./calendar-range";

describe("calendar range", () => {
  it("sends local-midnight instants with an exclusive end", () => {
    const { start, end } = monthRange(new Date(2026, 1, 14, 15, 30));
    expect(start).toBe(new Date(2026, 1, 1).toISOString());
    expect(end).toBe(new Date(2026, 2, 1).toISOString());
  });

  it("end is the midnight after the last visible day", () => {
    const { end } = localDayRange(new Date(2026, 0, 31, 23, 59), new Date(2026, 11, 31, 8));
    expect(end).toBe(new Date(2027, 0, 1).toISOString());
  });
});

describe("buildFeedUrl", () => {
  it("builds an absolute URL including the token", () => {
    const url = buildFeedUrl("http://host:8000", "abc", { kind: "all" });
    expect(url).toBe("http://host:8000/api/calendar/feed.ics?kind=all&token=abc");
  });
});
