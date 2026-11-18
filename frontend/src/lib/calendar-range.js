/**
 * Calendar range helpers. The backend accepts ISO-8601 instants with an
 * EXCLUSIVE end, so we send local-midnight instants.
 */

/**
 * Convert first/last visible local days into start/end ISO instants.
 *
 * @param {Date} firstDay First visible day (any time-of-day on that local day).
 * @param {Date} lastDay Last visible day (inclusive, any time-of-day).
 * @returns {{start: string, end: string}} start = local midnight of firstDay,
 *   end = local midnight of the day AFTER lastDay (exclusive).
 */
export function localDayRange(firstDay, lastDay) {
  const start = new Date(firstDay.getFullYear(), firstDay.getMonth(), firstDay.getDate());
  const end = new Date(lastDay.getFullYear(), lastDay.getMonth(), lastDay.getDate() + 1);
  return { start: start.toISOString(), end: end.toISOString() };
}

/**
 * Range covering the whole local month containing `d`.
 *
 * @param {Date} d Any date in the month.
 * @returns {{start: string, end: string}} ISO instants (end exclusive).
 */
export function monthRange(d) {
  return localDayRange(
    new Date(d.getFullYear(), d.getMonth(), 1),
    new Date(d.getFullYear(), d.getMonth() + 1, 0),
  );
}

/**
 * Build the absolute ICS feed URL.
 *
 * @param {string} origin e.g. window.location.origin.
 * @param {string|undefined} token Calendar token.
 * @param {Record<string,string>} [filters] Extra query params.
 * @returns {string} Absolute feed URL including ?token=.
 */
export function buildFeedUrl(origin, token, filters = {}) {
  const params = new URLSearchParams(filters);
  if (token) params.set("token", token);
  return `${origin}/api/calendar/feed.ics?${params.toString()}`;
}
