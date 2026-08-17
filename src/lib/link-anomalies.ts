import type { ParsedLogEvent } from "@/lib/parser/access-log";
import type { DetectedAnomaly } from "@/lib/detectors/statistical";

/**
 * The LLM anomaly pass only ever sees aggregate per-IP statistics (see
 * `summarizeEvents`), so it can name an offending IP but has no concept of
 * line numbers — it returns `lineNumbers: []`. Without resolving that IP
 * back to actual `LogEvent` rows here, those findings can never highlight
 * rows in the events table or appear on the timeline, making them look
 * second-class next to the statistical detectors' findings.
 *
 * This resolves any anomaly with a known `ip` but no `lineNumbers` against
 * the full parsed event list for the upload, and backfills a window from
 * those events' timestamps if one wasn't already set.
 */
export function linkAnomaliesToEvents(
  anomalies: DetectedAnomaly[],
  events: ParsedLogEvent[]
): DetectedAnomaly[] {
  const eventsByIp = new Map<string, ParsedLogEvent[]>();
  for (const e of events) {
    const arr = eventsByIp.get(e.ip) ?? [];
    arr.push(e);
    eventsByIp.set(e.ip, arr);
  }

  return anomalies.map((anomaly) => {
    if (anomaly.lineNumbers.length > 0 || !anomaly.ip) return anomaly;

    const ipEvents = eventsByIp.get(anomaly.ip);
    if (!ipEvents || ipEvents.length === 0) return anomaly;

    const timestamps = ipEvents.map((e) => e.timestamp.getTime());

    return {
      ...anomaly,
      lineNumbers: ipEvents.map((e) => e.lineNumber),
      windowStart: anomaly.windowStart ?? new Date(Math.min(...timestamps)),
      windowEnd: anomaly.windowEnd ?? new Date(Math.max(...timestamps)),
    };
  });
}
