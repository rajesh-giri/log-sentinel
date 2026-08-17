import type { ParsedLogEvent } from "@/lib/parser/access-log";

export interface IpAggregate {
  ip: string;
  requestCount: number;
  distinctPaths: number;
  topPaths: string[];
  methods: Record<string, number>;
  statusCodes: Record<string, number>;
  errorRate: number;
  userAgents: string[];
  firstSeen: string;
  lastSeen: string;
}

export interface LogSummary {
  totalRequests: number;
  timeRange: { start: string; end: string };
  uniqueIpCount: number;
  statusCodeDistribution: Record<string, number>;
  topPaths: { path: string; count: number }[];
  topIps: IpAggregate[];
}

/**
 * Compresses a (potentially large) list of parsed events into bounded
 * aggregate statistics. This is what we hand to the LLM instead of raw log
 * lines — keeps token usage roughly constant regardless of file size, and
 * is also directly useful for the human-facing summary/timeline.
 */
export function summarizeEvents(events: ParsedLogEvent[], maxTopIps = 25): LogSummary {
  if (events.length === 0) {
    return {
      totalRequests: 0,
      timeRange: { start: "", end: "" },
      uniqueIpCount: 0,
      statusCodeDistribution: {},
      topPaths: [],
      topIps: [],
    };
  }

  const byIp = new Map<string, ParsedLogEvent[]>();
  const pathCounts = new Map<string, number>();
  const statusCounts = new Map<string, number>();

  let minTs = events[0].timestamp;
  let maxTs = events[0].timestamp;

  for (const e of events) {
    const arr = byIp.get(e.ip) ?? [];
    arr.push(e);
    byIp.set(e.ip, arr);

    pathCounts.set(e.path, (pathCounts.get(e.path) ?? 0) + 1);
    const statusKey = String(e.statusCode);
    statusCounts.set(statusKey, (statusCounts.get(statusKey) ?? 0) + 1);

    if (e.timestamp < minTs) minTs = e.timestamp;
    if (e.timestamp > maxTs) maxTs = e.timestamp;
  }

  const ipAggregates: IpAggregate[] = Array.from(byIp.entries()).map(([ip, ipEvents]) => {
    const pathCountForIp = new Map<string, number>();
    const methodCounts: Record<string, number> = {};
    const statusForIp: Record<string, number> = {};
    const uaSet = new Set<string>();
    let errorCount = 0;
    let first = ipEvents[0].timestamp;
    let last = ipEvents[0].timestamp;

    for (const e of ipEvents) {
      pathCountForIp.set(e.path, (pathCountForIp.get(e.path) ?? 0) + 1);
      methodCounts[e.method] = (methodCounts[e.method] ?? 0) + 1;
      statusForIp[String(e.statusCode)] = (statusForIp[String(e.statusCode)] ?? 0) + 1;
      uaSet.add(e.userAgent);
      if (e.statusCode >= 400) errorCount += 1;
      if (e.timestamp < first) first = e.timestamp;
      if (e.timestamp > last) last = e.timestamp;
    }

    const topPaths = Array.from(pathCountForIp.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
      .map(([p]) => p);

    return {
      ip,
      requestCount: ipEvents.length,
      distinctPaths: pathCountForIp.size,
      topPaths,
      methods: methodCounts,
      statusCodes: statusForIp,
      errorRate: errorCount / ipEvents.length,
      userAgents: Array.from(uaSet).slice(0, 3),
      firstSeen: first.toISOString(),
      lastSeen: last.toISOString(),
    };
  });

  // Prioritize the "most interesting" IPs for the LLM's limited context:
  // highest volume first, since that's where most signal concentrates.
  const topIps = ipAggregates.sort((a, b) => b.requestCount - a.requestCount).slice(0, maxTopIps);

  const topPaths = Array.from(pathCounts.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 15)
    .map(([path, count]) => ({ path, count }));

  return {
    totalRequests: events.length,
    timeRange: { start: minTs.toISOString(), end: maxTs.toISOString() },
    uniqueIpCount: byIp.size,
    statusCodeDistribution: Object.fromEntries(statusCounts),
    topPaths,
    topIps,
  };
}
