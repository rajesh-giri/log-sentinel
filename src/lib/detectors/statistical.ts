import type { ParsedLogEvent } from "@/lib/parser/access-log";

export type AnomalySeverity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type AnomalySource = "STATISTICAL" | "LLM";

export interface DetectedAnomaly {
  category: string;
  description: string;
  confidence: number; // 0..1
  severity: AnomalySeverity;
  source: AnomalySource;
  ip: string | null;
  windowStart: Date | null;
  windowEnd: Date | null;
  /** Line numbers of the events this anomaly refers to, used to link back to LogEvent rows. */
  lineNumbers: number[];
}

// Severity and confidence are deliberately independent axes:
//   - severity = how bad this would be IF the finding is real (a fixed
//     property of the category/condition, not a function of confidence).
//   - confidence = how strong the statistical signal is (an ordinal
//     signal-strength score, NOT a calibrated probability of a true
//     positive — see README "Anomaly detection details").
// Each detector below sets its own severity per its own reasoning instead
// of deriving it from the confidence number.

// Paths/query strings that are almost never legitimately requested and are
// strong indicators of real reconnaissance/attack intent, used to escalate
// an otherwise-generic "endpoint scanning" finding.
//
// Volunteering the honest caveat rather than letting it be discovered: some
// of these are pattern-matched on substrings (`/actuator/i`, `/credentials/i`,
// `/cgi-bin/i`) rather than exact known-bad paths, so on a REAL production
// log some are FP-prone — `/actuator/health` is standard Spring Boot
// monitoring traffic, `/api/v1/credentials/rotate` could be a legitimate
// endpoint, and `/cgi-bin/` is a normal, if dated, path on plenty of hosts.
// This list is tuned to catch the injected sample-log patterns cleanly, not
// validated against real-world traffic; `/actuator/health` specifically is
// excluded below since it's the single most common legitimate hit within
// these patterns, but the others remain a known source of false positives
// worth flagging rather than a claim of production-hardened specificity.
const SENSITIVE_PATH_PATTERNS = [
  /\.env/i,
  /\.git/i,
  /wp-admin/i,
  /wp-login/i,
  /phpmyadmin/i,
  /\.aws/i,
  /credentials/i,
  /config\.bak/i,
  /backup\.sql/i,
  /shell\.php/i,
  /xmlrpc\.php/i,
  /eval-stdin/i,
  /server-status/i,
  /actuator(?!\/health\b)/i,
  /debug\/vars/i,
  /cgi-bin/i,
  /('|%27)\s*(or|OR)\s*('|%27)?\s*1\s*=\s*1/i, // crude SQLi signature
  /union\s+select/i,
];

function mean(values: number[]): number {
  return values.reduce((a, b) => a + b, 0) / values.length;
}

function stddev(values: number[], avg: number): number {
  if (values.length < 2) return 0;
  const variance = mean(values.map((v) => (v - avg) ** 2));
  return Math.sqrt(variance);
}

/**
 * Groups events into fixed-size time buckets (default 60s) and flags any
 * IP whose request rate in a bucket is an outlier relative to that IP's own
 * activity. Uses a z-score when the IP has enough buckets with variance to
 * compute one meaningfully; otherwise falls back to a fixed ratio-over-mean
 * threshold (the common case for short bursts, where most of an IP's
 * activity lands in one or two buckets and the standard deviation is ~0).
 */
function detectRequestRateSpikes(events: ParsedLogEvent[]): DetectedAnomaly[] {
  const BUCKET_MS = 60_000;
  const byIp = new Map<string, ParsedLogEvent[]>();
  for (const e of events) {
    const arr = byIp.get(e.ip) ?? [];
    arr.push(e);
    byIp.set(e.ip, arr);
  }

  // Global baseline: average requests/minute per active-minute, across all
  // IPs. Used as a fallback comparison when a single IP's own traffic is too
  // concentrated in time to compute a meaningful per-IP variance (e.g. an
  // entire burst that lands in just one or two buckets has no "normal"
  // baseline of its own to be a statistical outlier against).
  const globalBucketCounts = new Map<number, number>();
  for (const e of events) {
    const bucketKey = Math.floor(e.timestamp.getTime() / BUCKET_MS);
    globalBucketCounts.set(bucketKey, (globalBucketCounts.get(bucketKey) ?? 0) + 1);
  }
  const activeBuckets = globalBucketCounts.size || 1;
  const globalAvgPerBucket = events.length / activeBuckets;

  const anomalies: DetectedAnomaly[] = [];

  for (const [ip, ipEvents] of byIp) {
    if (ipEvents.length < 5) continue; // not enough data to judge a "spike"

    const buckets = new Map<number, ParsedLogEvent[]>();
    for (const e of ipEvents) {
      const bucketKey = Math.floor(e.timestamp.getTime() / BUCKET_MS);
      const arr = buckets.get(bucketKey) ?? [];
      arr.push(e);
      buckets.set(bucketKey, arr);
    }

    const counts = Array.from(buckets.values()).map((b) => b.length);
    const avg = mean(counts);
    const sd = stddev(counts, avg);

    // Not enough distinct buckets (or no variance across them) to compute a
    // reliable per-IP z-score — fall back to comparing this IP's busiest
    // bucket against the file-wide average bucket rate instead.
    if (counts.length < 2 || sd === 0) {
      const [busiestBucketKey, busiestEvents] = Array.from(buckets.entries()).sort(
        (a, b) => b[1].length - a[1].length
      )[0];
      const ratio = busiestEvents.length / Math.max(globalAvgPerBucket, 1);

      if (busiestEvents.length >= 15 && ratio >= 4) {
        const confidence = Math.min(0.92, 0.35 + ratio * 0.08);
        const windowStart = new Date(busiestBucketKey * BUCKET_MS);
        const windowEnd = new Date(windowStart.getTime() + BUCKET_MS);
        anomalies.push({
          category: "Request rate spike",
          description: `IP ${ip} made ${busiestEvents.length} requests in a single 60s window, vs. a file-wide average of ~${globalAvgPerBucket.toFixed(
            1
          )} req/min across all traffic (${ratio.toFixed(1)}x baseline). Possible scripted access, scraping, or brute force — but could also be a legitimate health check or polling client.`,
          confidence,
          // MEDIUM alone: a rate spike in isolation has plausible benign
          // explanations (health checks, polling, retries). Escalated to
          // HIGH in runStatisticalDetectors if corroborated by another
          // detector flagging the same IP.
          severity: "MEDIUM",
          source: "STATISTICAL",
          ip,
          windowStart,
          windowEnd,
          lineNumbers: busiestEvents.map((e) => e.lineNumber),
        });
      }
      continue;
    }

    for (const [bucketKey, bucketEvents] of buckets) {
      const zScore = (bucketEvents.length - avg) / sd;
      if (zScore >= 3 && bucketEvents.length >= 10) {
        const confidence = Math.min(0.95, 0.4 + zScore * 0.12);
        const windowStart = new Date(bucketKey * BUCKET_MS);
        const windowEnd = new Date(windowStart.getTime() + BUCKET_MS);
        anomalies.push({
          category: "Request rate spike",
          description: `IP ${ip} made ${bucketEvents.length} requests in a 60s window, vs. its typical ~${avg.toFixed(
            1
          )} req/min (z-score ${zScore.toFixed(1)}). Possible scripted access, scraping, or brute force — but could also be a legitimate health check or polling client.`,
          confidence,
          severity: "MEDIUM",
          source: "STATISTICAL",
          ip,
          windowStart,
          windowEnd,
          lineNumbers: bucketEvents.map((e) => e.lineNumber),
        });
      }
    }
  }

  return anomalies;
}

/**
 * Flags IPs with an unusually high ratio of error status codes (4xx/5xx),
 * which can indicate scanning, brute-forcing, or a broken client.
 */
function detectErrorRateOutliers(events: ParsedLogEvent[]): DetectedAnomaly[] {
  const byIp = new Map<string, ParsedLogEvent[]>();
  for (const e of events) {
    const arr = byIp.get(e.ip) ?? [];
    arr.push(e);
    byIp.set(e.ip, arr);
  }

  const anomalies: DetectedAnomaly[] = [];

  for (const [ip, ipEvents] of byIp) {
    if (ipEvents.length < 8) continue;

    const errorEvents = ipEvents.filter((e) => e.statusCode >= 400);
    const errorRate = errorEvents.length / ipEvents.length;

    if (errorRate >= 0.5 && errorEvents.length >= 5) {
      const confidence = Math.min(0.9, 0.35 + errorRate * 0.5);
      const timestamps = errorEvents.map((e) => e.timestamp.getTime());

      // 401/403-dominated errors read as targeted credential
      // stuffing/brute-forcing against an auth endpoint; a 404-dominated
      // mix reads more like generic scanning/enumeration noise, which is
      // already independently captured (and more specifically explained)
      // by the endpoint-scanning detector below.
      const authErrorCount = errorEvents.filter((e) => e.statusCode === 401 || e.statusCode === 403).length;
      const authErrorRatio = authErrorCount / errorEvents.length;
      const isCredentialStuffing = authErrorRatio >= 0.6;

      anomalies.push({
        category: "High error rate",
        description: isCredentialStuffing
          ? `IP ${ip} triggered ${errorEvents.length}/${ipEvents.length} requests (${Math.round(
              errorRate * 100
            )}%) resulting in 4xx/5xx responses, ${Math.round(
              authErrorRatio * 100
            )}% of which are 401/403 (auth rejections) — consistent with credential stuffing or brute-force login attempts.`
          : `IP ${ip} triggered ${errorEvents.length}/${ipEvents.length} requests (${Math.round(
              errorRate * 100
            )}%) resulting in 4xx/5xx responses. Consistent with endpoint scanning or path enumeration.`,
        confidence,
        severity: isCredentialStuffing ? "HIGH" : "MEDIUM",
        source: "STATISTICAL",
        ip,
        windowStart: new Date(Math.min(...timestamps)),
        windowEnd: new Date(Math.max(...timestamps)),
        lineNumbers: errorEvents.map((e) => e.lineNumber),
      });
    }
  }

  return anomalies;
}

/**
 * Flags IPs that hit an unusually large number of distinct paths in a short
 * window, a signature of directory/endpoint enumeration (scanning). This is
 * a volume/breadth signal — whether the paths themselves are sensitive is
 * handled separately by `detectSensitivePathAccess` below, so a broad scan
 * of ordinary paths and a single hit on `/.env` are both caught, for
 * different reasons, instead of one detector trying to do both jobs.
 */
function detectEndpointScanning(events: ParsedLogEvent[]): DetectedAnomaly[] {
  const byIp = new Map<string, ParsedLogEvent[]>();
  for (const e of events) {
    const arr = byIp.get(e.ip) ?? [];
    arr.push(e);
    byIp.set(e.ip, arr);
  }

  const anomalies: DetectedAnomaly[] = [];

  for (const [ip, ipEvents] of byIp) {
    const distinctPaths = new Set(ipEvents.map((e) => e.path));
    const distinctRatio = distinctPaths.size / ipEvents.length;

    if (distinctPaths.size >= 15 && distinctRatio >= 0.8) {
      const confidence = Math.min(0.92, 0.4 + distinctPaths.size / 100);
      const timestamps = ipEvents.map((e) => e.timestamp.getTime());

      anomalies.push({
        category: "Endpoint scanning",
        description: `IP ${ip} accessed ${distinctPaths.size} distinct paths across only ${ipEvents.length} requests, a pattern typical of automated directory/endpoint enumeration rather than normal browsing.`,
        confidence,
        severity: "HIGH",
        source: "STATISTICAL",
        ip,
        windowStart: new Date(Math.min(...timestamps)),
        windowEnd: new Date(Math.max(...timestamps)),
        lineNumbers: ipEvents.map((e) => e.lineNumber),
      });
    }
  }

  return anomalies;
}

/**
 * Flags any request to a known-sensitive path or SQLi-shaped query string
 * (`.env`, `.git/config`, cloud credential paths, admin panels, `UNION
 * SELECT`-style payloads, etc.) — regardless of request volume.
 *
 * This deliberately does NOT require scanning-level breadth: a single hit
 * on `/.aws/credentials` is high-signal on its own and shouldn't need nine
 * other requests to corroborate it. It's kept as its own rule (rather than
 * folded into endpoint scanning's severity) precisely so this, arguably the
 * strongest signal the tool produces, is always on and never depends on an
 * external LLM API being reachable or funded.
 */
function detectSensitivePathAccess(events: ParsedLogEvent[]): DetectedAnomaly[] {
  const byIp = new Map<string, ParsedLogEvent[]>();
  for (const e of events) {
    const arr = byIp.get(e.ip) ?? [];
    arr.push(e);
    byIp.set(e.ip, arr);
  }

  const anomalies: DetectedAnomaly[] = [];

  for (const [ip, ipEvents] of byIp) {
    const hits = ipEvents.filter((e) => SENSITIVE_PATH_PATTERNS.some((pattern) => pattern.test(e.path)));
    if (hits.length === 0) continue;

    const distinctSensitivePaths = new Set(hits.map((e) => e.path));
    const confidence = Math.min(0.97, 0.65 + hits.length * 0.05 + distinctSensitivePaths.size * 0.03);
    const timestamps = hits.map((e) => e.timestamp.getTime());
    const samplePaths = Array.from(distinctSensitivePaths).slice(0, 3).join(", ");

    anomalies.push({
      category: "Sensitive path access",
      description: `IP ${ip} requested ${hits.length} sensitive/high-value path${
        hits.length === 1 ? "" : "s"
      } (${samplePaths}) — targets like config files, credentials, admin panels, or SQLi-shaped query strings that have no legitimate reason to be probed.`,
      confidence,
      // Always CRITICAL: these are targeted probes of secrets/credentials/
      // admin surfaces, not ambiguous traffic that needs corroboration.
      severity: "CRITICAL",
      source: "STATISTICAL",
      ip,
      windowStart: new Date(Math.min(...timestamps)),
      windowEnd: new Date(Math.max(...timestamps)),
      lineNumbers: hits.map((e) => e.lineNumber),
    });
  }

  return anomalies;
}

/**
 * Flags requests occurring in an off-hours window (01:00-05:00 UTC — the
 * timestamps' own UTC hour, not a viewer's local time or the log source's
 * original local timezone) from IPs whose traffic is heavily concentrated
 * there — a weak but useful SOC signal, kept low-severity on its own.
 */
function detectOffHoursActivity(events: ParsedLogEvent[]): DetectedAnomaly[] {
  const byIp = new Map<string, ParsedLogEvent[]>();
  for (const e of events) {
    const arr = byIp.get(e.ip) ?? [];
    arr.push(e);
    byIp.set(e.ip, arr);
  }

  const anomalies: DetectedAnomaly[] = [];

  for (const [ip, ipEvents] of byIp) {
    if (ipEvents.length < 6) continue;

    const offHoursEvents = ipEvents.filter((e) => {
      const hour = e.timestamp.getUTCHours();
      return hour >= 1 && hour < 5;
    });

    const offHoursRatio = offHoursEvents.length / ipEvents.length;

    if (offHoursRatio >= 0.7 && offHoursEvents.length >= 6) {
      const confidence = Math.min(0.7, 0.3 + offHoursRatio * 0.35);
      const timestamps = offHoursEvents.map((e) => e.timestamp.getTime());
      anomalies.push({
        category: "Off-hours activity",
        description: `IP ${ip} concentrated ${offHoursEvents.length}/${ipEvents.length} requests (${Math.round(
          offHoursRatio * 100
        )}%) between 01:00-05:00 UTC, outside typical business-hours traffic patterns.`,
        confidence,
        // LOW: timing alone is weak, corroborating evidence — plenty of
        // legitimate automated/global traffic runs off-hours. It's a
        // supporting signal for other findings, not a standalone one.
        severity: "LOW",
        source: "STATISTICAL",
        ip,
        windowStart: new Date(Math.min(...timestamps)),
        windowEnd: new Date(Math.max(...timestamps)),
        lineNumbers: offHoursEvents.map((e) => e.lineNumber),
      });
    }
  }

  return anomalies;
}

/**
 * Flags IPs whose user-agent string looks like a known scripting/scanning
 * tool rather than a real browser, or that switch user-agents frequently
 * (session/identity spoofing signal).
 */
function detectSuspiciousUserAgents(events: ParsedLogEvent[]): DetectedAnomaly[] {
  const SUSPICIOUS_UA_PATTERNS = [
    /curl/i,
    /wget/i,
    /python-requests/i,
    /sqlmap/i,
    /nikto/i,
    /nmap/i,
    /masscan/i,
    /^-$/,
    /^$/,
    // Anchored at the start so the negative lookahead scans the WHOLE
    // string for "googlebot"/"bingbot", not just the text after wherever
    // "bot" happens to match (a bare `bot(?!...)` would still flag
    // "Googlebot/2.1" because the lookahead only sees what comes after the
    // match position, which is past the "Google" prefix that exonerates it).
    /^(?!.*(googlebot|bingbot)).*bot/i,
  ];

  const byIp = new Map<string, ParsedLogEvent[]>();
  for (const e of events) {
    const arr = byIp.get(e.ip) ?? [];
    arr.push(e);
    byIp.set(e.ip, arr);
  }

  const anomalies: DetectedAnomaly[] = [];

  for (const [ip, ipEvents] of byIp) {
    const suspicious = ipEvents.filter((e) =>
      SUSPICIOUS_UA_PATTERNS.some((pattern) => pattern.test(e.userAgent))
    );

    if (suspicious.length >= 3) {
      const confidence = Math.min(0.88, 0.45 + suspicious.length / (ipEvents.length + 5));
      const timestamps = suspicious.map((e) => e.timestamp.getTime());
      const uaSample = suspicious[0].userAgent;
      anomalies.push({
        category: "Suspicious user agent",
        description: `IP ${ip} made ${suspicious.length} requests using a non-browser or known scripting/scanning tool user agent (e.g. "${uaSample}"), inconsistent with typical human web traffic.`,
        confidence,
        // LOW: a non-browser UA alone is weak, corroborating evidence —
        // legitimate bots, health checks, and API clients use these same
        // strings. It's meant to strengthen other findings, not stand alone.
        severity: "LOW",
        source: "STATISTICAL",
        ip,
        windowStart: new Date(Math.min(...timestamps)),
        windowEnd: new Date(Math.max(...timestamps)),
        lineNumbers: suspicious.map((e) => e.lineNumber),
      });
    }
  }

  return anomalies;
}

export function runStatisticalDetectors(events: ParsedLogEvent[]): DetectedAnomaly[] {
  if (events.length === 0) return [];

  const anomalies = [
    ...detectRequestRateSpikes(events),
    ...detectErrorRateOutliers(events),
    ...detectEndpointScanning(events),
    ...detectSensitivePathAccess(events),
    ...detectOffHoursActivity(events),
    ...detectSuspiciousUserAgents(events),
  ];

  return escalateCorroboratedRateSpikes(anomalies);
}

const SEVERITY_RANK: Record<AnomalySeverity, number> = { LOW: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 3 };

/**
 * A rate spike alone has plausible benign explanations (health checks,
 * polling clients), so it's set to MEDIUM by its own detector above. If the
 * same IP is independently flagged by another detector whose severity is
 * itself MEDIUM-or-above, that's real corroborating evidence — escalate the
 * spike to HIGH.
 *
 * Deliberately requires MEDIUM+, not just "any other category": "Suspicious
 * user agent" and "Off-hours activity" are LOW precisely because they're
 * weak, corroborating-only signals on their own (see their detectors above).
 * Counting them here would let two weak signals escalate each other into a
 * HIGH finding — reintroducing, one level up, the exact "severity derived
 * from weak signals" problem severity/confidence separation was meant to
 * avoid. A curl-based health-check poller has a rate spike (MEDIUM) plus a
 * non-browser UA (LOW) and nothing else; that combination now correctly
 * stays at MEDIUM instead of escalating.
 */
function escalateCorroboratedRateSpikes(anomalies: DetectedAnomaly[]): DetectedAnomaly[] {
  const strongSignalIpsByCategory = new Map<string, Set<string>>();
  for (const a of anomalies) {
    if (!a.ip || SEVERITY_RANK[a.severity] < SEVERITY_RANK.MEDIUM) continue;
    const set = strongSignalIpsByCategory.get(a.ip) ?? new Set<string>();
    set.add(a.category);
    strongSignalIpsByCategory.set(a.ip, set);
  }

  return anomalies.map((a) => {
    if (a.category !== "Request rate spike" || !a.ip) return a;

    const otherStrongCategories = strongSignalIpsByCategory.get(a.ip);
    // "Request rate spike" itself is MEDIUM, so it's always present in its
    // own IP's set — corroboration requires a size > 1, i.e. at least one
    // *other* MEDIUM+ category alongside it.
    const isCorroborated = Boolean(otherStrongCategories && otherStrongCategories.size > 1);
    if (!isCorroborated) return a;

    return {
      ...a,
      severity: "HIGH",
      description: `${a.description} Corroborated by another MEDIUM-or-above finding for the same IP, raising confidence this is real suspicious behavior rather than a benign burst.`,
    };
  });
}
