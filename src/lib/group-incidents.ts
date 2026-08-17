import type { AnomalyItem } from "@/components/AnomalyPanel";
import type { Severity } from "@/lib/ui";

export interface IncidentGroup {
  /** `ip:<ip>` for grouped incidents, `solo:<anomalyId>` for IP-less findings. */
  id: string;
  ip: string | null;
  severity: Severity;
  maxConfidence: number;
  signals: AnomalyItem[];
  eventIds: Set<number>;
  windowStart: string | null;
  windowEnd: string | null;
}

const SEVERITY_RANK: Record<Severity, number> = { LOW: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 3 };

/**
 * A single injected attack typically trips several independent detectors
 * for the same IP (e.g. a scan also reads as a burst of errors and a
 * suspicious user agent), which produces a wall of overlapping cards that
 * all point at the same actor. Grouping by IP turns that into one incident
 * per actor, with the individual detector hits listed underneath as
 * "contributing signals" — a closer match to how a SOC analyst actually
 * triages ("what is this IP doing", not "here are eight unrelated alerts").
 *
 * Anomalies without an IP (which the LLM pass can produce) stay as their
 * own single-signal incident rather than being grouped away.
 */
export function groupAnomaliesIntoIncidents(anomalies: AnomalyItem[]): IncidentGroup[] {
  const byIp = new Map<string, AnomalyItem[]>();
  const solo: AnomalyItem[] = [];

  for (const a of anomalies) {
    if (!a.ip) {
      solo.push(a);
      continue;
    }
    const arr = byIp.get(a.ip) ?? [];
    arr.push(a);
    byIp.set(a.ip, arr);
  }

  const groups: IncidentGroup[] = [];

  for (const [ip, signals] of byIp) {
    groups.push(buildGroup(`ip:${ip}`, ip, signals));
  }
  for (const a of solo) {
    groups.push(buildGroup(`solo:${a.id}`, null, [a]));
  }

  return groups.sort((a, b) => {
    const severityDiff = SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity];
    if (severityDiff !== 0) return severityDiff;
    return b.maxConfidence - a.maxConfidence;
  });
}

function buildGroup(id: string, ip: string | null, signals: AnomalyItem[]): IncidentGroup {
  const severity = signals.reduce<Severity>(
    (worst, s) => (SEVERITY_RANK[s.severity] > SEVERITY_RANK[worst] ? s.severity : worst),
    "LOW"
  );
  const maxConfidence = Math.max(...signals.map((s) => s.confidence));
  const eventIds = new Set<number>();
  let windowStart: string | null = null;
  let windowEnd: string | null = null;

  for (const s of signals) {
    for (const e of s.events) eventIds.add(e.id);
    if (s.windowStart && (!windowStart || s.windowStart < windowStart)) windowStart = s.windowStart;
    if (s.windowEnd && (!windowEnd || s.windowEnd > windowEnd)) windowEnd = s.windowEnd;
  }

  return {
    id,
    ip,
    severity,
    maxConfidence,
    signals: signals.sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity]),
    eventIds,
    windowStart,
    windowEnd,
  };
}
