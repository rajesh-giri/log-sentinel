"use client";

import { useMemo } from "react";
import { SEVERITY_STYLES, type Severity } from "@/lib/ui";

export interface IncidentTimelineItem {
  id: number;
  category: string;
  severity: Severity;
  ip: string | null;
  source: "STATISTICAL" | "LLM";
  windowStart: string | null;
  windowEnd: string | null;
}

function formatTime(iso: string): string {
  return new Date(iso).toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

/**
 * A chronological, at-a-glance list of every anomaly window, ordered by
 * when it happened rather than by confidence/severity (that's what the
 * anomaly panel below is for). This is the "summarized timeline of events"
 * a SOC analyst would want first — what happened, in what order — distinct
 * from the traffic volume chart, which shows *how much* traffic there was
 * but not *which parts of it were incidents*.
 */
export function IncidentTimeline({
  anomalies,
  activeAnomalyIds,
  onSelect,
}: {
  anomalies: IncidentTimelineItem[];
  activeAnomalyIds: Set<number>;
  onSelect: (id: number) => void;
}) {
  const ordered = useMemo(
    () =>
      anomalies
        .filter((a) => a.windowStart !== null)
        .sort((a, b) => new Date(a.windowStart!).getTime() - new Date(b.windowStart!).getTime()),
    [anomalies]
  );

  if (ordered.length === 0) {
    return null;
  }

  return (
    <div className="scrollbar-thin overflow-x-auto rounded-lg border border-panel-border bg-panel p-3">
      <div className="flex min-w-max items-stretch gap-2">
        {ordered.map((a, idx) => {
          const isActive = activeAnomalyIds.has(a.id);
          return (
            <div key={a.id} className="flex items-center">
              {idx > 0 && <div className="mx-1 h-px w-4 bg-panel-border" />}
              <button
                onClick={() => onSelect(a.id)}
                className={`w-52 shrink-0 rounded-md border px-3 py-2 text-left transition ${
                  isActive ? "border-accent bg-accent/5" : "border-panel-border hover:border-foreground/25"
                }`}
              >
                <div className="flex items-center justify-between gap-2">
                  <span
                    className={`rounded-full border px-1.5 py-0.5 text-[10px] font-medium ${SEVERITY_STYLES[a.severity]}`}
                  >
                    {a.severity}
                  </span>
                  <span className="whitespace-nowrap text-[11px] text-foreground/40">
                    {formatTime(a.windowStart!)}
                  </span>
                </div>
                <p className="mt-1 truncate text-xs font-medium text-foreground/80" title={a.category}>
                  {a.category}
                </p>
                {a.ip && <p className="truncate text-[11px] text-foreground/40">{a.ip}</p>}
              </button>
            </div>
          );
        })}
      </div>
    </div>
  );
}
