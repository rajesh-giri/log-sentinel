"use client";

import { SEVERITY_STYLES, formatConfidence, type Severity } from "@/lib/ui";
import type { IncidentGroup } from "@/lib/group-incidents";

export interface AnomalyItem {
  id: number;
  category: string;
  description: string;
  confidence: number;
  severity: Severity;
  source: "STATISTICAL" | "LLM";
  ip: string | null;
  windowStart: string | null;
  windowEnd: string | null;
  events: { id: number; lineNumber: number }[];
}

export function AnomalyPanel({
  incidents,
  activeIncidentId,
  onSelect,
}: {
  incidents: IncidentGroup[];
  activeIncidentId: string | null;
  onSelect: (id: string | null) => void;
}) {
  if (incidents.length === 0) {
    return (
      <div className="rounded-lg border border-panel-border bg-panel px-4 py-8 text-center">
        <p className="text-sm text-foreground/50">No anomalies detected in this upload.</p>
      </div>
    );
  }

  return (
    <div className="space-y-2">
      {incidents.map((incident) => {
        const isActive = incident.id === activeIncidentId;
        const primary = incident.signals[0];
        const hasAi = incident.signals.some((s) => s.source === "LLM");

        return (
          <button
            key={incident.id}
            onClick={() => onSelect(isActive ? null : incident.id)}
            className={`block w-full rounded-lg border px-4 py-3 text-left transition ${
              isActive ? "border-accent bg-accent/5" : "border-panel-border bg-panel hover:border-foreground/25"
            }`}
          >
            <div className="mb-1.5 flex items-center justify-between gap-2">
              <div className="flex items-center gap-2">
                <span
                  className={`rounded-full border px-2 py-0.5 text-[11px] font-medium ${SEVERITY_STYLES[incident.severity]}`}
                >
                  {incident.severity}
                </span>
                <span className="text-sm font-medium">{incident.ip ?? primary.category}</span>
                {hasAi && (
                  <span className="rounded-full border border-accent/30 bg-accent/10 px-2 py-0.5 text-[10px] font-medium text-accent">
                    AI
                  </span>
                )}
              </div>
              <span className="whitespace-nowrap text-xs font-medium text-foreground/60">
                {formatConfidence(incident.maxConfidence)} confidence
              </span>
            </div>

            <p className="text-sm text-foreground/70">{primary.description}</p>

            {incident.signals.length > 1 && (
              <div className="mt-2 space-y-1 border-t border-panel-border/60 pt-2">
                <p className="text-[10px] font-medium uppercase tracking-wide text-foreground/40">
                  {incident.signals.length} contributing signals
                </p>
                {incident.signals.map((s) => (
                  <div key={s.id} className="flex items-center gap-1.5 text-xs text-foreground/60" title={s.description}>
                    <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${SEVERITY_STYLES[s.severity].split(" ")[0]}`} />
                    <span className="truncate">{s.category}</span>
                    <span className="ml-auto shrink-0 text-foreground/40">{formatConfidence(s.confidence)}</span>
                  </div>
                ))}
              </div>
            )}

            <div className="mt-2 flex items-center gap-3 text-xs text-foreground/40">
              {incident.ip && incident.signals.length === 1 && <span>IP: {incident.ip}</span>}
              {incident.eventIds.size > 0 && <span>{incident.eventIds.size} related event(s)</span>}
            </div>
          </button>
        );
      })}
    </div>
  );
}
