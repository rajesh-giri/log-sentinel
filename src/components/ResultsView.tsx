"use client";

import { useMemo, useState } from "react";
import { TimelineChart } from "@/components/TimelineChart";
import { IncidentTimeline } from "@/components/IncidentTimeline";
import { AnomalyPanel, type AnomalyItem } from "@/components/AnomalyPanel";
import { EventsTable, type EventRow } from "@/components/EventsTable";
import { groupAnomaliesIntoIncidents } from "@/lib/group-incidents";
import { formatBytes } from "@/lib/ui";

export function ResultsView({
  filename,
  narrativeSummary,
  events,
  anomalies,
  uniqueIpCount,
  totalBytes,
  totalEventCount,
  errorCount,
}: {
  filename: string;
  narrativeSummary: string | null;
  events: EventRow[];
  anomalies: AnomalyItem[];
  uniqueIpCount: number;
  totalBytes: number;
  totalEventCount: number;
  errorCount: number;
}) {
  const [activeIncidentId, setActiveIncidentId] = useState<string | null>(null);
  const [onlyFlagged, setOnlyFlagged] = useState(false);
  const [priorOnlyFlagged, setPriorOnlyFlagged] = useState(false);

  const incidents = useMemo(() => groupAnomaliesIntoIncidents(anomalies), [anomalies]);

  const activeIncident = useMemo(
    () => incidents.find((i) => i.id === activeIncidentId) ?? null,
    [incidents, activeIncidentId]
  );

  // Anomaly ids that belong to the currently-active incident, so the
  // per-anomaly incident timeline strip can highlight every signal that
  // makes up the selected (possibly grouped) incident, not just one.
  const activeAnomalyIds = useMemo(
    () => new Set(activeIncident?.signals.map((s) => s.id) ?? []),
    [activeIncident]
  );

  const anomalyIdToIncidentId = useMemo(() => {
    const map = new Map<number, string>();
    for (const incident of incidents) {
      for (const s of incident.signals) map.set(s.id, incident.id);
    }
    return map;
  }, [incidents]);

  const flaggedEventIds = useMemo(() => {
    if (activeIncident === null) {
      return new Set(incidents.flatMap((i) => Array.from(i.eventIds)));
    }
    return activeIncident.eventIds;
  }, [incidents, activeIncident]);

  function handleSelectIncident(id: string | null) {
    if (id !== null && activeIncidentId === null) {
      // Entering "filtered by incident" mode: remember whatever the user had
      // set, then force the table to narrow to just the triggering events.
      setPriorOnlyFlagged(onlyFlagged);
      setOnlyFlagged(true);
    } else if (id === null) {
      // Clearing the filter: restore whatever the user had before selecting
      // an incident, rather than always snapping back to "off".
      setOnlyFlagged(priorOnlyFlagged);
    }
    setActiveIncidentId(id);
  }

  function handleSelectFromTimeline(anomalyId: number) {
    const incidentId = anomalyIdToIncidentId.get(anomalyId) ?? null;
    handleSelectIncident(incidentId === activeIncidentId ? null : incidentId);
  }

  const llmCount = anomalies.filter((a) => a.source === "LLM").length;
  const statisticalCount = anomalies.length - llmCount;
  const hasTimedAnomalies = anomalies.some((a) => a.windowStart !== null);

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-xl font-semibold tracking-tight">{filename}</h1>
        <div className="mt-3 grid grid-cols-2 gap-3 sm:grid-cols-4">
          <StatCard label="Events" value={totalEventCount.toLocaleString()} />
          <StatCard label="Unique IPs" value={uniqueIpCount.toLocaleString()} />
          <StatCard label="Errors (4xx/5xx)" value={errorCount.toLocaleString()} tone={errorCount > 0 ? "warning" : undefined} />
          <StatCard label="Total transferred" value={formatBytes(totalBytes)} />
        </div>
      </div>

      {narrativeSummary && (
        <div className="rounded-lg border border-accent/20 bg-accent/5 px-4 py-3.5">
          <div className="mb-1 flex items-center gap-1.5 text-xs font-medium text-accent">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M12 2v2m0 16v2M4.93 4.93l1.41 1.41m11.32 11.32 1.41 1.41M2 12h2m16 0h2M4.93 19.07l1.41-1.41m11.32-11.32 1.41-1.41" />
              <circle cx="12" cy="12" r="4" />
            </svg>
            SOC Briefing
          </div>
          <p className="text-sm text-foreground/80">{narrativeSummary}</p>
        </div>
      )}

      {hasTimedAnomalies && (
        <div>
          <h2 className="mb-3 text-sm font-medium text-foreground/70">Incident timeline</h2>
          <IncidentTimeline
            anomalies={anomalies}
            activeAnomalyIds={activeAnomalyIds}
            onSelect={handleSelectFromTimeline}
          />
        </div>
      )}

      <div>
        <h2 className="mb-3 text-sm font-medium text-foreground/70">Traffic timeline</h2>
        <div className="rounded-lg border border-panel-border bg-panel p-4">
          <TimelineChart events={events} />
        </div>
      </div>

      <div className="grid grid-cols-1 gap-8 lg:grid-cols-[380px_1fr]">
        <div>
          <div className="mb-3 flex items-center justify-between">
            <h2 className="text-sm font-medium text-foreground/70">
              Incidents <span className="text-foreground/40">({incidents.length})</span>
            </h2>
            {anomalies.length > 0 && (
              <span className="text-xs text-foreground/40">
                {statisticalCount} rule-based{llmCount > 0 ? `, ${llmCount} AI-detected` : ""}
              </span>
            )}
          </div>
          <AnomalyPanel incidents={incidents} activeIncidentId={activeIncidentId} onSelect={handleSelectIncident} />
        </div>

        <div>
          <div className="mb-3 flex items-center justify-between">
            <h2 className="text-sm font-medium text-foreground/70">Events</h2>
            {activeIncidentId !== null && (
              <button
                onClick={() => handleSelectIncident(null)}
                className="text-xs text-accent hover:underline"
              >
                Clear incident filter
              </button>
            )}
          </div>
          <EventsTable
            events={events}
            flaggedEventIds={flaggedEventIds}
            onlyFlagged={onlyFlagged}
            onOnlyFlaggedChange={setOnlyFlagged}
          />
        </div>
      </div>
    </div>
  );
}

function StatCard({
  label,
  value,
  tone,
}: {
  label: string;
  value: string;
  tone?: "warning";
}) {
  return (
    <div className="rounded-lg border border-panel-border bg-panel px-4 py-3">
      <p className="text-xs text-foreground/50">{label}</p>
      <p className={`mt-1 text-lg font-semibold ${tone === "warning" ? "text-warning" : ""}`}>{value}</p>
    </div>
  );
}
