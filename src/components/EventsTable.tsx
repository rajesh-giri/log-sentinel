"use client";

import { useMemo, useState } from "react";
import { statusCodeClass } from "@/lib/ui";

export interface EventRow {
  id: number;
  timestamp: string;
  ip: string;
  method: string;
  path: string;
  statusCode: number;
  bytesSent: number;
  userAgent: string;
  lineNumber: number;
}

const PAGE_SIZE = 50;

export function EventsTable({
  events,
  flaggedEventIds,
  onlyFlagged,
  onOnlyFlaggedChange,
}: {
  events: EventRow[];
  flaggedEventIds: Set<number>;
  onlyFlagged: boolean;
  onOnlyFlaggedChange: (value: boolean) => void;
}) {
  const [page, setPage] = useState(0);
  const [filter, setFilter] = useState("");

  const filtered = useMemo(() => {
    let result = events;
    if (onlyFlagged) {
      result = result.filter((e) => flaggedEventIds.has(e.id));
    }
    if (filter.trim()) {
      const q = filter.trim().toLowerCase();
      result = result.filter(
        (e) => e.ip.includes(q) || e.path.toLowerCase().includes(q) || e.userAgent.toLowerCase().includes(q)
      );
    }
    return result;
  }, [events, filter, onlyFlagged, flaggedEventIds]);

  const totalPages = Math.max(Math.ceil(filtered.length / PAGE_SIZE), 1);
  // Clamp during render rather than via a useEffect + setState: onlyFlagged
  // can change from outside this component (selecting an incident), and a
  // stale page index would otherwise render an empty slice until the next
  // effect flush.
  const currentPage = Math.min(page, totalPages - 1);
  const pageEvents = filtered.slice(currentPage * PAGE_SIZE, (currentPage + 1) * PAGE_SIZE);

  return (
    <div>
      <div className="mb-3 flex flex-wrap items-center gap-3">
        <input
          value={filter}
          onChange={(e) => {
            setFilter(e.target.value);
            setPage(0);
          }}
          placeholder="Filter by IP, path, or user agent…"
          className="w-64 rounded-md border border-panel-border bg-black/30 px-3 py-1.5 text-sm outline-none focus:border-accent"
        />
        <label className="flex items-center gap-1.5 text-xs text-foreground/60">
          <input
            type="checkbox"
            checked={onlyFlagged}
            onChange={(e) => {
              onOnlyFlaggedChange(e.target.checked);
              setPage(0);
            }}
            className="accent-accent"
          />
          Only flagged events
        </label>
        <span className="text-xs text-foreground/40">
          {filtered.length.toLocaleString()} of {events.length.toLocaleString()} events
        </span>
      </div>

      <div className="scrollbar-thin overflow-x-auto rounded-lg border border-panel-border">
        <table className="w-full min-w-[900px] text-sm">
          <thead>
            <tr className="border-b border-panel-border bg-panel text-left text-xs text-foreground/50">
              <th className="px-3 py-2 font-medium">#</th>
              <th className="px-3 py-2 font-medium">Timestamp</th>
              <th className="px-3 py-2 font-medium">IP</th>
              <th className="px-3 py-2 font-medium">Method</th>
              <th className="px-3 py-2 font-medium">Path</th>
              <th className="px-3 py-2 font-medium">Status</th>
              <th className="px-3 py-2 font-medium">Bytes</th>
              <th className="px-3 py-2 font-medium">User Agent</th>
            </tr>
          </thead>
          <tbody>
            {pageEvents.map((e) => {
              const flagged = flaggedEventIds.has(e.id);
              return (
                <tr
                  key={e.id}
                  className={`border-b border-panel-border last:border-0 ${
                    flagged ? "bg-danger/5" : "hover:bg-panel/60"
                  }`}
                >
                  <td className="px-3 py-2 font-mono text-xs text-foreground/40">{e.lineNumber}</td>
                  <td className="whitespace-nowrap px-3 py-2 text-foreground/70">
                    {new Date(e.timestamp).toLocaleString()}
                  </td>
                  <td className="px-3 py-2 font-mono text-xs">
                    <span className="flex items-center gap-1.5">
                      {flagged && <span className="h-1.5 w-1.5 rounded-full bg-danger" title="Flagged as anomalous" />}
                      {e.ip}
                    </span>
                  </td>
                  <td className="px-3 py-2 text-foreground/70">{e.method}</td>
                  <td className="max-w-[240px] truncate px-3 py-2 font-mono text-xs text-foreground/70" title={e.path}>
                    {e.path}
                  </td>
                  <td className={`px-3 py-2 font-medium ${statusCodeClass(e.statusCode)}`}>{e.statusCode}</td>
                  <td className="px-3 py-2 text-foreground/50">{e.bytesSent.toLocaleString()}</td>
                  <td
                    className="max-w-[220px] truncate px-3 py-2 text-xs text-foreground/40"
                    title={e.userAgent}
                  >
                    {e.userAgent}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {totalPages > 1 && (
        <div className="mt-3 flex items-center justify-between text-xs text-foreground/50">
          <span>
            Page {currentPage + 1} of {totalPages}
          </span>
          <div className="flex gap-2">
            <button
              onClick={() => setPage((p) => Math.max(p - 1, 0))}
              disabled={currentPage === 0}
              className="rounded-md border border-panel-border px-2.5 py-1 disabled:opacity-30"
            >
              Prev
            </button>
            <button
              onClick={() => setPage((p) => Math.min(p + 1, totalPages - 1))}
              disabled={currentPage >= totalPages - 1}
              className="rounded-md border border-panel-border px-2.5 py-1 disabled:opacity-30"
            >
              Next
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
