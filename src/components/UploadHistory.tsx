"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { formatBytes } from "@/lib/ui";

interface UploadListItem {
  id: string;
  filename: string;
  status: "PROCESSING" | "COMPLETE" | "FAILED";
  errorMessage: string | null;
  rawSizeBytes: number;
  lineCount: number;
  parsedCount: number;
  createdAt: string;
  _count: { anomalies: number };
}

const STATUS_STYLES: Record<UploadListItem["status"], string> = {
  PROCESSING: "text-warning border-warning/30 bg-warning/10",
  COMPLETE: "text-success border-success/30 bg-success/10",
  FAILED: "text-danger border-danger/30 bg-danger/10",
};

export function UploadHistory({ refreshKey }: { refreshKey?: number }) {
  const [uploads, setUploads] = useState<UploadListItem[] | null>(null);

  useEffect(() => {
    let cancelled = false;
    fetch("/api/uploads")
      .then((res) => res.json())
      .then((data) => {
        if (!cancelled) setUploads(data.uploads ?? []);
      })
      .catch(() => {
        if (!cancelled) setUploads([]);
      });
    return () => {
      cancelled = true;
    };
  }, [refreshKey]);

  if (uploads === null) {
    return <p className="text-sm text-foreground/40">Loading upload history…</p>;
  }

  if (uploads.length === 0) {
    return (
      <p className="rounded-lg border border-panel-border bg-panel px-4 py-6 text-center text-sm text-foreground/40">
        No uploads yet. Upload a log file above to get started.
      </p>
    );
  }

  return (
    <div className="overflow-hidden rounded-lg border border-panel-border">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-panel-border bg-panel text-left text-xs text-foreground/50">
            <th className="px-4 py-2.5 font-medium">File</th>
            <th className="px-4 py-2.5 font-medium">Status</th>
            <th className="px-4 py-2.5 font-medium">Events</th>
            <th className="px-4 py-2.5 font-medium">Anomalies</th>
            <th className="px-4 py-2.5 font-medium">Size</th>
            <th className="px-4 py-2.5 font-medium">Uploaded</th>
          </tr>
        </thead>
        <tbody>
          {uploads.map((u) => (
            <tr key={u.id} className="border-b border-panel-border last:border-0 hover:bg-panel/60">
              <td className="px-4 py-2.5">
                {u.status === "COMPLETE" ? (
                  <Link href={`/uploads/${u.id}`} className="font-medium text-accent hover:underline">
                    {u.filename}
                  </Link>
                ) : (
                  <span className="font-medium">{u.filename}</span>
                )}
                {u.errorMessage && <p className="mt-0.5 text-xs text-foreground/40">{u.errorMessage}</p>}
              </td>
              <td className="px-4 py-2.5">
                <span className={`rounded-full border px-2 py-0.5 text-xs font-medium ${STATUS_STYLES[u.status]}`}>
                  {u.status}
                </span>
              </td>
              <td className="px-4 py-2.5 text-foreground/70">{u.parsedCount.toLocaleString()}</td>
              <td className="px-4 py-2.5">
                {u._count.anomalies > 0 ? (
                  <span className="font-medium text-warning">{u._count.anomalies}</span>
                ) : (
                  <span className="text-foreground/40">0</span>
                )}
              </td>
              <td className="px-4 py-2.5 text-foreground/50">{formatBytes(u.rawSizeBytes)}</td>
              <td className="px-4 py-2.5 text-foreground/50">
                {new Date(u.createdAt).toLocaleString()}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
