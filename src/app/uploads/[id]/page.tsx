import { notFound, redirect } from "next/navigation";
import Link from "next/link";
import { getSession } from "@/lib/session";
import { prisma } from "@/lib/prisma";
import { Navbar } from "@/components/Navbar";
import { ResultsView } from "@/components/ResultsView";

export default async function UploadResultsPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const session = await getSession();
  if (!session) {
    redirect("/login");
  }

  const { id } = await params;

  const upload = await prisma.upload.findFirst({
    where: { id, userId: session.userId },
    include: {
      anomalies: {
        orderBy: { confidence: "desc" },
        include: { events: { select: { id: true, lineNumber: true } } },
      },
    },
  });

  if (!upload) {
    notFound();
  }

  if (upload.status === "PROCESSING") {
    return (
      <div className="flex min-h-screen flex-col bg-background">
        <Navbar username={session.username} />
        <main className="mx-auto flex w-full max-w-6xl flex-1 items-center justify-center px-6 py-10">
          <p className="text-sm text-foreground/50">This upload is still processing. Refresh in a moment.</p>
        </main>
      </div>
    );
  }

  if (upload.status === "FAILED") {
    return (
      <div className="flex min-h-screen flex-col bg-background">
        <Navbar username={session.username} />
        <main className="mx-auto flex w-full max-w-6xl flex-1 flex-col items-center justify-center gap-3 px-6 py-10">
          <p className="rounded-lg border border-danger/30 bg-danger/10 px-4 py-3 text-sm text-danger">
            {upload.errorMessage ?? "This upload failed to process."}
          </p>
          <Link href="/" className="text-sm text-accent hover:underline">
            Back to dashboard
          </Link>
        </main>
      </div>
    );
  }

  const EVENTS_DISPLAY_LIMIT = 5000;

  const [events, aggregate, distinctIps, errorCount] = await Promise.all([
    prisma.logEvent.findMany({
      where: { uploadId: id },
      orderBy: { timestamp: "asc" },
      take: EVENTS_DISPLAY_LIMIT,
    }),
    prisma.logEvent.aggregate({
      where: { uploadId: id },
      _sum: { bytesSent: true },
    }),
    prisma.logEvent.groupBy({
      by: ["ip"],
      where: { uploadId: id },
    }),
    prisma.logEvent.count({
      where: { uploadId: id, statusCode: { gte: 400 } },
    }),
  ]);

  const totalEventCount = upload.parsedCount;
  const truncated = totalEventCount > events.length;

  const uniqueIpCount = distinctIps.length;
  const totalBytes = aggregate._sum.bytesSent ?? 0;

  return (
    <div className="flex min-h-screen flex-col bg-background">
      <Navbar username={session.username} />
      <main className="mx-auto w-full max-w-6xl flex-1 px-6 py-10">
        <Link href="/" className="mb-6 inline-flex items-center gap-1 text-xs text-foreground/50 hover:text-foreground/80">
          ← Back to dashboard
        </Link>
        {truncated && (
          <p className="mb-4 rounded-lg border border-warning/30 bg-warning/10 px-4 py-2.5 text-sm text-warning">
            Showing the first {events.length.toLocaleString()} of {totalEventCount.toLocaleString()} events. Anomaly
            detection ran against the full file; only the events table and chart below are truncated.
          </p>
        )}
        <ResultsView
          filename={upload.filename}
          narrativeSummary={upload.narrativeSummary}
          uniqueIpCount={uniqueIpCount}
          totalBytes={totalBytes}
          totalEventCount={totalEventCount}
          errorCount={errorCount}
          events={events.map((e) => ({
            id: e.id,
            timestamp: e.timestamp.toISOString(),
            ip: e.ip,
            method: e.method,
            path: e.path,
            statusCode: e.statusCode,
            bytesSent: e.bytesSent,
            userAgent: e.userAgent,
            lineNumber: e.lineNumber,
          }))}
          anomalies={upload.anomalies.map((a) => ({
            id: a.id,
            category: a.category,
            description: a.description,
            confidence: a.confidence,
            severity: a.severity,
            source: a.source,
            ip: a.ip,
            windowStart: a.windowStart?.toISOString() ?? null,
            windowEnd: a.windowEnd?.toISOString() ?? null,
            events: a.events,
          }))}
        />
      </main>
    </div>
  );
}
