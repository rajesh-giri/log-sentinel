import { NextRequest, NextResponse } from "next/server";
import { getSession } from "@/lib/session";
import { prisma } from "@/lib/prisma";
import { parseAccessLog } from "@/lib/parser/access-log";
import { runStatisticalDetectors } from "@/lib/detectors/statistical";
import { runLlmDetector } from "@/lib/llm/anomaly-detector";
import { generateTimelineSummary, buildFallbackSummary } from "@/lib/llm/timeline-summary";
import { summarizeEvents } from "@/lib/summarize";
import { linkAnomaliesToEvents } from "@/lib/link-anomalies";

export const runtime = "nodejs";

const MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024; // 5MB
const ALLOWED_EXTENSIONS = [".log", ".txt"];

export async function POST(request: NextRequest) {
  const session = await getSession();
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const formData = await request.formData().catch(() => null);
  const file = formData?.get("file");
  // Default true (opt-out) so existing/programmatic callers that don't send
  // this field keep today's behavior; only an explicit "false" turns it off.
  const enableAiDetection = formData?.get("enableAiDetection") !== "false";

  if (!file || !(file instanceof File)) {
    return NextResponse.json({ error: "No file was uploaded." }, { status: 400 });
  }

  const lowerName = file.name.toLowerCase();
  const hasAllowedExtension = ALLOWED_EXTENSIONS.some((ext) => lowerName.endsWith(ext));
  if (!hasAllowedExtension) {
    return NextResponse.json(
      { error: `Unsupported file type. Allowed extensions: ${ALLOWED_EXTENSIONS.join(", ")}` },
      { status: 400 }
    );
  }

  if (file.size > MAX_FILE_SIZE_BYTES) {
    return NextResponse.json(
      { error: `File too large. Maximum size is ${MAX_FILE_SIZE_BYTES / (1024 * 1024)}MB.` },
      { status: 400 }
    );
  }

  if (file.size === 0) {
    return NextResponse.json({ error: "Uploaded file is empty." }, { status: 400 });
  }

  const content = await file.text();

  const upload = await prisma.upload.create({
    data: {
      filename: file.name,
      status: "PROCESSING",
      rawSizeBytes: file.size,
      rawContent: content,
      userId: session.userId,
    },
  });

  try {
    const { events, errors, totalLines } = parseAccessLog(content);

    if (events.length === 0) {
      await prisma.upload.update({
        where: { id: upload.id },
        data: {
          status: "FAILED",
          errorMessage:
            "No lines matched the expected access log format. Verify this is an Nginx/Apache combined-format access log.",
          lineCount: totalLines,
        },
      });
      return NextResponse.json(
        { error: "No parseable log lines found in this file.", uploadId: upload.id },
        { status: 422 }
      );
    }

    const statisticalAnomalies = runStatisticalDetectors(events);
    const summary = summarizeEvents(events);
    // Skipping the call entirely when disabled (rather than calling it and
    // discarding the result) is the point — this is a latency/cost knob,
    // not just a display filter. generateTimelineSummary independently
    // falls back to its own deterministic template when passed no client,
    // so gating both on the same flag keeps the summary and the AI-labeled
    // anomalies consistent with each other for this upload.
    const llmAnomalies = enableAiDetection ? await runLlmDetector(summary, statisticalAnomalies) : [];
    const allAnomalies = linkAnomaliesToEvents([...statisticalAnomalies, ...llmAnomalies], events);
    const narrativeSummary = enableAiDetection
      ? await generateTimelineSummary(summary, allAnomalies)
      : buildFallbackSummary(summary, allAnomalies);

    await prisma.$transaction(async (tx) => {
      await tx.logEvent.createMany({
        data: events.map((e) => ({
          uploadId: upload.id,
          timestamp: e.timestamp,
          ip: e.ip,
          method: e.method,
          path: e.path,
          statusCode: e.statusCode,
          bytesSent: e.bytesSent,
          userAgent: e.userAgent,
          referrer: e.referrer,
          lineNumber: e.lineNumber,
        })),
      });

      for (const anomaly of allAnomalies) {
        const linkedEvents =
          anomaly.lineNumbers.length > 0
            ? await tx.logEvent.findMany({
                where: { uploadId: upload.id, lineNumber: { in: anomaly.lineNumbers } },
                select: { id: true },
              })
            : [];

        await tx.anomaly.create({
          data: {
            uploadId: upload.id,
            category: anomaly.category,
            description: anomaly.description,
            confidence: anomaly.confidence,
            severity: anomaly.severity,
            source: anomaly.source,
            ip: anomaly.ip,
            windowStart: anomaly.windowStart,
            windowEnd: anomaly.windowEnd,
            events: linkedEvents.length > 0 ? { connect: linkedEvents } : undefined,
          },
        });
      }

      await tx.upload.update({
        where: { id: upload.id },
        data: {
          status: "COMPLETE",
          lineCount: totalLines,
          parsedCount: events.length,
          errorMessage:
            errors.length > 0
              ? `${errors.length} of ${totalLines} lines could not be parsed and were skipped.`
              : null,
          narrativeSummary,
        },
      });
    });

    return NextResponse.json({
      uploadId: upload.id,
      parsedCount: events.length,
      skippedCount: errors.length,
      anomalyCount: allAnomalies.length,
      narrativeSummary,
    });
  } catch (err) {
    console.error("Upload processing failed:", err);
    await prisma.upload.update({
      where: { id: upload.id },
      data: {
        status: "FAILED",
        errorMessage: "An unexpected error occurred while processing this file.",
      },
    });
    return NextResponse.json({ error: "Failed to process upload." }, { status: 500 });
  }
}

export async function GET() {
  const session = await getSession();
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const uploads = await prisma.upload.findMany({
    where: { userId: session.userId },
    orderBy: { createdAt: "desc" },
    select: {
      id: true,
      filename: true,
      status: true,
      errorMessage: true,
      rawSizeBytes: true,
      lineCount: true,
      parsedCount: true,
      createdAt: true,
      _count: { select: { anomalies: true } },
    },
  });

  return NextResponse.json({ uploads });
}
