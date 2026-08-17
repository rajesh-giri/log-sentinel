import { getLlmClient, getLlmModel } from "@/lib/llm/client";
import type { LogSummary } from "@/lib/summarize";
import type { DetectedAnomaly } from "@/lib/detectors/statistical";

/**
 * Generates a short, human-readable narrative summary of the upload for a
 * SOC analyst — a couple of sentences framing what happened, similar to
 * what a human analyst would jot at the top of an incident ticket.
 *
 * Falls back to a deterministic, template-based summary when no LLM
 * provider is configured, so the app is fully usable without AI.
 */
export async function generateTimelineSummary(
  summary: LogSummary,
  anomalies: DetectedAnomaly[]
): Promise<string> {
  const client = getLlmClient();

  if (!client) {
    return buildFallbackSummary(summary, anomalies);
  }

  const topAnomalies = [...anomalies]
    .sort((a, b) => b.confidence - a.confidence)
    .slice(0, 8)
    .map((a) => `- [${a.severity}, conf ${a.confidence.toFixed(2)}] ${a.category}: ${a.description}`)
    .join("\n");

  const prompt = `Write a concise 3-5 sentence SOC analyst briefing summarizing this uploaded access log. Mention the traffic volume, time range, number of unique IPs, and call out the most important anomalies in plain English. Be direct and factual, no fluff, no markdown headers.

Stats: ${summary.totalRequests} requests from ${summary.uniqueIpCount} unique IPs between ${summary.timeRange.start} and ${summary.timeRange.end}.
Status code distribution: ${JSON.stringify(summary.statusCodeDistribution)}

Top anomalies detected:
${topAnomalies || "None detected."}`;

  try {
    const response = await client.chat.completions.create({
      model: getLlmModel(),
      messages: [{ role: "user", content: prompt }],
      temperature: 0.3,
    });

    const text = response.choices[0]?.message?.content?.trim();
    return text || buildFallbackSummary(summary, anomalies);
  } catch (err) {
    console.error("LLM timeline summary failed, using fallback:", err);
    return buildFallbackSummary(summary, anomalies);
  }
}

export function buildFallbackSummary(summary: LogSummary, anomalies: DetectedAnomaly[]): string {
  if (summary.totalRequests === 0) {
    return "No parseable log events were found in this upload.";
  }

  const critical = anomalies.filter((a) => a.severity === "CRITICAL" || a.severity === "HIGH").length;
  const anomalyClause =
    anomalies.length === 0
      ? "No significant anomalies were detected."
      : `${anomalies.length} anomal${anomalies.length === 1 ? "y" : "ies"} ${
          anomalies.length === 1 ? "was" : "were"
        } flagged${critical > 0 ? `, including ${critical} high/critical severity` : ""}.`;

  return `This upload contains ${summary.totalRequests} requests from ${summary.uniqueIpCount} unique IP${
    summary.uniqueIpCount === 1 ? "" : "s"
  }, spanning ${summary.timeRange.start} to ${summary.timeRange.end}. ${anomalyClause}`;
}
