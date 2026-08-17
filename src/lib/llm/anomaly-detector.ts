import { z } from "zod";
import { getLlmClient, getLlmModel } from "@/lib/llm/client";
import type { LogSummary } from "@/lib/summarize";
import type { DetectedAnomaly } from "@/lib/detectors/statistical";

const llmAnomalySchema = z.object({
  anomalies: z.array(
    z.object({
      category: z.string(),
      description: z.string(),
      confidence: z.number().min(0).max(1),
      severity: z.enum(["LOW", "MEDIUM", "HIGH", "CRITICAL"]),
      ip: z.string().nullable(),
    })
  ),
});

/**
 * Second detection pass, run after the deterministic statistical detectors.
 *
 * We deliberately do NOT send raw log lines to the LLM — only the bounded
 * aggregate summary (see `summarizeEvents`) plus the anomalies the
 * statistical pass already found. This keeps token usage/cost roughly flat
 * regardless of file size, and asks the model to focus on what fixed
 * thresholds can't express — combinations of individually-weak signals and
 * novel patterns — rather than re-flagging known-bad paths or re-deriving
 * stats it can't compute reliably from a summary alone. High-signal,
 * fixed-shape findings like credential/config-file probing are handled
 * deterministically (see `detectSensitivePathAccess` in
 * `src/lib/detectors/statistical.ts`) precisely so the tool's strongest
 * detection doesn't depend on an external API being reachable or funded.
 *
 * If no OPENAI_API_KEY is configured, this returns an empty list and the
 * app relies solely on the statistical detectors — see README "AI Usage".
 */
export async function runLlmDetector(
  summary: LogSummary,
  statisticalAnomalies: DetectedAnomaly[]
): Promise<DetectedAnomaly[]> {
  const client = getLlmClient();
  if (!client) return [];

  const alreadyFlaggedIps = new Set(statisticalAnomalies.map((a) => a.ip).filter(Boolean));

  const prompt = `You are a SOC (Security Operations Center) analyst assistant reviewing aggregated web access log statistics for a single uploaded log file.

You will be given:
1. Overall statistics for the file.
2. Per-IP aggregate behavior for the most active IPs.
3. A list of anomalies already flagged by deterministic statistical rules (rate spikes, error rate outliers, endpoint scanning, sensitive path/credential probing, off-hours activity, suspicious user agents).

Your job: identify ADDITIONAL noteworthy or suspicious patterns that the deterministic rules likely missed — these rules are good at fixed thresholds and known-bad paths, but bad at combinations of individually-weak signals (e.g. a slightly unusual method + an off-beat path + off-hours timing, none alone remarkable, together forming a coherent story) and novel patterns that don't match any fixed shape. Do not just restate the already-flagged anomalies below, and do not re-flag obviously sensitive paths (".env", ".git", credential files, admin panels, SQLi-looking query strings) — those are already caught deterministically; focus on what a fixed rule can't express.

If nothing genuinely new or noteworthy stands out, return an empty anomalies array — do not invent anomalies to pad the response.

For each anomaly, give a plain-English description a SOC analyst could read in 5 seconds, a confidence score between 0 and 1 reflecting how certain you are this is truly suspicious (not just unusual), and a severity level.

Already flagged IPs (avoid duplicating these unless you're adding genuinely new evidence): ${
    Array.from(alreadyFlaggedIps).join(", ") || "none"
  }

Overall stats:
${JSON.stringify(
  {
    totalRequests: summary.totalRequests,
    timeRange: summary.timeRange,
    uniqueIpCount: summary.uniqueIpCount,
    statusCodeDistribution: summary.statusCodeDistribution,
    topPaths: summary.topPaths,
  },
  null,
  2
)}

Per-IP aggregates (top ${summary.topIps.length} by volume):
${JSON.stringify(summary.topIps, null, 2)}
`;

  try {
    const response = await client.chat.completions.create({
      model: getLlmModel(),
      messages: [{ role: "user", content: prompt }],
      temperature: 0,
      response_format: {
        type: "json_schema",
        json_schema: {
          name: "anomaly_report",
          schema: {
            type: "object",
            properties: {
              anomalies: {
                type: "array",
                items: {
                  type: "object",
                  properties: {
                    category: { type: "string" },
                    description: { type: "string" },
                    confidence: { type: "number" },
                    severity: { type: "string", enum: ["LOW", "MEDIUM", "HIGH", "CRITICAL"] },
                    ip: { type: ["string", "null"] },
                  },
                  required: ["category", "description", "confidence", "severity", "ip"],
                  additionalProperties: false,
                },
              },
            },
            required: ["anomalies"],
            additionalProperties: false,
          },
        },
      },
    });

    const content = response.choices[0]?.message?.content;
    if (!content) return [];

    const parsed = llmAnomalySchema.safeParse(JSON.parse(content));
    if (!parsed.success) return [];

    return parsed.data.anomalies.map((a) => ({
      category: a.category,
      description: a.description,
      confidence: a.confidence,
      severity: a.severity,
      source: "LLM" as const,
      ip: a.ip,
      windowStart: null,
      windowEnd: null,
      lineNumbers: [],
    }));
  } catch (err) {
    console.error("LLM anomaly detection failed, continuing with statistical results only:", err);
    return [];
  }
}
