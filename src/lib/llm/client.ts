import OpenAI from "openai";

/**
 * LLM provider configuration. Both providers are used through the `openai`
 * SDK — Gemini exposes an OpenAI-compatible endpoint
 * (https://ai.google.dev/gemini-api/docs/openai), so rather than adding a
 * second SDK/dependency for a second provider, we just point the same
 * client at a different `baseURL` and API key. This keeps the rest of the
 * app (JSON-schema response format, `temperature`, etc.) provider-agnostic.
 *
 * If both are configured, Gemini is preferred (checked first) purely
 * because it's the more recently added option; only one is ever active.
 */
type LlmProvider = "gemini" | "openai";

const GEMINI_BASE_URL = "https://generativelanguage.googleapis.com/v1beta/openai/";

function resolveProvider(): LlmProvider | null {
  if (process.env.GEMINI_API_KEY) return "gemini";
  if (process.env.OPENAI_API_KEY) return "openai";
  return null;
}

let client: OpenAI | null = null;
let clientProvider: LlmProvider | null = null;

/**
 * Returns a shared LLM client (OpenAI or Gemini, via its OpenAI-compatible
 * endpoint), or `null` if no API key is configured for either provider.
 * The rest of the app is expected to treat LLM features as optional
 * enhancements and gracefully fall back to statistical-only results.
 */
export function getLlmClient(): OpenAI | null {
  const provider = resolveProvider();
  if (!provider) return null;

  // Re-create the client if the configured provider changed at runtime
  // (e.g. in tests), rather than only ever memoizing the first call.
  if (!client || clientProvider !== provider) {
    client =
      provider === "gemini"
        ? new OpenAI({ apiKey: process.env.GEMINI_API_KEY, baseURL: GEMINI_BASE_URL })
        : new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
    clientProvider = provider;
  }
  return client;
}

export function getLlmModel(): string {
  const provider = resolveProvider();
  if (provider === "gemini") {
    // Deliberately NOT the "-lite" tier: testing against a subtle,
    // multi-signal pattern (see llm-pattern.log / generateSubtleInsiderAbuse
    // in scripts/generate-sample-logs.ts — off-hours admin access + DELETEs
    // on other users' accounts, each individually below every statistical
    // detector's threshold) showed gemini-flash-lite-latest missed it
    // consistently (0/2 runs) while gemini-3.5-flash caught it reliably
    // (2/2 runs, correctly reasoning "authorization bypass... active data
    // deletion"). The whole point of the LLM pass is catching what fixed
    // thresholds can't, so a model too weak for that reasoning defeats the
    // purpose — worth the extra cost/latency over the lite tier.
    return process.env.GEMINI_MODEL || "gemini-3.5-flash";
  }
  return process.env.OPENAI_MODEL || "gpt-4o-mini";
}

export function isLlmEnabled(): boolean {
  return resolveProvider() !== null;
}
