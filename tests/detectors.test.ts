import { describe, expect, it } from "vitest";
import { readFileSync } from "fs";
import { join } from "path";
import { parseAccessLog } from "@/lib/parser/access-log";
import { runStatisticalDetectors, type AnomalySeverity } from "@/lib/detectors/statistical";

const SAMPLE_LOGS_DIR = join(__dirname, "..", "sample-logs");

function loadFixture(filename: string) {
  const content = readFileSync(join(SAMPLE_LOGS_DIR, filename), "utf-8");
  const { events } = parseAccessLog(content);
  return runStatisticalDetectors(events);
}

const SEVERITY_RANK: Record<AnomalySeverity, number> = {
  LOW: 0,
  MEDIUM: 1,
  HIGH: 2,
  CRITICAL: 3,
};

describe("runStatisticalDetectors against sample-logs fixtures", () => {
  it("produces zero anomalies for ordinary human browsing sessions", () => {
    const anomalies = loadFixture("normal-traffic.log");
    // normal-traffic.log deliberately includes two legitimate-but-automated
    // clients (a curl-based monitoring poller and a Googlebot crawler) that
    // ARE currently flagged — see README "Known limitations". This test
    // asserts the detectors stay quiet for the ~60 ordinary browsing
    // sessions specifically, rather than claiming zero anomalies file-wide.
    const KNOWN_FALSE_POSITIVE_IPS = new Set(["10.0.5.10", "66.249.66.1"]);
    const unexpected = anomalies.filter((a) => !a.ip || !KNOWN_FALSE_POSITIVE_IPS.has(a.ip));
    expect(unexpected).toHaveLength(0);
  });

  it("documents (rather than hides) the two known false-positive clients", () => {
    const anomalies = loadFixture("normal-traffic.log");
    const byIp = new Map(anomalies.map((a) => [a.ip, a]));

    // A constant-rate curl health-check poller: correctly does NOT trip
    // "Request rate spike", but does trip "Suspicious user agent" (curl is
    // always treated as non-browser). The reason it doesn't trip the rate
    // detector is more interesting than "constant rate has no spike against
    // its own baseline": a genuinely flat per-minute rate makes the
    // per-bucket standard deviation 0, which routes it into the
    // global-baseline fallback (see `detectRequestRateSpikes`), not a
    // self-relative comparison. It clears that fallback's ratio check only
    // because the poller supplies the large majority of this fixture's total
    // events, so its own volume inflates `globalAvgPerBucket` enough that its
    // busiest-bucket-vs-global-average ratio stays under the 4x threshold.
    // In other words, a high-volume constant-rate client raises the
    // detection bar for every other IP in the same file, not just itself.
    expect(byIp.get("10.0.5.10")?.category).toBe("Suspicious user agent");

    // A real Googlebot UA crawling every page once: excluded from
    // "Suspicious user agent" by the bot allowlist, but still trips
    // "Endpoint scanning", which doesn't look at UA at all.
    expect(byIp.get("66.249.66.1")?.category).toBe("Endpoint scanning");
  });

  it("flags the injected request rate spike in with-anomalies.log", () => {
    const anomalies = loadFixture("with-anomalies.log");
    const categories = anomalies.map((a) => a.category);
    expect(categories).toContain("Request rate spike");
  });

  it("flags the injected endpoint scan in with-anomalies.log", () => {
    const anomalies = loadFixture("with-anomalies.log");
    const categories = anomalies.map((a) => a.category);
    expect(categories).toContain("Endpoint scanning");
  });

  it("flags the injected off-hours brute-force burst in with-anomalies.log", () => {
    const anomalies = loadFixture("with-anomalies.log");
    const categories = anomalies.map((a) => a.category);
    expect(categories).toContain("Off-hours activity");
  });

  it("ranks the endpoint scan above a suspicious-user-agent finding by severity", () => {
    const anomalies = loadFixture("with-anomalies.log");
    const scan = anomalies.find((a) => a.category === "Endpoint scanning");
    const suspiciousUa = anomalies.find((a) => a.category === "Suspicious user agent");

    expect(scan).toBeDefined();
    expect(suspiciousUa).toBeDefined();
    expect(SEVERITY_RANK[scan!.severity]).toBeGreaterThan(SEVERITY_RANK[suspiciousUa!.severity]);
  });

  it("flags sensitive path access on its own, independent of scanning breadth", () => {
    const anomalies = loadFixture("with-anomalies.log");
    const sensitivePathFinding = anomalies.find((a) => a.category === "Sensitive path access");
    expect(sensitivePathFinding).toBeDefined();
    expect(sensitivePathFinding!.severity).toBe("CRITICAL");
  });

  it("only escalates a rate spike to HIGH when corroborated by a MEDIUM+ signal, not a LOW one", () => {
    const anomalies = loadFixture("with-anomalies.log");
    const byIpAndCategory = new Map(anomalies.map((a) => [`${a.ip}:${a.category}`, a]));

    // 10.44.201.17 (the curl-poller-shaped IP in this fixture) has a rate
    // spike plus only a LOW "Suspicious user agent" finding — that's the
    // exact "weak signal drives severity" shape the escalation rule must
    // NOT reward, so it should stay at the rate spike detector's own MEDIUM.
    const weaklyCorroborated = byIpAndCategory.get("10.44.201.17:Request rate spike");
    expect(weaklyCorroborated).toBeDefined();
    expect(weaklyCorroborated!.severity).toBe("MEDIUM");

    // 10.91.13.240 has a rate spike alongside genuinely MEDIUM+ findings
    // (High error rate, Endpoint scanning, Sensitive path access) — that IS
    // real corroboration and should escalate to HIGH.
    const genuinelyCorroborated = byIpAndCategory.get("10.91.13.240:Request rate spike");
    expect(genuinelyCorroborated).toBeDefined();
    expect(genuinelyCorroborated!.severity).toBe("HIGH");
  });

  it("stays statistically near-silent on the subtle insider-abuse pattern in llm-pattern.log", () => {
    // llm-pattern.log is built (see generateSubtleInsiderAbuse in
    // scripts/generate-sample-logs.ts) to sit under every fixed detector
    // threshold individually — this asserts that design holds, i.e. that
    // only the weak, generic off-hours signal fires and nothing else. The
    // point of this fixture is to demonstrate the LLM pass adding a
    // genuinely new CRITICAL finding that the statistical rules cannot
    // express (see README "AI Usage"), not to exercise the statistical
    // detectors themselves.
    const anomalies = loadFixture("llm-pattern.log");
    expect(anomalies).toHaveLength(1);
    expect(anomalies[0].category).toBe("Off-hours activity");
    expect(anomalies[0].severity).toBe("LOW");
    expect(anomalies[0].ip).toBe("198.51.100.23");
  });
});

describe("sensitive path detector's actuator/health exclusion", () => {
  function detectFor(path: string) {
    const log = `10.0.0.1 - - [01/Jan/2025:00:00:00 +0000] "GET ${path} HTTP/1.1" 200 100 "-" "curl/8.0"\n`;
    return loadFixtureFromString(log);
  }

  function loadFixtureFromString(content: string) {
    const { events } = parseAccessLog(content);
    return runStatisticalDetectors(events);
  }

  it("does not flag /actuator/health as a sensitive path", () => {
    const anomalies = detectFor("/actuator/health");
    expect(anomalies.find((a) => a.category === "Sensitive path access")).toBeUndefined();
  });

  it("still flags other /actuator/* subpaths as sensitive", () => {
    const anomalies = detectFor("/actuator/env");
    expect(anomalies.find((a) => a.category === "Sensitive path access")).toBeDefined();
  });
});
