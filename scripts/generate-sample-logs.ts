/**
 * Generates synthetic Nginx-combined-format access log files for
 * demoing/testing log-sentinel. Produces:
 *   - sample-logs/normal-traffic.log   (clean baseline traffic)
 *   - sample-logs/with-anomalies.log   (baseline + injected suspicious patterns)
 *
 * Run with: npx tsx scripts/generate-sample-logs.ts
 */
import { mkdirSync, writeFileSync } from "fs";
import { join } from "path";

const OUT_DIR = join(__dirname, "..", "sample-logs");

// Seeded PRNG (mulberry32) rather than Math.random(): these fixtures are
// asserted against by exact category/severity in tests/detectors.test.ts,
// so regenerating them should be reproducible instead of occasionally
// shifting request timing enough to flip a borderline detector threshold.
function mulberry32(seed: number): () => number {
  let a = seed;
  return function () {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const random = mulberry32(20240610);

const PATHS = [
  "/",
  "/index.html",
  "/about",
  "/products",
  "/products/42",
  "/products/17",
  "/products/103",
  "/cart",
  "/checkout",
  "/checkout/confirm",
  "/api/session",
  "/api/cart",
  "/static/app.css",
  "/static/app.js",
  "/static/vendor.js",
  "/images/logo.png",
  "/images/banner.jpg",
  "/blog",
  "/blog/hello-world",
  "/blog/release-notes",
  "/contact",
  "/faq",
  "/pricing",
];

const BROWSER_UAS = [
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
  "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
];

const SCANNER_UAS = ["curl/8.4.0", "python-requests/2.31.0", "sqlmap/1.7.11#stable", "Nikto/2.5.0", "masscan/1.3.2"];

// Legitimate-but-automated clients deliberately included in the "clean"
// baseline (see generateMonitoringPoller / generateLegitimateCrawler below)
// rather than only ever generating sparse human browsing sessions, which
// can't stress the detectors' volume/breadth thresholds at all.
const MONITORING_UA = "curl/8.4.0";
const GOOGLEBOT_UA = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)";

const SCAN_PATHS = [
  "/wp-admin",
  "/wp-login.php",
  "/.env",
  "/.git/config",
  "/admin",
  "/admin/config.php",
  "/phpmyadmin",
  "/.aws/credentials",
  "/config.bak",
  "/api/v1/users?id=1' OR '1'='1",
  "/backup.sql",
  "/shell.php",
  "/xmlrpc.php",
  "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
  "/.well-known/security.txt",
  "/server-status",
  "/console",
  "/actuator/env",
  "/debug/vars",
  "/cgi-bin/test.cgi",
];

function randomChoice<T>(arr: T[]): T {
  return arr[Math.floor(random() * arr.length)];
}

function randomIp(seed: number): string {
  return `10.${(seed * 7) % 200}.${(seed * 13) % 255}.${(seed * 29) % 255}`;
}

function formatApacheTime(date: Date): string {
  const months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
  const pad = (n: number, len = 2) => String(n).padStart(len, "0");
  return `${pad(date.getUTCDate())}/${months[date.getUTCMonth()]}/${date.getUTCFullYear()}:${pad(
    date.getUTCHours()
  )}:${pad(date.getUTCMinutes())}:${pad(date.getUTCSeconds())} +0000`;
}

function logLine(opts: {
  ip: string;
  time: Date;
  method: string;
  path: string;
  status: number;
  bytes: number;
  referrer?: string;
  userAgent: string;
}): string {
  const { ip, time, method, path, status, bytes, referrer = "-", userAgent } = opts;
  return `${ip} - - [${formatApacheTime(time)}] "${method} ${path} HTTP/1.1" ${status} ${bytes} "${referrer}" "${userAgent}"`;
}

function generateNormalTraffic(startTime: Date, durationMinutes: number, numUsers: number): string[] {
  const lines: string[] = [];
  const endTime = new Date(startTime.getTime() + durationMinutes * 60_000);

  for (let userIdx = 0; userIdx < numUsers; userIdx++) {
    const ip = randomIp(userIdx + 1);
    const ua = randomChoice(BROWSER_UAS);
    const sessionStart = new Date(
      startTime.getTime() + random() * (endTime.getTime() - startTime.getTime())
    );
    const pageViews = 3 + Math.floor(random() * 8);
    let cursor = sessionStart;

    for (let i = 0; i < pageViews; i++) {
      const path = randomChoice(PATHS);
      const status = random() < 0.03 ? 404 : 200;
      lines.push(
        logLine({
          ip,
          time: cursor,
          method: "GET",
          path,
          status,
          bytes: 800 + Math.floor(random() * 15000),
          referrer: i > 0 ? `https://example.com${randomChoice(PATHS)}` : undefined,
          userAgent: ua,
        })
      );
      cursor = new Date(cursor.getTime() + (2000 + random() * 20000));
    }
  }

  return lines;
}

function generateRateSpike(startTime: Date, ip: string): string[] {
  const lines: string[] = [];
  const ua = randomChoice(SCANNER_UAS);
  for (let i = 0; i < 180; i++) {
    const time = new Date(startTime.getTime() + i * 250); // ~4 req/sec for 45s
    lines.push(
      logLine({
        ip,
        time,
        method: "GET",
        path: "/api/session",
        status: i % 9 === 0 ? 429 : 200,
        bytes: 512,
        userAgent: ua,
      })
    );
  }
  return lines;
}

function generateEndpointScan(startTime: Date, ip: string): string[] {
  const lines: string[] = [];
  const ua = randomChoice(SCANNER_UAS);
  let cursor = startTime;
  for (const path of SCAN_PATHS) {
    lines.push(
      logLine({
        ip,
        time: cursor,
        method: "GET",
        path,
        status: random() < 0.85 ? 404 : 403,
        bytes: 150 + Math.floor(random() * 300),
        userAgent: ua,
      })
    );
    cursor = new Date(cursor.getTime() + 300 + random() * 900);
  }
  return lines;
}

function generateOffHoursBruteForce(startTime: Date, ip: string): string[] {
  // Concentrate all requests between 02:00-04:00 UTC.
  const offHoursStart = new Date(startTime);
  offHoursStart.setUTCHours(2, 0, 0, 0);

  const lines: string[] = [];
  const ua = "python-requests/2.31.0";
  for (let i = 0; i < 40; i++) {
    const time = new Date(offHoursStart.getTime() + i * 60_000 * 2); // every 2 min
    lines.push(
      logLine({
        ip,
        time,
        method: "POST",
        path: "/api/session",
        status: 401,
        bytes: 90,
        userAgent: ua,
      })
    );
  }
  return lines;
}

/**
 * A legitimate uptime/health-check poller: constant-rate requests to a
 * lightweight endpoint from one fixed IP, using `curl` (a completely
 * ordinary choice for a monitoring cron job or load balancer health check).
 *
 * Included deliberately in the "clean" baseline rather than only sparse
 * human browsing sessions, because sparse sessions can never produce enough
 * volume from one IP to test whether the rate-spike/UA detectors can tell
 * this apart from an attack. As documented in the README, they currently
 * can't: this trips both "Request rate spike" (curl at a rate well above
 * the file's sparse baseline) and "Suspicious user agent" (curl is always
 * treated as non-browser, regardless of the fact that health checks are
 * one of the most common legitimate uses of curl in production).
 */
function generateMonitoringPoller(startTime: Date, durationMinutes: number, ip: string): string[] {
  const lines: string[] = [];
  const endTime = new Date(startTime.getTime() + durationMinutes * 60_000);
  let cursor = new Date(startTime);
  while (cursor < endTime) {
    lines.push(
      logLine({
        ip,
        time: cursor,
        method: "GET",
        path: "/api/session",
        status: 200,
        bytes: 64,
        userAgent: MONITORING_UA,
      })
    );
    cursor = new Date(cursor.getTime() + 4000); // every 4s
  }
  return lines;
}

/**
 * A legitimate search-engine crawler walking the whole site once, using a
 * real Googlebot UA string. Included for the same reason as the monitoring
 * poller: it's exactly the kind of automated-but-legitimate client a
 * "no false positives" claim needs to be tested against. It's excluded from
 * "Suspicious user agent" by the Googlebot allowlist in that detector, but
 * `detectEndpointScanning` doesn't look at UA at all, so a crawler visiting
 * enough distinct pages in one pass still trips "Endpoint scanning" —
 * a second known, documented false-positive class (see README).
 */
function generateLegitimateCrawler(startTime: Date, ip: string): string[] {
  const lines: string[] = [];
  let cursor = new Date(startTime);
  for (const path of PATHS) {
    lines.push(
      logLine({
        ip,
        time: cursor,
        method: "GET",
        path,
        status: 200,
        bytes: 1200 + Math.floor(random() * 4000),
        userAgent: GOOGLEBOT_UA,
      })
    );
    cursor = new Date(cursor.getTime() + 4000 + random() * 4000);
  }
  return lines;
}

/**
 * A subtle "insider abuse" pattern deliberately designed to stay UNDER every
 * statistical detector's threshold individually, while still forming an
 * obviously concerning story in aggregate — the exact gap the LLM pass
 * exists to fill (see `runLlmDetector`'s docstring: "combinations of
 * individually-weak signals... none alone remarkable, together forming a
 * coherent story").
 *
 * Deliberately evades each fixed rule:
 *   - Only 6 requests total -> `detectRequestRateSpikes`/`detectOffHoursActivity`
 *     need >=5/>=6 events to even evaluate the IP, and 6 spread over ~100
 *     minutes never clusters into a >=15-request bucket, so no rate spike.
 *   - All 200s -> `detectErrorRateOutliers` needs >=8 requests before it even
 *     looks, and there are zero errors anyway.
 *   - Only 6 distinct paths -> `detectEndpointScanning` needs >=15.
 *   - None of the paths match `SENSITIVE_PATH_PATTERNS` (no ".env"/"wp-admin"/
 *     etc substring) -> `detectSensitivePathAccess` stays silent, even though
 *     "delete other users' accounts" and "export the customer list" are far
 *     more sensitive in intent than most of that fixed list.
 *   - A real desktop Chrome UA, not a scripting tool -> `detectSuspiciousUserAgents`
 *     stays silent.
 * The one exception: cramming all 6 requests into the 01:00-05:00 UTC window
 * does clear `detectOffHoursActivity`'s threshold (>=6 events, >=70% ratio),
 * so that one fires — but only as a LOW, generic "off-hours" flag with no
 * idea *what* happened off-hours. Connecting "LOW off-hours" + "DELETE on
 * two other users' accounts" + "admin dashboard browsing" + "a customer
 * export" into "this looks like insider account tampering, not noise" is
 * exactly what a fixed threshold can't express and the LLM pass is asked to
 * do from the aggregate per-IP stats alone (method/path/timing breakdown —
 * see `summarizeEvents`).
 */
function generateSubtleInsiderAbuse(startTime: Date, ip: string): string[] {
  const offHoursStart = new Date(startTime);
  offHoursStart.setUTCHours(2, 15, 0, 0);

  const ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
  const requests: { method: string; path: string }[] = [
    { method: "GET", path: "/admin/dashboard" },
    { method: "GET", path: "/admin/users" },
    { method: "GET", path: "/admin/users/482" },
    { method: "DELETE", path: "/api/v1/users/482" },
    { method: "DELETE", path: "/api/v1/users/483" },
    { method: "GET", path: "/api/v1/export/customers.csv" },
  ];

  const lines: string[] = [];
  let cursor = new Date(offHoursStart);
  for (const { method, path } of requests) {
    lines.push(
      logLine({
        ip,
        time: cursor,
        method,
        path,
        status: 200,
        bytes: method === "GET" && path.endsWith(".csv") ? 48_000 : 400 + Math.floor(random() * 600),
        userAgent: ua,
      })
    );
    cursor = new Date(cursor.getTime() + (8 + random() * 12) * 60_000); // 8-20 min apart
  }
  return lines;
}

function sortByEmbeddedTimestamp(lines: string[]): string[] {
  const extractTs = (line: string) => line.slice(line.indexOf("[") + 1, line.indexOf("]"));
  return [...lines].sort((a, b) => extractTs(a).localeCompare(extractTs(b)));
}

function main() {
  mkdirSync(OUT_DIR, { recursive: true });

  const baseTime = new Date("2024-06-10T08:00:00Z");

  // --- normal-traffic.log: baseline browsing + legitimate automated
  // clients (monitoring poller, search crawler), no attacks. See the
  // README's "Sample log files" section for which of these currently still
  // trip a detector — this file is a specificity test, not a guarantee.
  const normalBrowsing = generateNormalTraffic(baseTime, 240, 60);
  const monitoringPoller = generateMonitoringPoller(baseTime, 240, "10.0.5.10");
  const legitimateCrawler = generateLegitimateCrawler(new Date(baseTime.getTime() + 30 * 60_000), "66.249.66.1");
  const normalLines = sortByEmbeddedTimestamp([...normalBrowsing, ...monitoringPoller, ...legitimateCrawler]);
  writeFileSync(join(OUT_DIR, "normal-traffic.log"), normalLines.join("\n") + "\n");

  // --- with-anomalies.log: baseline + three distinct injected attack patterns ---
  const baseline = generateNormalTraffic(baseTime, 240, 80);
  const rateSpike = generateRateSpike(new Date(baseTime.getTime() + 90 * 60_000), "10.44.201.17");
  const endpointScan = generateEndpointScan(new Date(baseTime.getTime() + 150 * 60_000), "10.91.13.240");
  const bruteForce = generateOffHoursBruteForce(baseTime, "10.203.87.6");

  const allLines = sortByEmbeddedTimestamp([...baseline, ...rateSpike, ...endpointScan, ...bruteForce]);

  writeFileSync(join(OUT_DIR, "with-anomalies.log"), allLines.join("\n") + "\n");

  // --- llm-pattern.log: baseline + the subtle insider-abuse actor above.
  // Statistically near-silent by design (see generateSubtleInsiderAbuse) —
  // meant to demonstrate the LLM pass adding a genuinely new finding from
  // aggregate stats, not to test the statistical detectors.
  const llmBaseline = generateNormalTraffic(baseTime, 240, 50);
  const insiderAbuse = generateSubtleInsiderAbuse(baseTime, "198.51.100.23");
  const llmLines = sortByEmbeddedTimestamp([...llmBaseline, ...insiderAbuse]);
  writeFileSync(join(OUT_DIR, "llm-pattern.log"), llmLines.join("\n") + "\n");

  console.log(`Wrote ${normalLines.length} lines to sample-logs/normal-traffic.log`);
  console.log(`Wrote ${allLines.length} lines to sample-logs/with-anomalies.log`);
  console.log(`Wrote ${llmLines.length} lines to sample-logs/llm-pattern.log`);
}

main();
