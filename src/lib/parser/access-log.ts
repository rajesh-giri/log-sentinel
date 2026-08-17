/**
 * Parser for the Nginx/Apache "combined" access log format:
 *
 *   127.0.0.1 - - [10/Oct/2023:13:55:36 +0000] "GET /index.html HTTP/1.1" 200 2326 "-" "Mozilla/5.0"
 *
 * We normalize each line into a `ParsedLogEvent`, which is the shape the rest
 * of the app (DB, detectors, UI) works with regardless of the original log
 * format. Swapping in a different log format later only requires writing a
 * new parser that produces this same shape.
 */

export interface ParsedLogEvent {
  timestamp: Date;
  ip: string;
  method: string;
  path: string;
  statusCode: number;
  bytesSent: number;
  userAgent: string;
  referrer: string | null;
  lineNumber: number;
}

export interface ParseError {
  lineNumber: number;
  raw: string;
  reason: string;
}

export interface ParseResult {
  events: ParsedLogEvent[];
  errors: ParseError[];
  totalLines: number;
}

// Combined log format regex. Groups: ip, timestamp, method, path, protocol,
// status, bytes, referrer, userAgent.
const LOG_LINE_REGEX =
  /^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) [^"]*" (\d{3}) (\S+) "([^"]*)" "([^"]*)"/;

// Example: 10/Oct/2023:13:55:36 +0000
const MONTHS: Record<string, string> = {
  Jan: "01",
  Feb: "02",
  Mar: "03",
  Apr: "04",
  May: "05",
  Jun: "06",
  Jul: "07",
  Aug: "08",
  Sep: "09",
  Oct: "10",
  Nov: "11",
  Dec: "12",
};

function parseApacheTimestamp(raw: string): Date | null {
  const match = /^(\d{2})\/(\w{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-]\d{4})$/.exec(raw);
  if (!match) return null;

  const [, day, monStr, year, hour, min, sec, tz] = match;
  const month = MONTHS[monStr];
  if (!month) return null;

  const tzFormatted = `${tz.slice(0, 3)}:${tz.slice(3)}`;
  const iso = `${year}-${month}-${day}T${hour}:${min}:${sec}${tzFormatted}`;
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? null : date;
}

export function parseAccessLog(content: string): ParseResult {
  const lines = content.split(/\r?\n/);
  const events: ParsedLogEvent[] = [];
  const errors: ParseError[] = [];

  let totalLines = 0;

  lines.forEach((rawLine, idx) => {
    const line = rawLine.trim();
    if (line.length === 0) return;

    totalLines += 1;
    const lineNumber = idx + 1;

    const match = LOG_LINE_REGEX.exec(line);
    if (!match) {
      errors.push({ lineNumber, raw: line, reason: "Line did not match expected access log format" });
      return;
    }

    const [, ip, timestampRaw, method, path, statusStr, bytesStr, referrer, userAgent] = match;

    const timestamp = parseApacheTimestamp(timestampRaw);
    if (!timestamp) {
      errors.push({ lineNumber, raw: line, reason: `Unparseable timestamp: "${timestampRaw}"` });
      return;
    }

    const statusCode = Number.parseInt(statusStr, 10);
    const bytesSent = bytesStr === "-" ? 0 : Number.parseInt(bytesStr, 10);

    events.push({
      timestamp,
      ip,
      method: method.toUpperCase(),
      path,
      statusCode,
      bytesSent: Number.isNaN(bytesSent) ? 0 : bytesSent,
      userAgent: userAgent || "-",
      referrer: referrer === "-" ? null : referrer,
      lineNumber,
    });
  });

  return { events, errors, totalLines };
}
