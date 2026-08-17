export type Severity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export const SEVERITY_STYLES: Record<Severity, string> = {
  LOW: "bg-foreground/10 text-foreground/70 border-foreground/20",
  MEDIUM: "bg-warning/10 text-warning border-warning/30",
  HIGH: "bg-orange-500/10 text-orange-400 border-orange-500/30",
  CRITICAL: "bg-danger/10 text-danger border-danger/30",
};

export function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  const exponent = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  const value = bytes / 1024 ** exponent;
  return `${value.toFixed(exponent === 0 ? 0 : 1)} ${units[exponent]}`;
}

export function formatConfidence(confidence: number): string {
  return `${Math.round(confidence * 100)}%`;
}

export function statusCodeClass(status: number): string {
  if (status >= 500) return "text-danger";
  if (status >= 400) return "text-warning";
  if (status >= 300) return "text-accent";
  return "text-success";
}
