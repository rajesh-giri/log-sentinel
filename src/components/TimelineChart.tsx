"use client";

import { useMemo } from "react";
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
} from "recharts";

interface EventLike {
  timestamp: string;
  statusCode: number;
}

interface TimelineChartProps {
  events: EventLike[];
}

const BUCKET_COUNT_TARGET = 60;

export function TimelineChart({ events }: TimelineChartProps) {
  const data = useMemo(() => {
    if (events.length === 0) return [];

    const timestamps = events.map((e) => new Date(e.timestamp).getTime());
    const min = Math.min(...timestamps);
    const max = Math.max(...timestamps);
    const span = Math.max(max - min, 1);
    const bucketSize = Math.max(Math.ceil(span / BUCKET_COUNT_TARGET), 1000);

    const buckets = new Map<number, { total: number; errors: number }>();

    for (const e of events) {
      const ts = new Date(e.timestamp).getTime();
      const bucketKey = Math.floor((ts - min) / bucketSize);
      const bucket = buckets.get(bucketKey) ?? { total: 0, errors: 0 };
      bucket.total += 1;
      if (e.statusCode >= 400) bucket.errors += 1;
      buckets.set(bucketKey, bucket);
    }

    const bucketCount = Math.floor(span / bucketSize) + 1;
    const result: { time: number; label: string; requests: number; errors: number }[] = [];

    for (let i = 0; i < bucketCount; i++) {
      const bucket = buckets.get(i) ?? { total: 0, errors: 0 };
      const bucketTime = min + i * bucketSize;
      result.push({
        time: bucketTime,
        label: new Date(bucketTime).toLocaleString(undefined, {
          month: "short",
          day: "numeric",
          hour: "2-digit",
          minute: "2-digit",
        }),
        requests: bucket.total,
        errors: bucket.errors,
      });
    }

    return result;
  }, [events]);

  if (data.length === 0) {
    return <p className="text-sm text-foreground/40">No events to chart.</p>;
  }

  return (
    <ResponsiveContainer width="100%" height={220}>
      <AreaChart data={data} margin={{ top: 8, right: 12, left: -12, bottom: 0 }}>
        <defs>
          <linearGradient id="requestsGradient" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#22d3ee" stopOpacity={0.35} />
            <stop offset="100%" stopColor="#22d3ee" stopOpacity={0} />
          </linearGradient>
          <linearGradient id="errorsGradient" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#f87171" stopOpacity={0.4} />
            <stop offset="100%" stopColor="#f87171" stopOpacity={0} />
          </linearGradient>
        </defs>
        <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" vertical={false} />
        <XAxis
          dataKey="label"
          tick={{ fill: "#8b98a5", fontSize: 11 }}
          minTickGap={40}
          axisLine={{ stroke: "#1f2937" }}
          tickLine={false}
        />
        <YAxis tick={{ fill: "#8b98a5", fontSize: 11 }} axisLine={false} tickLine={false} width={32} />
        <Tooltip
          contentStyle={{
            background: "#10151f",
            border: "1px solid #1f2937",
            borderRadius: 8,
            fontSize: 12,
          }}
          labelStyle={{ color: "#e6edf3" }}
        />
        <Area
          type="monotone"
          dataKey="requests"
          name="Requests"
          stroke="#22d3ee"
          fill="url(#requestsGradient)"
          strokeWidth={1.5}
        />
        <Area
          type="monotone"
          dataKey="errors"
          name="Errors (4xx/5xx)"
          stroke="#f87171"
          fill="url(#errorsGradient)"
          strokeWidth={1.5}
        />
      </AreaChart>
    </ResponsiveContainer>
  );
}
