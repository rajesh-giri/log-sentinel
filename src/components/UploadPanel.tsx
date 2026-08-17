"use client";

import { useCallback, useRef, useState } from "react";
import { useRouter } from "next/navigation";

export function UploadPanel() {
  const router = useRouter();
  const inputRef = useRef<HTMLInputElement>(null);
  const [isDragging, setIsDragging] = useState(false);
  const [isUploading, setIsUploading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [fileName, setFileName] = useState<string | null>(null);
  const [enableAiDetection, setEnableAiDetection] = useState(true);

  const upload = useCallback(
    async (file: File) => {
      setError(null);
      setIsUploading(true);
      setFileName(file.name);

      const formData = new FormData();
      formData.append("file", file);
      formData.append("enableAiDetection", String(enableAiDetection));

      try {
        const res = await fetch("/api/uploads", { method: "POST", body: formData });
        const data = await res.json();

        if (!res.ok) {
          setError(data.error ?? "Upload failed.");
          setIsUploading(false);
          return;
        }

        router.push(`/uploads/${data.uploadId}`);
      } catch {
        setError("Network error while uploading. Please try again.");
        setIsUploading(false);
      }
    },
    [router, enableAiDetection]
  );

  function handleDrop(e: React.DragEvent) {
    e.preventDefault();
    setIsDragging(false);
    const file = e.dataTransfer.files?.[0];
    if (file) upload(file);
  }

  function handleFileSelect(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (file) upload(file);
  }

  return (
    <div className="space-y-3">
      <label className="flex items-center gap-1.5 text-xs text-foreground/60">
        <input
          type="checkbox"
          checked={enableAiDetection}
          onChange={(e) => setEnableAiDetection(e.target.checked)}
          disabled={isUploading}
          className="accent-accent"
        />
        Run AI-assisted anomaly detection
        <span className="text-foreground/40">(adds latency; off = statistical detectors only)</span>
      </label>

      <div
        onDragOver={(e) => {
          e.preventDefault();
          setIsDragging(true);
        }}
        onDragLeave={() => setIsDragging(false)}
        onDrop={handleDrop}
        onClick={() => inputRef.current?.click()}
        className={`flex cursor-pointer flex-col items-center justify-center gap-3 rounded-xl border-2 border-dashed px-6 py-14 text-center transition ${
          isDragging
            ? "border-accent bg-accent/5"
            : "border-panel-border bg-panel hover:border-foreground/30"
        }`}
      >
        <input
          ref={inputRef}
          type="file"
          accept=".log,.txt"
          className="hidden"
          onChange={handleFileSelect}
          disabled={isUploading}
        />

        <div className="flex h-12 w-12 items-center justify-center rounded-full bg-accent/10 text-accent">
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
            <path d="M12 16V4m0 0-4 4m4-4 4 4" strokeLinecap="round" strokeLinejoin="round" />
            <path d="M4 16v2a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-2" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
        </div>

        {isUploading ? (
          <div>
            <p className="text-sm font-medium">Processing {fileName}…</p>
            <p className="mt-1 text-xs text-foreground/50">
              Parsing, running anomaly detection, and generating a summary. This may take a few seconds.
            </p>
          </div>
        ) : (
          <div>
            <p className="text-sm font-medium">Drop a log file here, or click to browse</p>
            <p className="mt-1 text-xs text-foreground/50">Accepts .log or .txt files, up to 5MB</p>
          </div>
        )}
      </div>

      {error && (
        <p className="rounded-md border border-danger/30 bg-danger/10 px-3 py-2 text-sm text-danger">{error}</p>
      )}
    </div>
  );
}
