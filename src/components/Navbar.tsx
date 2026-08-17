"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";

export function Navbar({ username }: { username: string }) {
  const router = useRouter();

  async function handleLogout() {
    await fetch("/api/auth/logout", { method: "POST" });
    router.push("/login");
    router.refresh();
  }

  return (
    <header className="sticky top-0 z-10 border-b border-panel-border bg-background/80 backdrop-blur">
      <div className="mx-auto flex max-w-6xl items-center justify-between px-6 py-3.5">
        <Link href="/" className="flex items-center gap-2">
          <div className="flex h-7 w-7 items-center justify-center rounded-md bg-accent/10 text-accent">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
              <path d="M12 2 4 6v6c0 5 3.5 8.5 8 10 4.5-1.5 8-5 8-10V6l-8-4Z" strokeLinejoin="round" />
              <path d="m9 12 2 2 4-4" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
          </div>
          <span className="text-sm font-semibold tracking-tight">Log Sentinel</span>
        </Link>

        <div className="flex items-center gap-4">
          <span className="text-xs text-foreground/50">
            Signed in as <span className="text-foreground/80">{username}</span>
          </span>
          <button
            onClick={handleLogout}
            className="rounded-md border border-panel-border px-3 py-1.5 text-xs font-medium text-foreground/70 transition hover:border-foreground/30 hover:text-foreground"
          >
            Sign out
          </button>
        </div>
      </div>
    </header>
  );
}
