import { redirect } from "next/navigation";
import { getSession } from "@/lib/session";
import { Navbar } from "@/components/Navbar";
import { UploadPanel } from "@/components/UploadPanel";
import { UploadHistory } from "@/components/UploadHistory";

export default async function DashboardPage() {
  const session = await getSession();
  if (!session) {
    redirect("/login");
  }

  return (
    <div className="flex min-h-screen flex-col bg-background">
      <Navbar username={session.username} />

      <main className="mx-auto w-full max-w-6xl flex-1 px-6 py-10">
        <div className="mb-8">
          <h1 className="text-xl font-semibold tracking-tight">Upload a log file</h1>
          <p className="mt-1 text-sm text-foreground/50">
            Nginx/Apache-style access log format. We&apos;ll parse it, build a timeline, and flag anomalies.
          </p>
        </div>

        <UploadPanel />

        <div className="mt-12">
          <h2 className="mb-3 text-sm font-medium text-foreground/70">Recent uploads</h2>
          <UploadHistory />
        </div>
      </main>
    </div>
  );
}
