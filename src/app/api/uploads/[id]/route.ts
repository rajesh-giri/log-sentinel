import { NextRequest, NextResponse } from "next/server";
import { getSession } from "@/lib/session";
import { prisma } from "@/lib/prisma";

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const session = await getSession();
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const { id } = await params;

  const upload = await prisma.upload.findFirst({
    where: { id, userId: session.userId },
    include: {
      anomalies: {
        orderBy: { confidence: "desc" },
        include: { events: { select: { id: true, lineNumber: true } } },
      },
    },
  });

  if (!upload) {
    return NextResponse.json({ error: "Upload not found." }, { status: 404 });
  }

  const events = await prisma.logEvent.findMany({
    where: { uploadId: id },
    orderBy: { timestamp: "asc" },
    take: 5000,
  });

  return NextResponse.json({ upload, events, totalEventCount: upload.parsedCount });
}

export async function DELETE(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const session = await getSession();
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const { id } = await params;

  const upload = await prisma.upload.findFirst({ where: { id, userId: session.userId } });
  if (!upload) {
    return NextResponse.json({ error: "Upload not found." }, { status: 404 });
  }

  await prisma.upload.delete({ where: { id } });

  return NextResponse.json({ ok: true });
}
