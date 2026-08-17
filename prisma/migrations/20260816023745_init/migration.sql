-- CreateEnum
CREATE TYPE "UploadStatus" AS ENUM ('PROCESSING', 'COMPLETE', 'FAILED');

-- CreateEnum
CREATE TYPE "AnomalySource" AS ENUM ('STATISTICAL', 'LLM');

-- CreateEnum
CREATE TYPE "AnomalySeverity" AS ENUM ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL');

-- CreateTable
CREATE TABLE "User" (
    "id" TEXT NOT NULL,
    "username" TEXT NOT NULL,
    "passwordHash" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "User_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Upload" (
    "id" TEXT NOT NULL,
    "filename" TEXT NOT NULL,
    "status" "UploadStatus" NOT NULL DEFAULT 'PROCESSING',
    "errorMessage" TEXT,
    "rawSizeBytes" INTEGER NOT NULL,
    "lineCount" INTEGER NOT NULL DEFAULT 0,
    "parsedCount" INTEGER NOT NULL DEFAULT 0,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "userId" TEXT NOT NULL,

    CONSTRAINT "Upload_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "LogEvent" (
    "id" SERIAL NOT NULL,
    "timestamp" TIMESTAMP(3) NOT NULL,
    "ip" TEXT NOT NULL,
    "method" TEXT NOT NULL,
    "path" TEXT NOT NULL,
    "statusCode" INTEGER NOT NULL,
    "bytesSent" INTEGER NOT NULL,
    "userAgent" TEXT NOT NULL,
    "referrer" TEXT,
    "lineNumber" INTEGER NOT NULL,
    "uploadId" TEXT NOT NULL,

    CONSTRAINT "LogEvent_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Anomaly" (
    "id" SERIAL NOT NULL,
    "category" TEXT NOT NULL,
    "description" TEXT NOT NULL,
    "confidence" DOUBLE PRECISION NOT NULL,
    "severity" "AnomalySeverity" NOT NULL,
    "source" "AnomalySource" NOT NULL,
    "ip" TEXT,
    "windowStart" TIMESTAMP(3),
    "windowEnd" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "uploadId" TEXT NOT NULL,

    CONSTRAINT "Anomaly_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "_AnomalyToLogEvent" (
    "A" INTEGER NOT NULL,
    "B" INTEGER NOT NULL,

    CONSTRAINT "_AnomalyToLogEvent_AB_pkey" PRIMARY KEY ("A","B")
);

-- CreateIndex
CREATE UNIQUE INDEX "User_username_key" ON "User"("username");

-- CreateIndex
CREATE INDEX "LogEvent_uploadId_idx" ON "LogEvent"("uploadId");

-- CreateIndex
CREATE INDEX "LogEvent_ip_idx" ON "LogEvent"("ip");

-- CreateIndex
CREATE INDEX "LogEvent_timestamp_idx" ON "LogEvent"("timestamp");

-- CreateIndex
CREATE INDEX "Anomaly_uploadId_idx" ON "Anomaly"("uploadId");

-- CreateIndex
CREATE INDEX "_AnomalyToLogEvent_B_index" ON "_AnomalyToLogEvent"("B");

-- AddForeignKey
ALTER TABLE "Upload" ADD CONSTRAINT "Upload_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "LogEvent" ADD CONSTRAINT "LogEvent_uploadId_fkey" FOREIGN KEY ("uploadId") REFERENCES "Upload"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Anomaly" ADD CONSTRAINT "Anomaly_uploadId_fkey" FOREIGN KEY ("uploadId") REFERENCES "Upload"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "_AnomalyToLogEvent" ADD CONSTRAINT "_AnomalyToLogEvent_A_fkey" FOREIGN KEY ("A") REFERENCES "Anomaly"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "_AnomalyToLogEvent" ADD CONSTRAINT "_AnomalyToLogEvent_B_fkey" FOREIGN KEY ("B") REFERENCES "LogEvent"("id") ON DELETE CASCADE ON UPDATE CASCADE;
