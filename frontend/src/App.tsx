import { useState } from "react";
import { QueryClient, QueryClientProvider, useMutation, useQuery } from "@tanstack/react-query";
import {
  Activity,
  AlertTriangle,
  Database,
  FileWarning,
  Play,
  RefreshCw,
  ShieldAlert,
} from "lucide-react";
import {
  fetchHealth,
  fetchLakehouseAlerts,
  fetchLakehouseDlq,
  fetchLakehouseSummary,
  triggerIngest,
  type IngestResponse,
} from "./api/threatIntel";

const queryClient = new QueryClient();

const DEFAULT_SAMPLE_LOG_PATH = "backend/sample_logs/sample_access.log";

function DashboardContent() {
  const [ingestMode, setIngestMode] = useState<"file" | "raw">("file");
  const [logPath, setLogPath] = useState<string>(DEFAULT_SAMPLE_LOG_PATH);
  const [sourceName, setSourceName] = useState<string>("custom_stream.log");
  const [rawText, setRawText] = useState<string>(
    [
      '203.0.113.25 - - [17/Nov/2026:14:25:30 +0000] "POST /login HTTP/1.1" 401 512 "DemoClient/1.0"',
      '203.0.113.25 - - [17/Nov/2026:14:25:31 +0000] "POST /login HTTP/1.1" 401 512 "DemoClient/1.0"',
      "malformed-log-line-for-dlq",
    ].join("\n")
  );
  const [failedLoginThreshold, setFailedLoginThreshold] = useState<number>(3);
  const [requestVolumeThreshold, setRequestVolumeThreshold] = useState<number>(5);
  const [lastIngest, setLastIngest] = useState<IngestResponse | null>(null);

  const healthQuery = useQuery({
    queryKey: ["health"],
    queryFn: fetchHealth,
    retry: 1,
  });

  const summaryQuery = useQuery({
    queryKey: ["lakehouse-summary"],
    queryFn: fetchLakehouseSummary,
    retry: false,
  });

  const alertsQuery = useQuery({
    queryKey: ["lakehouse-alerts", failedLoginThreshold, requestVolumeThreshold],
    queryFn: () =>
      fetchLakehouseAlerts({
        failed_login_threshold: failedLoginThreshold,
        request_volume_threshold: requestVolumeThreshold,
      }),
    retry: false,
  });

  const dlqQuery = useQuery({
    queryKey: ["lakehouse-dlq"],
    queryFn: fetchLakehouseDlq,
    retry: false,
  });

  const ingestMutation = useMutation({
    mutationFn: () =>
      ingestMode === "file"
        ? triggerIngest({
            log_path: logPath,
            failed_login_threshold: failedLoginThreshold,
            request_volume_threshold: requestVolumeThreshold,
          })
        : triggerIngest({
            raw_lines: rawText.split(/\r?\n/),
            source_name: sourceName,
            failed_login_threshold: failedLoginThreshold,
            request_volume_threshold: requestVolumeThreshold,
          }),
    onSuccess: (data) => {
      setLastIngest(data);
      queryClient.invalidateQueries({ queryKey: ["lakehouse-summary"] });
      queryClient.invalidateQueries({ queryKey: ["lakehouse-alerts"] });
      queryClient.invalidateQueries({ queryKey: ["lakehouse-dlq"] });
    },
  });

  const refreshAll = () => {
    healthQuery.refetch();
    summaryQuery.refetch();
    alertsQuery.refetch();
    dlqQuery.refetch();
  };

  const alerts = alertsQuery.data ?? lastIngest?.alerts ?? [];
  const summaryRows = summaryQuery.data ?? [];
  const dlqEntries = dlqQuery.data ?? [];

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      <header className="border-b border-slate-800 bg-slate-900/80 px-6 py-4">
        <div className="mx-auto flex max-w-7xl flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <ShieldAlert className="h-7 w-7 text-emerald-400" />
            <div>
              <h1 className="text-lg font-semibold tracking-tight">
                DevSecOps Threat Intelligence &amp; Log Analyzer
              </h1>
              <p className="text-xs text-slate-400">
                Medallion Lakehouse (Bronze / Silver / Gold / DLQ Parquet) • FastAPI &amp; DuckDB
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <span
              className={`inline-flex items-center gap-1.5 rounded-full px-3 py-1 text-xs font-medium ${
                healthQuery.isSuccess
                  ? "bg-emerald-950 text-emerald-300 ring-1 ring-emerald-700/60"
                  : "bg-rose-950 text-rose-300 ring-1 ring-rose-700/60"
              }`}
            >
              <Activity className="h-3.5 w-3.5" />
              {healthQuery.isSuccess ? "API Online" : "API Offline"}
            </span>
            <button
              type="button"
              onClick={refreshAll}
              className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800 px-3 py-1.5 text-xs font-medium text-slate-200 hover:bg-slate-700"
            >
              <RefreshCw className="h-3.5 w-3.5" />
              Refresh
            </button>
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-7xl space-y-6 px-6 py-6">
        <section className="grid gap-6 lg:grid-cols-3">
          <div className="rounded-xl border border-slate-800 bg-slate-900 p-5 lg:col-span-2">
            <div className="mb-4 flex items-center justify-between">
              <h2 className="flex items-center gap-2 text-sm font-semibold uppercase tracking-wider text-slate-300">
                <Database className="h-4 w-4 text-sky-400" />
                Ingestion &amp; Threshold Controls
              </h2>
              <div className="flex rounded-lg border border-slate-700 bg-slate-950 p-0.5 text-xs">
                <button
                  type="button"
                  onClick={() => setIngestMode("file")}
                  className={`rounded-md px-2.5 py-1 ${
                    ingestMode === "file"
                      ? "bg-sky-600 text-white"
                      : "text-slate-400 hover:text-slate-200"
                  }`}
                >
                  Log File
                </button>
                <button
                  type="button"
                  onClick={() => setIngestMode("raw")}
                  className={`rounded-md px-2.5 py-1 ${
                    ingestMode === "raw"
                      ? "bg-sky-600 text-white"
                      : "text-slate-400 hover:text-slate-200"
                  }`}
                >
                  Raw Lines
                </button>
              </div>
            </div>

            {ingestMode === "file" ? (
              <div className="space-y-3">
                <label className="block text-xs text-slate-400">
                  Log File Path (relative to backend or repo root)
                  <input
                    type="text"
                    value={logPath}
                    onChange={(e) => setLogPath(e.target.value)}
                    className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 focus:border-sky-500 focus:outline-none"
                  />
                </label>
              </div>
            ) : (
              <div className="space-y-3">
                <label className="block text-xs text-slate-400">
                  Source Name
                  <input
                    type="text"
                    value={sourceName}
                    onChange={(e) => setSourceName(e.target.value)}
                    className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 focus:border-sky-500 focus:outline-none"
                  />
                </label>
                <label className="block text-xs text-slate-400">
                  Raw Access Log Lines (one per line)
                  <textarea
                    rows={4}
                    value={rawText}
                    onChange={(e) => setRawText(e.target.value)}
                    className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 font-mono text-xs text-slate-100 focus:border-sky-500 focus:outline-none"
                  />
                </label>
              </div>
            )}

            <div className="mt-4 grid gap-4 sm:grid-cols-2">
              <label className="block text-xs text-slate-400">
                Failed Login Threshold (`RULE-AUTH-001`)
                <input
                  type="number"
                  min={1}
                  value={failedLoginThreshold}
                  onChange={(e) => setFailedLoginThreshold(Math.max(1, Number(e.target.value) || 1))}
                  className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 focus:border-sky-500 focus:outline-none"
                />
              </label>
              <label className="block text-xs text-slate-400">
                Request Volume Threshold (`RULE-VOL-001`)
                <input
                  type="number"
                  min={1}
                  value={requestVolumeThreshold}
                  onChange={(e) => setRequestVolumeThreshold(Math.max(1, Number(e.target.value) || 1))}
                  className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 focus:border-sky-500 focus:outline-none"
                />
              </label>
            </div>

            <div className="mt-5 flex items-center gap-3">
              <button
                type="button"
                onClick={() => ingestMutation.mutate()}
                disabled={ingestMutation.isPending}
                className="inline-flex items-center gap-2 rounded-lg bg-emerald-600 px-4 py-2 text-sm font-medium text-white hover:bg-emerald-500 disabled:opacity-50"
              >
                <Play className="h-4 w-4" />
                {ingestMutation.isPending ? "Ingesting..." : "Run Pipeline & Materialize Parquet"}
              </button>
              {ingestMutation.isError && (
                <span className="text-xs text-rose-400">
                  {(ingestMutation.error as Error)?.message ?? "Ingestion failed"}
                </span>
              )}
            </div>
          </div>

          <div className="rounded-xl border border-slate-800 bg-slate-900 p-5">
            <h2 className="mb-3 text-sm font-semibold uppercase tracking-wider text-slate-300">
              Latest Ingestion Snapshot
            </h2>
            {lastIngest ? (
              <div className="space-y-3 text-xs">
                <div className="grid grid-cols-2 gap-2">
                  <div className="rounded-lg bg-slate-950 p-3">
                    <div className="text-slate-400">Valid Events</div>
                    <div className="mt-0.5 text-lg font-semibold text-emerald-400">
                      {lastIngest.counts.valid_events}
                    </div>
                  </div>
                  <div className="rounded-lg bg-slate-950 p-3">
                    <div className="text-slate-400">DLQ Lines</div>
                    <div className="mt-0.5 text-lg font-semibold text-amber-400">
                      {lastIngest.counts.dead_letter_lines}
                    </div>
                  </div>
                </div>
                <div className="space-y-1.5 rounded-lg bg-slate-950 p-3 font-mono text-[11px] text-slate-300">
                  <div className="truncate">Bronze: {lastIngest.artifacts.bronze_parquet}</div>
                  <div className="truncate">Silver: {lastIngest.artifacts.silver_parquet}</div>
                  <div className="truncate">Gold: {lastIngest.artifacts.gold_parquet}</div>
                </div>
              </div>
            ) : (
              <p className="text-xs text-slate-400">
                Trigger an ingestion run to materialize Bronze, Silver, and Gold Parquet files and inspect counts.
              </p>
            )}
          </div>
        </section>

        <section className="rounded-xl border border-slate-800 bg-slate-900 p-5">
          <h2 className="mb-4 flex items-center gap-2 text-sm font-semibold uppercase tracking-wider text-slate-300">
            <AlertTriangle className="h-4 w-4 text-amber-400" />
            Threat Alerts Feed ({alerts.length})
          </h2>
          {alerts.length === 0 ? (
            <p className="text-xs text-slate-400">
              No alerts triggered at current thresholds. Lower thresholds or ingest suspicious log lines.
            </p>
          ) : (
            <div className="grid gap-3 md:grid-cols-2">
              {alerts.map((alert, idx) => (
                <div
                  key={`${alert.rule_id}-${alert.source_ip}-${idx}`}
                  className="rounded-lg border border-slate-800 bg-slate-950 p-4"
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-mono text-xs font-semibold text-sky-300">
                      {alert.rule_id}
                    </span>
                    <span
                      className={`rounded-full px-2.5 py-0.5 text-[11px] font-medium uppercase ${
                        alert.severity === "high"
                          ? "bg-rose-950 text-rose-300 ring-1 ring-rose-700/60"
                          : "bg-amber-950 text-amber-300 ring-1 ring-amber-700/60"
                      }`}
                    >
                      {alert.severity}
                    </span>
                  </div>
                  <div className="mt-2 font-mono text-sm text-white">{alert.source_ip}</div>
                  <p className="mt-1 text-xs text-slate-300">{alert.reason}</p>
                  <div className="mt-2 text-[11px] text-slate-400">
                    Matched Events: <span className="font-semibold text-slate-200">{alert.event_count}</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </section>

        <section className="grid gap-6 lg:grid-cols-3">
          <div className="rounded-xl border border-slate-800 bg-slate-900 p-5 lg:col-span-2">
            <h2 className="mb-4 text-sm font-semibold uppercase tracking-wider text-slate-300">
              Gold IP Summary (DuckDB Parquet)
            </h2>
            {summaryRows.length === 0 ? (
              <p className="text-xs text-slate-400">
                No Gold summary rows materialized yet. Run ingestion to populate Gold Parquet.
              </p>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead className="border-b border-slate-800 text-slate-400">
                    <tr>
                      <th className="py-2 pr-4">Source IP</th>
                      <th className="py-2 px-3">Requests</th>
                      <th className="py-2 px-3">Failed Logins</th>
                      <th className="py-2 px-3">4xx</th>
                      <th className="py-2 pl-3">5xx</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/70">
                    {summaryRows.map((row) => (
                      <tr key={row.source_ip} className="hover:bg-slate-800/40">
                        <td className="py-2.5 pr-4 font-mono text-slate-200">{row.source_ip}</td>
                        <td className="py-2.5 px-3">{row.total_requests}</td>
                        <td className="py-2.5 px-3 text-rose-300">{row.failed_logins}</td>
                        <td className="py-2.5 px-3 text-amber-300">{row.client_errors_4xx}</td>
                        <td className="py-2.5 pl-3 text-purple-300">{row.server_errors_5xx}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          <div className="rounded-xl border border-slate-800 bg-slate-900 p-5">
            <h2 className="mb-4 flex items-center gap-2 text-sm font-semibold uppercase tracking-wider text-slate-300">
              <FileWarning className="h-4 w-4 text-amber-400" />
              Dead-Letter Queue ({dlqEntries.length})
            </h2>
            {dlqEntries.length === 0 ? (
              <p className="text-xs text-slate-400">No malformed log lines in DLQ.</p>
            ) : (
              <div className="space-y-2.5">
                {dlqEntries.map((entry, idx) => (
                  <div
                    key={`${entry.rejected_at}-${idx}`}
                    className="rounded-lg border border-slate-800 bg-slate-950 p-3 text-xs"
                  >
                    <div className="font-mono text-amber-300 break-all">{entry.raw_line}</div>
                    <div className="mt-1 text-[11px] text-slate-500">{entry.source_name}</div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </section>
      </main>
    </div>
  );
}

export function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <DashboardContent />
    </QueryClientProvider>
  );
}

export default App;
