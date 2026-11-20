import axios from "axios";

const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL ?? "http://127.0.0.1:8000",
  headers: {
    "Content-Type": "application/json",
  },
});

export interface ThreatAlert {
  rule_id: string;
  severity: "high" | "medium" | "low" | string;
  source_ip: string;
  reason: string;
  event_count: number;
}

export interface IpSummaryRow {
  source_ip: string;
  total_requests: number;
  failed_logins: number;
  client_errors_4xx: number;
  server_errors_5xx: number;
}

export interface DlqEntry {
  raw_line: string;
  source_name: string;
  rejected_at: string;
}

export interface IngestResponse {
  source_name: string;
  counts: {
    raw_lines: number;
    valid_events: number;
    dead_letter_lines: number;
    alerts: number;
  };
  artifacts: {
    bronze_parquet: string;
    silver_parquet: string;
    gold_parquet: string;
    dlq_parquet: string | null;
  };
  alerts: ThreatAlert[];
}

export interface IngestPayload {
  log_path?: string;
  raw_lines?: string[];
  source_name?: string;
  failed_login_threshold?: number;
  request_volume_threshold?: number;
}

export async function fetchHealth(): Promise<{ status: string }> {
  const { data } = await api.get<{ status: string }>("/health");
  return data;
}

export async function triggerIngest(payload: IngestPayload): Promise<IngestResponse> {
  const { data } = await api.post<IngestResponse>("/ingest", payload);
  return data;
}

export async function fetchLakehouseSummary(): Promise<IpSummaryRow[]> {
  const { data } = await api.get<IpSummaryRow[]>("/lakehouse/summary");
  return data;
}

export async function fetchLakehouseAlerts(params?: {
  failed_login_threshold?: number;
  request_volume_threshold?: number;
}): Promise<ThreatAlert[]> {
  const { data } = await api.get<ThreatAlert[]>("/lakehouse/alerts", { params });
  return data;
}

export async function fetchLakehouseDlq(): Promise<DlqEntry[]> {
  const { data } = await api.get<DlqEntry[]>("/lakehouse/dlq");
  return data;
}
