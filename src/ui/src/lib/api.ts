import { invoke } from "@tauri-apps/api/core";

export async function getStatus(port?: number) {
  return invoke<StatusResponse>("get_status", { apiPort: port });
}

export async function getHealth(port?: number) {
  return invoke<HealthResponse>("get_health", { apiPort: port });
}

export async function getConntrack(port?: number) {
  return invoke<Record<string, unknown>>("get_conntrack", { apiPort: port });
}

export async function getConfig() {
  return invoke<{ raw: string }>("get_config");
}

export async function saveConfig(raw: string) {
  return invoke("save_config", { raw });
}

export interface StatusResponse {
  status: string;
  version: string;
  uptime_seconds: number;
  packets_processed: number;
  active_connections: number;
}

export interface HealthResponse {
  healthy: boolean;
  windivert_ok: boolean;
  raw_socket_ok: boolean;
}
