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

export interface SplitTunnelState {
  mode: string;
  blacklist_domains: string[];
  blacklist_ips: string[];
  blacklist_cidrs: string[];
  whitelist_domains: string[];
  whitelist_ips: string[];
  whitelist_cidrs: string[];
}

export async function getSplitTunnel(port?: number) {
  return invoke<SplitTunnelState>("get_split_tunnel", { apiPort: port });
}

export async function setSplitTunnelMode(mode: string, port?: number) {
  return invoke<void>("set_split_tunnel_mode", { mode, apiPort: port });
}

export async function addSplitTunnelEntry(
  list: string,
  entryType: string,
  value: string,
  port?: number
) {
  return invoke<void>("add_split_tunnel_entry", {
    list,
    entryType,
    value,
    apiPort: port,
  });
}

export async function removeSplitTunnelEntry(
  list: string,
  entryType: string,
  value: string,
  port?: number
) {
  return invoke<void>("remove_split_tunnel_entry", {
    list,
    entryType,
    value,
    apiPort: port,
  });
}

export interface GeoblockState {
  static_count: number;
  user_domains: string[];
  probed_domains: string[];
}

export async function getGeoblockState(port?: number) {
  return invoke<GeoblockState>("get_geoblock_state", { apiPort: port });
}

export async function addGeoblockDomain(domain: string, port?: number) {
  return invoke<void>("add_geoblock_domain", { domain, apiPort: port });
}

export async function removeGeoblockDomain(domain: string, port?: number) {
  return invoke<void>("remove_geoblock_domain", { domain, apiPort: port });
}
