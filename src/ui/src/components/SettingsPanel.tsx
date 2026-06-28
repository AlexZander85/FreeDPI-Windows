import { useTranslation } from "react-i18next";
import { useState } from "react";
import { getConfig, saveConfig } from "@/lib/api";

interface Settings {
  windivert_filter: string;
  split_size: number;
  split_count: number;
  fake_sni: string;
  fake_ttl_offset: number;
  api_port: number;
  dns_doh_url: string;
  dns_dot_addr: string;
  dns_cache_ttl: number;
}

const DEFAULT_SETTINGS: Settings = {
  windivert_filter: "ip && (tcp.DstPort == 443 or tcp.SrcPort == 443 or udp.DstPort == 53 or udp.DstPort == 443)",
  split_size: 1,
  split_count: 3,
  fake_sni: "www.google.com",
  fake_ttl_offset: 1,
  api_port: 11337,
  dns_doh_url: "https://cloudflare-dns.com/dns-query",
  dns_dot_addr: "1.1.1.1:853",
  dns_cache_ttl: 300,
};

function parseTomlToSettings(raw: string): Partial<Settings> {
  const result: Record<string, string | number> = {};
  for (const line of raw.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const eq = trimmed.indexOf("=");
    if (eq === -1) continue;
    const key = trimmed.slice(0, eq).trim();
    let val: string | number = trimmed.slice(eq + 1).trim();
    if (typeof val === "string" && val.startsWith('"') && val.endsWith('"')) {
      val = val.slice(1, -1);
    } else if (!isNaN(Number(val))) {
      val = Number(val);
    }
    result[key] = val;
  }
  return result as Partial<Settings>;
}

function settingsToToml(s: Settings): string {
  const lines: string[] = [];
  for (const [key, val] of Object.entries(s)) {
    if (typeof val === "string") {
      lines.push(`${key} = "${val}"`);
    } else {
      lines.push(`${key} = ${val}`);
    }
  }
  return lines.join("\n");
}

export default function SettingsPanel() {
  const { t } = useTranslation();
  const [settings, setSettings] = useState<Settings>(DEFAULT_SETTINGS);
  const [saved, setSaved] = useState(false);

  const update = (key: keyof Settings, value: string | number) => {
    setSettings((prev) => ({ ...prev, [key]: value }));
    setSaved(false);
  };

  const save = async () => {
    try {
      const toml = settingsToToml(settings);
      await saveConfig(toml);
      localStorage.setItem("byebyedpi-api-port", String(settings.api_port));
      setSaved(true);
      setTimeout(() => setSaved(false), 2000);
    } catch (e) {
      console.error("Failed to save config:", e);
    }
  };

  const load = async () => {
    try {
      const { raw } = await getConfig();
      if (raw) {
        const parsed = parseTomlToSettings(raw);
        setSettings((prev) => ({ ...prev, ...parsed }));
      }
    } catch (e) {
      console.error("Failed to load config:", e);
    }
  };

  useState(() => { load(); });

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold">{t("settings.title")}</h2>
        <button
          onClick={save}
          className="px-4 py-1.5 text-sm font-medium rounded-md transition-colors"
          style={{
            background: saved ? "var(--accent)" : "var(--accent)",
            color: "var(--text-on-accent, #fff)",
          }}
        >
          {saved ? t("settings.saved") : t("settings.save")}
        </button>
      </div>

      <div className="space-y-3">
        <SettingGroup title={t("settings.advanced")}>
          <SettingInput
            label={t("settings.windivert_filter")}
            value={settings.windivert_filter}
            onChange={(v) => update("windivert_filter", v)}
          />
          <div className="grid grid-cols-2 gap-3">
            <SettingNumber
              label={t("settings.split_size")}
              value={settings.split_size}
              onChange={(v) => update("split_size", v)}
            />
            <SettingNumber
              label={t("settings.split_count")}
              value={settings.split_count}
              onChange={(v) => update("split_count", v)}
            />
          </div>
          <SettingInput
            label={t("settings.fake_sni")}
            value={settings.fake_sni}
            onChange={(v) => update("fake_sni", v)}
          />
          <SettingNumber
            label={t("settings.fake_ttl_offset")}
            value={settings.fake_ttl_offset}
            onChange={(v) => update("fake_ttl_offset", v)}
          />
        </SettingGroup>

        <SettingGroup title={t("settings.general")}>
          <SettingNumber
            label={t("settings.api_port")}
            value={settings.api_port}
            onChange={(v) => update("api_port", v)}
          />
          <SettingInput
            label={t("settings.dns_doh_url")}
            value={settings.dns_doh_url}
            onChange={(v) => update("dns_doh_url", v)}
          />
          <SettingInput
            label={t("settings.dns_dot_addr")}
            value={settings.dns_dot_addr}
            onChange={(v) => update("dns_dot_addr", v)}
          />
          <SettingNumber
            label={t("settings.dns_cache_ttl")}
            value={settings.dns_cache_ttl}
            onChange={(v) => update("dns_cache_ttl", v)}
          />
        </SettingGroup>
      </div>
    </div>
  );
}

function SettingGroup({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <div
      className="p-3 rounded-lg space-y-3"
      style={{ background: "var(--bg-elevated)", border: "1px solid var(--border)" }}
    >
      <div className="text-sm font-medium">{title}</div>
      {children}
    </div>
  );
}

function SettingInput({
  label,
  value,
  onChange,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
}) {
  return (
    <div>
      <label className="text-xs block mb-1" style={{ color: "var(--text-secondary)" }}>
        {label}
      </label>
      <input
        type="text"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="w-full px-3 py-1.5 text-sm rounded-md outline-none"
        style={{
          background: "var(--bg-muted)",
          color: "var(--text-primary)",
          border: "1px solid var(--border)",
        }}
      />
    </div>
  );
}

function SettingNumber({
  label,
  value,
  onChange,
}: {
  label: string;
  value: number;
  onChange: (v: number) => void;
}) {
  return (
    <div>
      <label className="text-xs block mb-1" style={{ color: "var(--text-secondary)" }}>
        {label}
      </label>
      <input
        type="number"
        value={value}
        onChange={(e) => onChange(Number(e.target.value))}
        className="w-full px-3 py-1.5 text-sm rounded-md outline-none"
        style={{
          background: "var(--bg-muted)",
          color: "var(--text-primary)",
          border: "1px solid var(--border)",
        }}
      />
    </div>
  );
}
