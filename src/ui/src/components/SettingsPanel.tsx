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
  zero_config_enabled: boolean;
  zero_config_auto_detect: boolean;
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
  zero_config_enabled: true,
  zero_config_auto_detect: false,
};

function parseTomlToSettings(raw: string): Partial<Settings> {
  const result: Partial<Settings> = {};
  let currentSection = "";
  for (const line of raw.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    if (trimmed.startsWith("[") && trimmed.endsWith("]")) {
      currentSection = trimmed.slice(1, -1).trim();
      continue;
    }
    const eq = trimmed.indexOf("=");
    if (eq === -1) continue;
    const key = trimmed.slice(0, eq).trim();
    const valStr = trimmed.slice(eq + 1).trim();
    let val: string | number | boolean = valStr;
    if (valStr.startsWith('"') && valStr.endsWith('"')) {
      val = valStr.slice(1, -1);
    } else if (valStr === "true") {
      val = true;
    } else if (valStr === "false") {
      val = false;
    } else if (!isNaN(Number(valStr))) {
      val = Number(valStr);
    }

    if (currentSection === "api" && key === "port") {
      result.api_port = val as number;
    } else if (currentSection === "windivert" && key === "filter") {
      result.windivert_filter = val as string;
    } else if (currentSection === "dns") {
      if (key === "doh_url") result.dns_doh_url = val as string;
      if (key === "dot_addr") result.dns_dot_addr = val as string;
      if (key === "cache_ttl") result.dns_cache_ttl = val as number;
    } else if (currentSection === "desync") {
      if (key === "fake_sni") result.fake_sni = val as string;
      if (key === "split_size") result.split_size = val as number;
      if (key === "split_count") result.split_count = val as number;
      if (key === "fake_ttl_offset") result.fake_ttl_offset = val as number;
    } else if (currentSection === "zero_config") {
      if (key === "enabled") result.zero_config_enabled = val as boolean;
      if (key === "auto_detect") result.zero_config_auto_detect = val as boolean;
    }
  }
  return result;
}

function settingsToToml(s: Settings): string {
  return `[api]
port = ${s.api_port}
enabled = true

[windivert]
filter = "${s.windivert_filter}"

[dns]
doh_url = "${s.dns_doh_url}"
dot_addr = "${s.dns_dot_addr}"
cache_ttl = ${s.dns_cache_ttl}

[desync]
fake_sni = "${s.fake_sni}"
split_size = ${s.split_size}
split_count = ${s.split_count}
fake_ttl_offset = ${s.fake_ttl_offset}

[zero_config]
enabled = ${s.zero_config_enabled}
auto_detect = ${s.zero_config_auto_detect}
`;
}

export default function SettingsPanel() {
  const { t } = useTranslation();
  const [settings, setSettings] = useState<Settings>(DEFAULT_SETTINGS);
  const [saved, setSaved] = useState(false);

  const update = (key: keyof Settings, value: string | number | boolean) => {
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

  useState(() => {
    load();
  });

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
        {/* Zero-Config Whitelist Bypass Settings */}
        <SettingGroup title={t("settings.zero_config_title")}>
          <SettingCheckbox
            label={t("settings.zero_config_enabled")}
            description={t("settings.zero_config_enabled_desc")}
            value={settings.zero_config_enabled}
            onChange={(v) => update("zero_config_enabled", v)}
          />
          <div className="pt-2 border-t" style={{ borderColor: "var(--border)" }}>
            <SettingCheckbox
              label={t("settings.zero_config_auto_detect")}
              description={t("settings.zero_config_auto_detect_desc")}
              value={settings.zero_config_auto_detect}
              onChange={(v) => update("zero_config_auto_detect", v)}
            />
          </div>
        </SettingGroup>

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

function SettingCheckbox({
  label,
  description,
  value,
  onChange,
}: {
  label: string;
  description?: string;
  value: boolean;
  onChange: (v: boolean) => void;
}) {
  return (
    <div className="flex items-start space-x-3 py-1">
      <input
        type="checkbox"
        checked={value}
        onChange={(e) => onChange(e.target.checked)}
        className="mt-1 h-4 w-4 rounded border-gray-300 text-indigo-600 focus:ring-indigo-500 cursor-pointer"
      />
      <div className="text-sm">
        <label className="font-medium cursor-pointer" style={{ color: "var(--text-primary)" }} onClick={() => onChange(!value)}>
          {label}
        </label>
        {description && (
          <p className="text-xs mt-0.5" style={{ color: "var(--text-secondary)" }}>
            {description}
          </p>
        )}
      </div>
    </div>
  );
}
