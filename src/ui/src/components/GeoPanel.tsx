import { useState, useEffect, useCallback } from "react";
import { useTranslation } from "react-i18next";
import {
  getGeoblockState,
  addGeoblockDomain,
  removeGeoblockDomain,
  saveGeoblockProxyConfig,
  GeoblockState,
} from "@/lib/api";

interface Region {
  key: string;
  color: string;
  defaultDomains: number;
}

const REGIONS: Region[] = [
  { key: "russia", color: "#ef4444", defaultDomains: 47 },
  { key: "europe", color: "#3b82f6", defaultDomains: 47 },
  { key: "us", color: "#10b981", defaultDomains: 47 },
  { key: "global", color: "#8b5cf6", defaultDomains: 0 },
  { key: "excluded", color: "#6b7280", defaultDomains: 9 },
];

export default function GeoPanel() {
  const { t } = useTranslation();
  const [state, setState] = useState<GeoblockState | null>(null);
  const [newValue, setNewValue] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<{ text: string; ok: boolean } | null>(null);

  const [proxyEnabled, setProxyEnabled] = useState(false);
  const [proxyHost, setProxyHost] = useState("");
  const [proxyPort, setProxyPort] = useState(1080);
  const [proxyUsername, setProxyUsername] = useState("");
  const [proxyPassword, setProxyPassword] = useState("");
  const [operaFallback, setOperaFallback] = useState(true);

  const load = useCallback(async () => {
    try {
      const gs = await getGeoblockState();
      setState(gs);
      setError(null);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
    const interval = setInterval(load, 3000);
    return () => clearInterval(interval);
  }, [load]);

  useEffect(() => {
    if (state) {
      setProxyEnabled((prev) => (state.custom_proxy_enabled !== undefined ? state.custom_proxy_enabled : prev));
      setProxyHost((prev) => state.custom_proxy_host || prev);
      setProxyPort((prev) => state.custom_proxy_port || prev);
      setProxyUsername((prev) => state.custom_proxy_username || prev);
      setOperaFallback((prev) => (state.use_opera_fallback !== undefined ? state.use_opera_fallback : prev));
    }
  }, [state]);

  const handleSaveProxy = async () => {
    try {
      await saveGeoblockProxyConfig({
        enabled: proxyEnabled,
        host: proxyHost,
        port: proxyPort,
        username: proxyUsername || undefined,
        password: proxyPassword || undefined,
        use_opera_fallback: operaFallback,
      });
      showMsg(t("settings.saved") || "Saved", true);
    } catch (e) {
      showMsg(String(e), false);
    }
  };

  const showMsg = (text: string, ok: boolean) => {
    setMessage({ text, ok });
    setTimeout(() => setMessage(null), 2000);
  };

  const handleAdd = async () => {
    const val = newValue.trim().toLowerCase();
    if (!val) return;
    try {
      await addGeoblockDomain(val);
      setNewValue("");
      showMsg(t("splittunnel.added") || "Added", true);
      await load();
    } catch (e) {
      showMsg(String(e), false);
    }
  };

  const handleRemove = async (domain: string) => {
    try {
      await removeGeoblockDomain(domain);
      showMsg(t("splittunnel.removed") || "Removed", true);
      await load();
    } catch (e) {
      showMsg(String(e), false);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter") {
      handleAdd();
    }
  };

  if (loading && !state) {
    return (
      <div className="flex items-center justify-center h-32" style={{ color: "var(--text-secondary)" }}>
        Loading...
      </div>
    );
  }

  return (
    <div className="space-y-6" style={{ color: "var(--text)" }}>
      {/* 1. Header & Overview */}
      <div className="space-y-4">
        <h2 className="text-lg font-semibold">{t("geo.title")}</h2>
        
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {REGIONS.map((r) => {
            // If Europe, we combine default count + user custom domains count
            let displayCount = r.defaultDomains;
            if (r.key === "europe" && state) {
              displayCount = state.static_count;
            }

            return (
              <div
                key={r.key}
                className="flex items-center justify-between p-3 rounded-lg transition-all duration-200"
                style={{ 
                  background: "var(--bg-elevated)", 
                  border: "1px solid var(--border)",
                  boxShadow: "0 2px 4px rgba(0,0,0,0.02)"
                }}
              >
                <div className="flex items-center gap-3">
                  <div
                    className="w-3 h-3 rounded-full shadow-sm"
                    style={{ background: r.color }}
                  />
                  <div>
                    <div className="text-sm font-medium">{t(`geo.${r.key}`)}</div>
                    <div className="text-xs" style={{ color: "var(--text-secondary)" }}>
                      {t("geo.domains", { count: displayCount })}
                    </div>
                  </div>
                </div>
                <div
                  className="text-xs px-2 py-1 rounded font-mono"
                  style={{ background: "var(--bg-muted)", color: "var(--text-secondary)" }}
                >
                  {r.key === "russia" && "Direct → SOCKS5"}
                  {r.key === "europe" && "OperaProxy → Direct"}
                  {r.key === "us" && "UserProxy → Direct"}
                  {r.key === "global" && "Direct"}
                  {r.key === "excluded" && "Pass-through"}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Custom SOCKS5 Proxy Settings */}
      <div 
        className="p-4 rounded-xl space-y-4"
        style={{ 
          background: "var(--bg-elevated)", 
          border: "1px solid var(--border)",
          boxShadow: "0 4px 6px rgba(0,0,0,0.02)"
        }}
      >
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-semibold uppercase tracking-wider" style={{ color: "var(--text-secondary)" }}>
            {t("geo.proxy_title") || "Кастомный SOCKS5 Прокси"}
          </h3>
          <button 
            onClick={handleSaveProxy}
            className="px-4 py-1.5 text-xs font-semibold rounded-lg shadow-sm active:scale-95 transition-all"
            style={{ background: "var(--accent)", color: "white" }}
          >
            {t("geo.save_proxy_btn") || "Сохранить"}
          </button>
        </div>

        <div className="flex items-center justify-between pt-1">
          <label className="flex items-center gap-2 cursor-pointer">
            <input 
              type="checkbox" 
              checked={proxyEnabled} 
              onChange={(e) => setProxyEnabled(e.target.checked)}
              className="w-4 h-4 rounded accent-indigo-600"
            />
            <span className="text-xs font-medium">{t("geo.proxy_enable") || "Использовать кастомный прокси"}</span>
          </label>
        </div>

        {proxyEnabled && (
          <div className="space-y-3 pt-2">
            <div className="grid grid-cols-3 gap-3">
              <div className="col-span-2 space-y-1">
                <label className="text-xs font-medium" style={{ color: "var(--text-secondary)" }}>
                  Host / IP
                </label>
                <input 
                  type="text" 
                  value={proxyHost}
                  onChange={(e) => setProxyHost(e.target.value)}
                  placeholder="127.0.0.1"
                  className="w-full px-3 py-1.5 text-xs rounded-lg outline-none"
                  style={{ background: "var(--bg-muted)", border: "1px solid var(--border)", color: "var(--text)" }}
                />
              </div>
              <div className="space-y-1">
                <label className="text-xs font-medium" style={{ color: "var(--text-secondary)" }}>
                  Port
                </label>
                <input 
                  type="number" 
                  value={proxyPort}
                  onChange={(e) => setProxyPort(Number(e.target.value))}
                  placeholder="1080"
                  className="w-full px-3 py-1.5 text-xs rounded-lg outline-none"
                  style={{ background: "var(--bg-muted)", border: "1px solid var(--border)", color: "var(--text)" }}
                />
              </div>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1">
                <label className="text-xs font-medium" style={{ color: "var(--text-secondary)" }}>
                  Username
                </label>
                <input 
                  type="text" 
                  value={proxyUsername}
                  onChange={(e) => setProxyUsername(e.target.value)}
                  placeholder="Optional"
                  className="w-full px-3 py-1.5 text-xs rounded-lg outline-none"
                  style={{ background: "var(--bg-muted)", border: "1px solid var(--border)", color: "var(--text)" }}
                />
              </div>
              <div className="space-y-1">
                <label className="text-xs font-medium" style={{ color: "var(--text-secondary)" }}>
                  Password
                </label>
                <input 
                  type="password" 
                  value={proxyPassword}
                  onChange={(e) => setProxyPassword(e.target.value)}
                  placeholder="••••••••"
                  className="w-full px-3 py-1.5 text-xs rounded-lg outline-none"
                  style={{ background: "var(--bg-muted)", border: "1px solid var(--border)", color: "var(--text)" }}
                />
              </div>
            </div>

            <div className="flex items-center justify-between pt-1">
              <label className="flex items-center gap-2 cursor-pointer">
                <input 
                  type="checkbox" 
                  checked={operaFallback} 
                  onChange={(e) => setOperaFallback(e.target.checked)}
                  className="w-4 h-4 rounded accent-indigo-600"
                />
                <span className="text-xs">{t("geo.opera_fallback") || "Использовать Opera Proxy как fallback"}</span>
              </label>
            </div>
          </div>
        )}
      </div>

      <hr style={{ borderColor: "var(--border)" }} />

      {/* 2. Custom domains editor */}
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-semibold uppercase tracking-wider" style={{ color: "var(--text-secondary)" }}>
            {t("geo.custom_title")}
          </h3>
          {message && (
            <span
              className="text-xs px-2 py-0.5 rounded transition-all duration-300"
              style={{
                background: message.ok ? "rgba(16, 185, 129, 0.1)" : "rgba(239, 68, 68, 0.1)",
                color: message.ok ? "var(--success)" : "var(--destructive)",
              }}
            >
              {message.text}
            </span>
          )}
        </div>

        {/* Input box */}
        <div className="flex gap-2">
          <input
            type="text"
            value={newValue}
            onChange={(e) => setNewValue(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder={t("geo.add_placeholder")}
            className="flex-1 px-3 py-2 text-sm rounded-lg outline-none transition-all duration-200"
            style={{
              background: "var(--bg-elevated)",
              border: "1px solid var(--border)",
              color: "var(--text)",
            }}
          />
          <button
            onClick={handleAdd}
            className="px-4 py-2 text-sm font-semibold rounded-lg shadow-sm transition-all duration-200 active:scale-95"
            style={{
              background: "var(--accent)",
              color: "white",
            }}
          >
            {t("geo.add_btn")}
          </button>
        </div>

        {/* Tags list */}
        <div 
          className="p-3 rounded-lg min-h-[100px] border border-dashed"
          style={{ 
            background: "rgba(0,0,0,0.02)",
            borderColor: "var(--border)",
          }}
        >
          {state && state.user_domains.length > 0 ? (
            <div className="flex flex-wrap gap-2">
              {state.user_domains.map((domain) => (
                <span
                  key={domain}
                  className="inline-flex items-center gap-1.5 px-2.5 py-1 text-xs rounded-full shadow-sm transition-all duration-150 hover:bg-opacity-80"
                  style={{ background: "var(--bg-elevated)", border: "1px solid var(--border)", color: "var(--text)" }}
                >
                  <span className="font-mono">{domain}</span>
                  <button
                    onClick={() => handleRemove(domain)}
                    className="hover:opacity-75 transition-all duration-150"
                    style={{ color: "var(--destructive)", fontSize: "14px", fontWeight: "bold" }}
                    title="Remove"
                  >
                    &times;
                  </button>
                </span>
              ))}
            </div>
          ) : (
            <div className="flex items-center justify-center h-16 text-xs" style={{ color: "var(--text-secondary)" }}>
              {t("geo.no_custom_domains")}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
