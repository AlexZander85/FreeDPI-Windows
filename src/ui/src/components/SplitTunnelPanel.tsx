import { useState, useEffect, useCallback } from "react";
import { useTranslation } from "react-i18next";
import {
  getSplitTunnel,
  setSplitTunnelMode,
  addSplitTunnelEntry,
  removeSplitTunnelEntry,
  SplitTunnelState,
} from "@/lib/api";

type ListType = "blacklist" | "whitelist";
type EntryType = "domain" | "ip" | "cidr";

export default function SplitTunnelPanel() {
  const { t } = useTranslation();
  const [state, setState] = useState<SplitTunnelState | null>(null);
  const [activeList, setActiveList] = useState<ListType>("blacklist");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [newValue, setNewValue] = useState("");
  const [activeEntryType, setActiveEntryType] = useState<EntryType>("domain");
  const [message, setMessage] = useState<{ text: string; ok: boolean } | null>(null);

  const load = useCallback(async () => {
    try {
      setLoading(true);
      const st = await getSplitTunnel();
      setState(st);
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

  const showMsg = (text: string, ok: boolean) => {
    setMessage({ text, ok });
    setTimeout(() => setMessage(null), 2000);
  };

  const handleModeChange = async (mode: string) => {
    try {
      await setSplitTunnelMode(mode);
      showMsg(t("splittunnel.mode_updated"), true);
    } catch (e) {
      showMsg(String(e), false);
    }
  };

  const handleAdd = async () => {
    const val = newValue.trim();
    if (!val) return;
    try {
      await addSplitTunnelEntry(activeList, activeEntryType, val);
      setNewValue("");
      showMsg(t("splittunnel.added"), true);
      await load();
    } catch (e) {
      showMsg(String(e), false);
    }
  };

  const handleRemove = async (entryType: EntryType, value: string) => {
    try {
      await removeSplitTunnelEntry(activeList, entryType, value);
      showMsg(t("splittunnel.removed"), true);
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

  if (error && !state) {
    return (
      <div className="p-4" style={{ color: "var(--destructive)" }}>
        {error}
      </div>
    );
  }

  const currentMode = state?.mode || "BlacklistOnly";
  const entries =
    activeList === "blacklist"
      ? {
          domains: state?.blacklist_domains || [],
          ips: state?.blacklist_ips || [],
          cidrs: state?.blacklist_cidrs || [],
        }
      : {
          domains: state?.whitelist_domains || [],
          ips: state?.whitelist_ips || [],
          cidrs: state?.whitelist_cidrs || [],
        };

  const renderEntryList = (items: string[], entryType: EntryType) => {
    if (items.length === 0) {
      return (
        <div className="text-xs py-2" style={{ color: "var(--text-secondary)" }}>
          {t("splittunnel.no_entries")}
        </div>
      );
    }
    return (
      <div className="flex flex-wrap gap-1 py-1">
        {items.map((item, i) => (
          <span
            key={`${entryType}-${i}`}
            className="inline-flex items-center gap-1 px-2 py-0.5 text-xs rounded-md"
            style={{ background: "var(--bg-muted)", color: "var(--text)" }}
          >
            {item}
            <button
              onClick={() => handleRemove(entryType, item)}
              className="hover:opacity-70"
              style={{ color: "var(--destructive)" }}
              title={t("splittunnel.remove")}
            >
              &times;
            </button>
          </span>
        ))}
      </div>
    );
  };

  return (
    <div style={{ color: "var(--text)" }}>
      {message && (
        <div
          className="text-xs px-3 py-1 rounded mb-2"
          style={{
            background: message.ok ? "var(--accent)" : "var(--destructive)",
            color: "#fff",
          }}
        >
          {message.text}
        </div>
      )}

      {/* Mode Selector */}
      <div className="mb-4">
        <h3 className="text-sm font-semibold mb-2">{t("splittunnel.mode")}</h3>
        <div className="flex gap-1">
          {(["BlacklistOnly", "WhitelistOnly", "Auto"] as const).map((mode) => (
            <button
              key={mode}
              onClick={() => handleModeChange(mode)}
              className="px-3 py-1.5 text-xs font-medium rounded-md transition-colors"
              style={{
                background: currentMode === mode ? "var(--accent)" : "var(--bg-muted)",
                color: currentMode === mode ? "#fff" : "var(--text-secondary)",
                border: `1px solid ${currentMode === mode ? "var(--accent)" : "var(--border)"}`,
              }}
            >
              {t(`splittunnel.${mode === "BlacklistOnly" ? "blacklist_only" : mode === "WhitelistOnly" ? "whitelist_only" : "auto"}`)}
            </button>
          ))}
        </div>
      </div>

      {/* List tabs: Blacklist / Whitelist */}
      <div className="mb-2">
        <div className="flex gap-1">
          {(["blacklist", "whitelist"] as const).map((list) => (
            <button
              key={list}
              onClick={() => setActiveList(list)}
              className="px-3 py-1.5 text-xs font-medium rounded-md transition-colors"
              style={{
                background: activeList === list ? "var(--accent)" : "var(--bg-muted)",
                color: activeList === list ? "#fff" : "var(--text-secondary)",
              }}
            >
              {t(`splittunnel.${list}`)}
            </button>
          ))}
        </div>
      </div>

      {/* Add Entry */}
      <div className="flex gap-1 mb-3">
        <select
          value={activeEntryType}
          onChange={(e) => setActiveEntryType(e.target.value as EntryType)}
          className="px-2 py-1 text-xs rounded-md"
          style={{
            background: "var(--bg-muted)",
            color: "var(--text)",
            border: "1px solid var(--border)",
          }}
        >
          <option value="domain">{t("splittunnel.domains")}</option>
          <option value="ip">{t("splittunnel.ips")}</option>
          <option value="cidr">{t("splittunnel.cidrs")}</option>
        </select>
        <input
          type="text"
          value={newValue}
          onChange={(e) => setNewValue(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder={t(
            `splittunnel.placeholder_${
              activeEntryType === "domain"
                ? "domain"
                : activeEntryType === "ip"
                ? "ip"
                : "cidr"
            }`
          )}
          className="flex-1 px-2 py-1 text-xs rounded-md"
          style={{
            background: "var(--bg-muted)",
            color: "var(--text)",
            border: "1px solid var(--border)",
          }}
        />
        <button
          onClick={handleAdd}
          className="px-3 py-1 text-xs font-medium rounded-md"
          style={{
            background: "var(--accent)",
            color: "#fff",
          }}
        >
          {t(
            `splittunnel.add_${
              activeEntryType === "domain"
                ? "domain"
                : activeEntryType === "ip"
                ? "ip"
                : "cidr"
            }`
          )}
        </button>
      </div>

      {/* Current entries by type */}
      <div className="space-y-1">
        <div className="text-xs font-semibold py-1" style={{ color: "var(--text-secondary)" }}>
          {t("splittunnel.domains")} ({entries.domains.length})
        </div>
        {renderEntryList(entries.domains, "domain")}

        <div className="text-xs font-semibold py-1" style={{ color: "var(--text-secondary)" }}>
          {t("splittunnel.ips")} ({entries.ips.length})
        </div>
        {renderEntryList(entries.ips, "ip")}

        <div className="text-xs font-semibold py-1" style={{ color: "var(--text-secondary)" }}>
          {t("splittunnel.cidrs")} ({entries.cidrs.length})
        </div>
        {renderEntryList(entries.cidrs, "cidr")}
      </div>
    </div>
  );
}
