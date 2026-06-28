import { useTranslation } from "react-i18next";
import { useEngine } from "@/contexts/EngineContext";
import StatsGraph from "./StatsGraph";

export default function StatusPanel() {
  const { t } = useTranslation();
  const { status, isOnline } = useEngine();

  const uptime = status?.uptime_seconds || 0;
  const h = Math.floor(uptime / 3600);
  const m = Math.floor((uptime % 3600) / 60);
  const s = uptime % 60;

  return (
    <div className="space-y-4">
      <h2 className="text-lg font-semibold">{t("status.title")}</h2>

      <div className="grid grid-cols-2 gap-3">
        <StatusCard
          label={t("status.uptime")}
          value={`${h}${t("status.hours")} ${m}${t("status.minutes")} ${s}${t("status.seconds")}`}
          color="var(--accent)"
        />
        <StatusCard
          label={t("status.packets")}
          value={formatNumber(status?.packets_processed || 0)}
          color="var(--accent)"
        />
        <StatusCard
          label={t("status.connections")}
          value={String(status?.active_connections || 0)}
          color="var(--accent)"
        />
        <StatusCard
          label={t("status.windivert")}
          value={status?.windivert_ok ? t("status.ok") : t("status.error")}
          color={status?.windivert_ok ? "var(--accent)" : "var(--destructive)"}
        />
      </div>

      <StatsGraph />
    </div>
  );
}

function StatusCard({
  label,
  value,
  color,
}: {
  label: string;
  value: string;
  color: string;
}) {
  return (
    <div
      className="p-3 rounded-lg"
      style={{ background: "var(--bg-elevated)", border: "1px solid var(--border)" }}
    >
      <div className="text-xs" style={{ color: "var(--text-secondary)" }}>
        {label}
      </div>
      <div className="text-xl font-bold mt-1" style={{ color }}>
        {value}
      </div>
    </div>
  );
}

function formatNumber(n: number): string {
  if (n >= 1_000_000) return (n / 1_000_000).toFixed(1) + "M";
  if (n >= 1_000) return (n / 1_000).toFixed(1) + "K";
  return String(n);
}
