import { useTranslation } from "react-i18next";

interface Region {
  key: string;
  color: string;
  domains: number;
}

const REGIONS: Region[] = [
  { key: "russia", color: "#ef4444", domains: 47 },
  { key: "europe", color: "#3b82f6", domains: 47 },
  { key: "us", color: "#10b981", domains: 47 },
  { key: "global", color: "#8b5cf6", domains: 0 },
  { key: "excluded", color: "#6b7280", domains: 9 },
];

export default function GeoPanel() {
  const { t } = useTranslation();

  return (
    <div className="space-y-4">
      <h2 className="text-lg font-semibold">{t("geo.title")}</h2>

      <div className="grid grid-cols-1 gap-3">
        {REGIONS.map((r) => (
          <div
            key={r.key}
            className="flex items-center justify-between p-3 rounded-lg"
            style={{ background: "var(--bg-elevated)", border: "1px solid var(--border)" }}
          >
            <div className="flex items-center gap-3">
              <div
                className="w-3 h-3 rounded-full"
                style={{ background: r.color }}
              />
              <div>
                <div className="text-sm font-medium">{t(`geo.${r.key}`)}</div>
                <div className="text-xs" style={{ color: "var(--text-secondary)" }}>
                  {t("geo.domains", { count: r.domains })}
                </div>
              </div>
            </div>
            <div
              className="text-xs px-2 py-1 rounded"
              style={{ background: "var(--bg-muted)", color: "var(--text-secondary)" }}
            >
              {r.key === "russia" && "Direct → SOCKS5"}
              {r.key === "europe" && "OperaVPN → Direct"}
              {r.key === "us" && "UserProxy → Direct"}
              {r.key === "global" && "Direct"}
              {r.key === "excluded" && "Pass-through"}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
