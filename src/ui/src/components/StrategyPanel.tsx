import { useTranslation } from "react-i18next";
import { useState } from "react";

interface Strategy {
  id: number;
  name: string;
  category: string;
  source: string;
  enabled: boolean;
}

const STRATEGIES: Strategy[] = [
  { id: 1, name: "MultiSplit", category: "tcp", source: "zapret", enabled: true },
  { id: 2, name: "MultiDisorder", category: "tcp", source: "zapret", enabled: true },
  { id: 3, name: "FakeDataSplit", category: "tcp", source: "zapret", enabled: true },
  { id: 4, name: "TcpSeg", category: "tcp", source: "zapret", enabled: false },
  { id: 5, name: "SynData", category: "tcp", source: "zapret", enabled: false },
  { id: 6, name: "FakeSni", category: "tcp", source: "byedpi", enabled: true },
  { id: 7, name: "OobInjection", category: "tcp", source: "byedpi", enabled: false },
  { id: 8, name: "Disorder", category: "tcp", source: "RIPDPI", enabled: false },
  { id: 9, name: "ByteByByte", category: "tcp", source: "rust-no-dpi-socks", enabled: false },
  { id: 10, name: "PortShuffle", category: "tcp", source: "CandyTunnel", enabled: false },
  { id: 11, name: "FragOverlap", category: "ip", source: "dpibreak", enabled: true },
  { id: 12, name: "BadChecksum", category: "ip", source: "zapret", enabled: false },
  { id: 13, name: "TtlManipulation", category: "ip", source: "zapret", enabled: false },
  { id: 14, name: "TtlJitter", category: "ip", source: "CandyTunnel", enabled: false },
  { id: 15, name: "DscpRandom", category: "ip", source: "CandyTunnel", enabled: false },
  { id: 16, name: "TlsRecordFrag", category: "tls", source: "zapret", enabled: true },
  { id: 17, name: "TlsRecordPad", category: "tls", source: "zapret", enabled: false },
  { id: 18, name: "SniMicrofrag", category: "tls", source: "omoikane", enabled: false },
  { id: 19, name: "H2SettingsFlood", category: "http", source: "NaiveProxy", enabled: false },
  { id: 20, name: "QuicBlocking", category: "quic", source: "zapret", enabled: true },
  { id: 21, name: "Udp2Icmp", category: "obfs", source: "zapret", enabled: false },
  { id: 22, name: "XorFirst", category: "obfs", source: "dpimyass", enabled: false },
  { id: 23, name: "ChaCha20", category: "crypto", source: "CandyTunnel", enabled: false },
];

const CATEGORY_COLORS: Record<string, string> = {
  tcp: "#3b82f6",
  ip: "#8b5cf6",
  tls: "#f59e0b",
  http: "#10b981",
  quic: "#ef4444",
  obfs: "#6366f1",
  crypto: "#ec4899",
};

export default function StrategyPanel() {
  const { t } = useTranslation();
  const [strategies, setStrategies] = useState(STRATEGIES);
  const [filter, setFilter] = useState<string>("all");

  const toggle = (id: number) => {
    setStrategies((prev) =>
      prev.map((s) => (s.id === id ? { ...s, enabled: !s.enabled } : s))
    );
  };

  const filtered =
    filter === "all" ? strategies : strategies.filter((s) => s.category === filter);

  const categories = ["all", "tcp", "ip", "tls", "http", "quic", "obfs", "crypto"];

  return (
    <div className="space-y-4">
      <h2 className="text-lg font-semibold">
        {t("strategies.title")} ({t("strategies.count", { count: strategies.length })})
      </h2>

      {/* Category filter */}
      <div className="flex gap-1 flex-wrap">
        {categories.map((cat) => (
          <button
            key={cat}
            onClick={() => setFilter(cat)}
            className="px-2 py-1 text-xs rounded-md transition-colors"
            style={{
              background: filter === cat ? "var(--accent)" : "var(--bg-muted)",
              color: filter === cat ? "var(--text-on-accent, #fff)" : "var(--text-secondary)",
              border: "1px solid var(--border)",
            }}
          >
            {cat === "all" ? "All" : t(`strategies.${cat}`)}
          </button>
        ))}
      </div>

      {/* Strategy list */}
      <div className="space-y-1">
        {filtered.map((s) => (
          <div
            key={s.id}
            className="flex items-center justify-between px-3 py-2 rounded-md"
            style={{ background: "var(--bg-elevated)", border: "1px solid var(--border)" }}
          >
            <div className="flex items-center gap-2">
              <span
                className="w-2 h-2 rounded-full"
                style={{ background: CATEGORY_COLORS[s.category] || "#888" }}
              />
              <span className="text-sm font-medium">{s.name}</span>
              <span className="text-xs" style={{ color: "var(--text-secondary)" }}>
                {s.source}
              </span>
            </div>
            <button
              onClick={() => toggle(s.id)}
              className="relative w-9 h-5 rounded-full transition-colors"
              style={{
                background: s.enabled ? "var(--accent)" : "var(--bg-muted)",
              }}
            >
              <span
                className="absolute top-0.5 left-0.5 w-4 h-4 rounded-full bg-white transition-transform"
                style={{
                  transform: s.enabled ? "translateX(16px)" : "translateX(0)",
                }}
              />
            </button>
          </div>
        ))}
      </div>
    </div>
  );
}
