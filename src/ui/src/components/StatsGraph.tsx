import { useTranslation } from "react-i18next";
import { useEngine } from "@/contexts/EngineContext";
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
} from "recharts";
import { useEffect, useRef, useState } from "react";

interface DataPoint {
  time: string;
  packets: number;
}

export default function StatsGraph() {
  const { t } = useTranslation();
  const { status } = useEngine();
  const [data, setData] = useState<DataPoint[]>([]);
  const prevPackets = useRef(0);

  useEffect(() => {
    if (!status) return;
    const current = status.packets_processed;
    const delta = current - prevPackets.current;
    prevPackets.current = current;

    const now = new Date();
    const time = `${now.getHours().toString().padStart(2, "0")}:${now.getMinutes().toString().padStart(2, "0")}:${now.getSeconds().toString().padStart(2, "0")}`;

    setData((prev) => {
      const next = [...prev, { time, packets: delta }];
      return next.slice(-60); // last 60 data points
    });
  }, [status?.packets_processed]);

  return (
    <div
      className="p-3 rounded-lg"
      style={{ background: "var(--bg-elevated)", border: "1px solid var(--border)" }}
    >
      <div className="text-sm font-medium mb-2">{t("stats.title")}</div>
      <ResponsiveContainer width="100%" height={150}>
        <LineChart data={data}>
          <XAxis
            dataKey="time"
            tick={{ fontSize: 10, fill: "var(--text-secondary)" }}
            interval="preserveStartEnd"
          />
          <YAxis
            tick={{ fontSize: 10, fill: "var(--text-secondary)" }}
            width={40}
          />
          <Tooltip
            contentStyle={{
              background: "var(--bg-elevated)",
              border: "1px solid var(--border)",
              borderRadius: "0.5rem",
              fontSize: "12px",
            }}
          />
          <Line
            type="monotone"
            dataKey="packets"
            stroke="var(--accent)"
            strokeWidth={2}
            dot={false}
          />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}
