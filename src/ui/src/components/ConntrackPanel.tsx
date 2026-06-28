import { useTranslation } from "react-i18next";
import { useEffect, useState } from "react";
import { getConntrack } from "@/lib/api";

interface Connection {
  src: string;
  dst: string;
  sport: number;
  dport: number;
  state: string;
}

export default function ConntrackPanel() {
  const { t } = useTranslation();
  const [connections, setConnections] = useState<Connection[]>([]);

  useEffect(() => {
    const fetchConnections = async () => {
      try {
        const port = parseInt(localStorage.getItem("byebyedpi-api-port") || "11337", 10);
        const data = await getConntrack(port);
        setConnections((data as { entries?: Connection[] }).entries || []);
      } catch {
        setConnections([]);
      }
    };

    fetchConnections();
    const interval = setInterval(fetchConnections, 2000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="space-y-4">
      <h2 className="text-lg font-semibold">
        {t("connections.title")} ({t("connections.total", { count: connections.length })})
      </h2>

      {connections.length === 0 ? (
        <div className="text-sm py-8 text-center" style={{ color: "var(--text-secondary)" }}>
          {t("connections.no_connections")}
        </div>
      ) : (
        <div
          className="rounded-lg overflow-hidden"
          style={{ border: "1px solid var(--border)" }}
        >
          <table className="w-full text-sm">
            <thead>
              <tr style={{ background: "var(--bg-muted)" }}>
                <th className="px-3 py-2 text-left">{t("connections.source")}</th>
                <th className="px-3 py-2 text-left">{t("connections.destination")}</th>
                <th className="px-3 py-2 text-left">{t("connections.state")}</th>
              </tr>
            </thead>
            <tbody>
              {connections.map((c, i) => (
                <tr
                  key={i}
                  className="border-t"
                  style={{ borderColor: "var(--border)" }}
                >
                  <td className="px-3 py-1.5 font-mono text-xs">
                    {c.src}:{c.sport}
                  </td>
                  <td className="px-3 py-1.5 font-mono text-xs">
                    {c.dst}:{c.dport}
                  </td>
                  <td className="px-3 py-1.5">
                    <span
                      className="text-xs px-2 py-0.5 rounded-full"
                      style={{
                        background: c.state === "Established" ? "var(--accent)" : "var(--bg-muted)",
                        color: c.state === "Established" ? "var(--text-on-accent, #fff)" : "var(--text-secondary)",
                      }}
                    >
                      {c.state}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
