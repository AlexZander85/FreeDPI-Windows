import { createContext, useContext, useEffect, useState, useRef } from "react";
import { getStatus, getHealth } from "@/lib/api";

interface EngineStatus {
  status: string;
  version: string;
  uptime_seconds: number;
  packets_processed: number;
  active_connections: number;
  windivert_ok: boolean;
  raw_socket_ok: boolean;
}

interface EngineContextType {
  status: EngineStatus | null;
  isOnline: boolean;
  refresh: () => void;
}

const EngineContext = createContext<EngineContextType>({
  status: null,
  isOnline: false,
  refresh: () => {},
});

export function EngineProvider({ children }: { children: React.ReactNode }) {
  const [status, setStatus] = useState<EngineStatus | null>(null);
  const [isOnline, setIsOnline] = useState(false);
  const intervalRef = useRef<number | null>(null);

  const fetchStatus = async () => {
    try {
      const port = parseInt(localStorage.getItem("byebyedpi-api-port") || "11337", 10);
      const [statusData, healthData] = await Promise.all([
        getStatus(port).catch(() => null),
        getHealth(port).catch(() => null),
      ]);
      if (statusData) {
        setStatus({
          ...statusData,
          windivert_ok: healthData?.windivert_ok ?? false,
          raw_socket_ok: healthData?.raw_socket_ok ?? false,
        });
        setIsOnline(true);
      } else {
        setIsOnline(false);
      }
    } catch {
      setIsOnline(false);
    }
  };

  useEffect(() => {
    fetchStatus();
    intervalRef.current = window.setInterval(fetchStatus, 2000);
    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current);
    };
  }, []);

  return (
    <EngineContext.Provider value={{ status, isOnline, refresh: fetchStatus }}>
      {children}
    </EngineContext.Provider>
  );
}

export const useEngine = () => useContext(EngineContext);
