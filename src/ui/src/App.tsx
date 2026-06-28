import { ThemeProvider } from "./contexts/ThemeContext";
import { EngineProvider } from "./contexts/EngineContext";
import Dashboard from "./components/Dashboard";

export default function App() {
  return (
    <ThemeProvider defaultTheme="system">
      <EngineProvider>
        <Dashboard />
      </EngineProvider>
    </ThemeProvider>
  );
}
