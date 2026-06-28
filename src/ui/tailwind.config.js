/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        border: "var(--border)",
        input: "var(--input)",
        ring: "var(--ring)",
        background: "var(--bg-base)",
        foreground: "var(--text-primary)",
        primary: {
          DEFAULT: "var(--accent)",
          foreground: "var(--text-on-accent)",
        },
        secondary: {
          DEFAULT: "var(--bg-elevated)",
          foreground: "var(--text-primary)",
        },
        muted: {
          DEFAULT: "var(--bg-muted)",
          foreground: "var(--text-secondary)",
        },
        destructive: {
          DEFAULT: "var(--destructive)",
          foreground: "var(--text-on-accent)",
        },
        card: {
          DEFAULT: "var(--bg-elevated)",
          foreground: "var(--text-primary)",
        },
      },
      borderRadius: {
        lg: "var(--radius)",
        md: "calc(var(--radius) - 2px)",
        sm: "calc(var(--radius) - 4px)",
      },
    },
  },
  plugins: [],
};
