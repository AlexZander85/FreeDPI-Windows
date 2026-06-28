import { useTranslation } from "react-i18next";

export default function LanguageSwitcher() {
  const { i18n, t } = useTranslation();
  const current = i18n.language;

  const toggle = () => {
    const next = current === "en" ? "ru" : "en";
    i18n.changeLanguage(next);
    localStorage.setItem("byebyedpi-lang", next);
  };

  return (
    <button
      onClick={toggle}
      className="px-3 py-1.5 text-xs font-medium rounded-md transition-colors"
      style={{
        background: "var(--bg-muted)",
        color: "var(--text-primary)",
        border: "1px solid var(--border)",
      }}
      title={t("language.label")}
    >
      {current === "en" ? "🇷🇺 RU" : "🇬🇧 EN"}
    </button>
  );
}
