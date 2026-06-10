import i18n from "i18next";
import { initReactI18next } from "react-i18next";
import en from "./en.json";
import ru from "./ru.json";

const saved = localStorage.getItem("leshiy.lang") ?? "en";
i18n.use(initReactI18next).init({
  resources: { en: { translation: en }, ru: { translation: ru } },
  lng: saved, fallbackLng: "en", interpolation: { escapeValue: false },
});
export function setLanguage(lng: string) { localStorage.setItem("leshiy.lang", lng); void i18n.changeLanguage(lng); }
export default i18n;
