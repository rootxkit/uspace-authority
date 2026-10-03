// The twin of literals.tsx that differs in one thing: the words from the catalogue.
declare function t(key: string): string;

export function Hello() {
  return <p aria-label={t("authority.tracks.title")}>{t("authority.tracks.title")} · <img alt="" /></p>;
}
