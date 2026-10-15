"use client";

// The light/dark toggle of the top bar: a pressed button that says what
// it switches to. The choice is the provider's (its onSchemeChange
// writes the uspace_scheme cookie, src/components/Providers.tsx).
import { useT } from "@rootxkit/uspace-ui/i18n";
import { useTheme } from "@rootxkit/uspace-ui/theme";
import { MoonIcon, SunIcon } from "./icons";

export function SchemeToggle() {
  const t = useT();
  const { resolved, setScheme } = useTheme();
  const dark = resolved === "dark";
  return (
    <button
      type="button"
      aria-pressed={dark}
      aria-label={t("authority.scheme.dark")}
      title={t("authority.scheme.dark")}
      onClick={() => setScheme(dark ? "light" : "dark")}
      className="inline-flex size-8 shrink-0 items-center justify-center rounded-md border border-border bg-card text-foreground transition-colors hover:bg-hover focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
      data-testid="scheme-toggle"
    >
      {dark ? <MoonIcon /> : <SunIcon />}
    </button>
  );
}
