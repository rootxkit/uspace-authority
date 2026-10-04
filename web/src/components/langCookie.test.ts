// The language choice cookie: readable by the page (it is a preference,
// not a credential), sent over HTTPS only, on every path, for a year.
import { LANG_COOKIE } from "@rootxkit/uspace-ui/i18n";
import { describe, expect, it } from "vitest";
import { langCookie } from "./langCookie";

describe("langCookie", () => {
  it("is Secure, SameSite=Lax, Path=/ and a year long, for each language", () => {
    for (const lang of ["ka", "en"] as const) {
      const attrs = langCookie(lang).split("; ");
      expect(attrs[0]).toBe(`${LANG_COOKIE}=${lang}`);
      expect(attrs.slice(1).sort()).toEqual(["Max-Age=31536000", "Path=/", "SameSite=Lax", "Secure"]);
    }
  });
});
