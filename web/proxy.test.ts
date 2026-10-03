// The proxy's matcher: the paths it leaves alone are exactly the ones it
// names. A "." in the string must reach the pattern escaped, or it
// matches any character and the proxy skips page paths it should handle.
import { describe, expect, it } from "vitest";
import { config } from "./proxy";

const matcher = new RegExp(`^${config.matcher[0] ?? ""}$`);

describe("proxy matcher", () => {
  it("leaves Next's assets, the BFF, api and picture-ws paths, the basemap and the static files alone", () => {
    for (const p of ["/_next/static/a.js", "/_bff/login", "/v1/zones", "/oauth/token", "/basemap/style.json", "/.well-known/jwks.json", "/healthz", "/favicon.ico"]) {
      expect(matcher.test(p), p).toBe(false);
    }
  });

  it("handles a page path that only resembles one of them (the pair above)", () => {
    for (const p of ["/xwell-known/a", "/en/xwell-known", "/favicon-ico", "/faviconxico", "/en", "/"]) {
      expect(matcher.test(p), p).toBe(true);
    }
  });
});
