// The session the shell shows: the uspace_session cookie's claims decoded
// without verification (the kit's sessionDisplay, M20), for display only.
// A token already past its exp is shown as signed out; api and
// picture-ws decide every request whatever this says.
import { readSessionToken, sessionDisplay, type CookieReader } from "@rootxkit/uspace-ui/auth/server";
import type { SessionDisplay } from "@rootxkit/uspace-ui/model";

export function displaySession(cookies: CookieReader, nowMs: number = Date.now()): SessionDisplay | null {
  const s = sessionDisplay(readSessionToken(cookies));
  if (s === null || s.exp * 1000 <= nowMs) return null;
  return s;
}
