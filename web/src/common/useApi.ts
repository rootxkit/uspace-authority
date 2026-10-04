"use client";

// One read of api through the BFF, as a state a page renders: loading,
// loaded, refused (api's or the BFF's answer, with its problem) or
// failed (nothing answered). A 401 goes to the sign-in page (the
// client's onUnauthorized) and is never shown as a refusal. A refusal is
// shown as one: an empty list is only ever what api answered (E-02).
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { ApiError } from "@rootxkit/uspace-ui/api";
import { useLang } from "@rootxkit/uspace-ui/i18n";
import { consoleClient, type ConsoleClient } from "../api/client";
import { loginPath } from "../shell/paths";

export type Load<T> =
  | { kind: "idle" }
  | { kind: "loading" }
  | { kind: "loaded"; data: T }
  | { kind: "refused"; error: ApiError }
  | { kind: "failed" };

/** The console's client for this page, sending a 401 to the sign-in. */
export function useClient(): ConsoleClient {
  const { lang } = useLang();
  const router = useRouter();
  return useMemo(
    () =>
      consoleClient(
        () => lang,
        () => router.replace(loginPath(lang)),
      ),
    [lang, router],
  );
}

/** The data of a 2xx answer; an answer without a body is a failure of api's contract. */
export function must<T>(r: { data?: T }): T {
  if (r.data === undefined) throw new Error("the answer had no body");
  return r.data;
}

/** A thrown value as a load state (a 401 stays loading: the page is leaving). */
export function stateOf<T>(err: unknown): Load<T> {
  if (err instanceof ApiError) return err.status === 401 ? { kind: "loading" } : { kind: "refused", error: err };
  return { kind: "failed" };
}

/**
 * Runs `load` whenever `key` changes (null: nothing is read, the state is
 * idle) and on `reload()`. An answer that arrives after the key changed
 * is dropped.
 */
export function useLoad<T>(key: string | null, load: (c: ConsoleClient) => Promise<T>): { state: Load<T>; reload(): void } {
  const client = useClient();
  const loadRef = useRef(load);
  useEffect(() => {
    loadRef.current = load;
  });
  const [round, setRound] = useState(0);
  // The answer is kept with the request it answers; a newer request shows loading until its own arrives.
  const [result, setResult] = useState<{ token: string; state: Load<T> } | null>(null);
  const token = key === null ? null : `${round}:${key}`;
  useEffect(() => {
    if (token === null) return;
    let live = true;
    loadRef
      .current(client)
      .then((data) => {
        if (live) setResult({ token, state: { kind: "loaded", data } });
      })
      .catch((err: unknown) => {
        if (live) setResult({ token, state: stateOf<T>(err) });
      });
    return () => {
      live = false;
    };
  }, [token, client]);
  const reload = useCallback(() => setRound((r) => r + 1), []);
  const state: Load<T> = token === null ? { kind: "idle" } : result !== null && result.token === token ? result.state : { kind: "loading" };
  return { state, reload };
}
