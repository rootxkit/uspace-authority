"use client";

// The authoring pages' reach to api (WP-22): the console client of
// src/api/client.ts for this page's language, which sends a 401 to the
// sign-in page, and a loader that keeps what api answered (the data, its
// refusal with the problem, or a failure to reach it) so that a refused
// or failed read is said and never shown as an empty list (E-02).
import { useCallback, useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import { ApiError } from "@rootxkit/uspace-ui/api";
import { useLang } from "@rootxkit/uspace-ui/i18n";
import { consoleClient, type ConsoleClient } from "../api/client";
import { loginPath } from "../shell/paths";

/** The console's client for this page. */
export function useConsole(): ConsoleClient {
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

export type Load<T> =
  | { kind: "loading" }
  | { kind: "loaded"; data: T }
  /** api answered with a refusal: its status and problem. */
  | { kind: "refused"; error: ApiError }
  /** api was not reached, or answered something unreadable. */
  | { kind: "failed" };

/** What a failed call was: api's refusal, or a failure to reach it. */
export function outcomeOf(err: unknown): { kind: "refused"; error: ApiError } | { kind: "failed" } {
  return err instanceof ApiError ? { kind: "refused", error: err } : { kind: "failed" };
}

/**
 * Runs `read` with the console's client when `key` changes or `reload`
 * is called, and keeps its outcome. `read` resolves with the data or
 * rejects; a call superseded by a newer one is dropped.
 */
export function useLoad<T>(key: string, read: (c: ConsoleClient) => Promise<T>): { state: Load<T>; reload(): void } {
  const client = useConsole();
  const [result, setResult] = useState<{ key: string; round: number; load: Load<T> } | null>(null);
  const [round, setRound] = useState(0);
  const reload = useCallback(() => setRound((r) => r + 1), []);
  useEffect(() => {
    let live = true;
    read(client)
      .then((data) => {
        if (live) setResult({ key, round, load: { kind: "loaded", data } });
      })
      .catch((err: unknown) => {
        if (live) setResult({ key, round, load: outcomeOf(err) });
      });
    return () => {
      live = false;
    };
    // `read` is the caller's closure over `key`; `key` names what it reads.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [client, key, round]);
  // Another key is loading until it answers; a reload of the same key keeps what it showed.
  const state: Load<T> = result === null || result.key !== key ? { kind: "loading" } : result.load;
  return { state, reload };
}

/** `data` of an openapi-fetch answer, or a rejection when there is none (a 2xx without a body). */
export function must<T>(r: { data?: T }): T {
  if (r.data === undefined) throw new Error("api answered without a body");
  return r.data;
}
