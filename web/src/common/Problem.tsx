"use client";

// A refusal or a failure in words: the status, api's title and detail as
// sent, the field errors by path, and a Retry-After as the server said
// it. A 409 is final (the state it refused will not change by retrying)
// and says so; nothing here retries anything.
import { ApiError } from "@rootxkit/uspace-ui/api";
import { useT } from "@rootxkit/uspace-ui/i18n";
import type { Load } from "./useApi";

export function ProblemText({ error }: { error: ApiError }) {
  const t = useT();
  const p = error.problem;
  const fields = p?.errors ?? [];
  return (
    <div role="alert" className="flex flex-col gap-1 text-sm" data-testid="problem" data-status={error.status} data-slug={error.slug ?? ""}>
      <p className="m-0 font-semibold text-[var(--us-danger)]">
        {t("authority.problem.refused", { status: error.status, title: p?.title ?? "" })}
      </p>
      {p !== null && p.detail !== null && p.detail !== "" && <p className="m-0">{p.detail}</p>}
      {fields.length > 0 && (
        <ul className="m-0 ps-5">
          {fields.map((f) => (
            <li key={`${f.field}:${f.reason}`}>{t("authority.problem.field", { field: f.field, reason: f.reason })}</li>
          ))}
        </ul>
      )}
      {error.status === 403 && <p className="m-0 text-[var(--us-text-muted)]">{t("authority.problem.forbidden_hint")}</p>}
      {error.status === 409 && <p className="m-0 text-[var(--us-text-muted)]">{t("authority.problem.conflict_hint")}</p>}
      {error.retryAfterS !== null && <p className="m-0">{t("authority.problem.retry_after", { seconds: error.retryAfterS })}</p>}
    </div>
  );
}

/** What a load state that is not "loaded" says; null for loaded and idle. */
export function LoadNotice<T>({ state }: { state: Load<T> }) {
  const t = useT();
  if (state.kind === "loading") {
    return (
      <p role="status" className="m-0 text-sm text-[var(--us-text-muted)]" data-testid="loading">
        {t("authority.common.loading")}
      </p>
    );
  }
  if (state.kind === "refused") return <ProblemText error={state.error} />;
  if (state.kind === "failed") {
    return (
      <p role="alert" className="m-0 text-sm text-[var(--us-danger)]" data-testid="failed">
        {t("authority.common.failed")}
      </p>
    );
  }
  return null;
}
