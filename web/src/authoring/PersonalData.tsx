"use client";

// Personal data behind a stated purpose (CLAUDE.md rule 6; spec 06 §5
// purpose limitation). Nothing is read until the person chooses one of
// the configured purposes (WEB_PII_PURPOSES); the purpose is sent as the
// request's `purpose`, api records the view with it before it answers,
// and what it answers is shown here and kept nowhere else: closing the
// panel drops it. The panel is offered only to the roles the operation
// admits; api refuses the others whatever this shows.
import { useId, useState } from "react";
import { useLang, useT } from "@rootxkit/uspace-ui/i18n";
import { Button, Label } from "@rootxkit/uspace-ui/ui";
import { useRuntimeConfig } from "../components/Providers";
import { catalogues } from "../i18n/catalogues";
import type { Role } from "../shell/nav";
import { outcomeOf, type Load } from "./api";
import { Can, Facts, ProblemNotice } from "./ui";

/** The label of a purpose code: the catalogue's words, else the code as configured. */
export function purposeLabelKey(code: string): string {
  return `authority.purpose.${code}`;
}

export interface PersonalDataProps<T> {
  /** The operation's x-roles. */
  roles: readonly Role[];
  /** Reads the data for `purpose`; api answers or refuses. */
  read(purpose: string): Promise<T>;
  /** The rows to show: a label key and the value. */
  rows(data: T): readonly (readonly [string, string | null | undefined])[];
  testId: string;
}

export function PersonalData<T>(props: PersonalDataProps<T>) {
  return (
    <Can roles={props.roles}>
      <PersonalDataPanel {...props} />
    </Can>
  );
}

function PersonalDataPanel<T>({ read, rows, testId }: PersonalDataProps<T>) {
  const t = useT();
  const { lang } = useLang();
  const cfg = useRuntimeConfig();
  const id = useId();
  const [purpose, setPurpose] = useState("");
  const [state, setState] = useState<Load<T> | null>(null);
  // A configured code the catalogue has no words for is shown as configured.
  const label = (code: string) => (purposeLabelKey(code) in (catalogues[lang] ?? {}) ? t(purposeLabelKey(code)) : code);
  return (
    <section className="flex flex-col gap-2 rounded border border-[var(--us-border)] p-3" aria-label={t("authority.pii.title")} data-testid={testId}>
      <h2 className="m-0 text-base font-semibold">{t("authority.pii.title")}</h2>
      <p className="m-0 text-xs text-[var(--us-text-muted)]">{t("authority.pii.intro")}</p>
      {cfg.piiPurposesProblem !== null && (
        <p className="m-0 text-xs" data-testid={`${testId}-purposes-default`}>
          {t("authority.pii.purposes_default", { problem: cfg.piiPurposesProblem })}
        </p>
      )}
      <form
        className="flex flex-wrap items-end gap-2"
        onSubmit={(e) => {
          e.preventDefault();
          // Validated before anything is sent: no purpose, no request.
          if (purpose === "") return;
          setState({ kind: "loading" });
          read(purpose)
            .then((data) => setState({ kind: "loaded", data }))
            .catch((err: unknown) => setState(outcomeOf(err)));
        }}
      >
        <div className="flex flex-col gap-1">
          <Label htmlFor={`${id}-purpose`}>{t("authority.pii.purpose")}</Label>
          <select
            id={`${id}-purpose`}
            className="rounded border border-[var(--us-border)] bg-[var(--us-surface)] px-2 py-1 text-sm"
            value={purpose}
            required
            onChange={(e) => {
              setPurpose(e.target.value);
              setState(null);
            }}
            data-testid={`${testId}-purpose`}
          >
            <option value="">{t("authority.pii.choose_purpose")}</option>
            {cfg.piiPurposes.map((p) => (
              <option key={p} value={p}>
                {label(p)}
              </option>
            ))}
          </select>
        </div>
        <Button type="submit" size="sm" disabled={purpose === "" || state?.kind === "loading"} data-testid={`${testId}-show`}>
          {t("authority.pii.show")}
        </Button>
        {state?.kind === "loaded" && (
          <Button type="button" size="sm" variant="outline" onClick={() => setState(null)} data-testid={`${testId}-hide`}>
            {t("authority.pii.hide")}
          </Button>
        )}
      </form>
      {state?.kind === "loaded" && (
        <div data-testid={`${testId}-data`}>
          <p className="m-0 mb-1 text-xs">{t("authority.pii.recorded", { purpose: label(purpose) })}</p>
          <Facts items={rows(state.data)} />
        </div>
      )}
      {state?.kind === "refused" && <ProblemNotice error={state.error} testId={`${testId}-problem`} />}
      {state?.kind === "failed" && <ProblemNotice error="failed" testId={`${testId}-problem`} />}
    </section>
  );
}
