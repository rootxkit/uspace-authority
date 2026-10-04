"use client";

// Small display pieces shared by WP-23's pages, on the kit's shadcn set:
// a list of facts, a page header, a labelled native choice and a labelled
// input. Every label is a catalogue key; values are what api sent.
import { useId, type ReactNode } from "react";
import { useT } from "@rootxkit/uspace-ui/i18n";
import { Input, Label, Textarea } from "@rootxkit/uspace-ui/ui";

export interface Fact {
  /** The catalogue key of the term. */
  labelKey: string;
  value: ReactNode;
  testId?: string;
}

/** Term and value pairs, in a description list. */
export function Facts({ items, testId }: { items: readonly Fact[]; testId?: string }) {
  const t = useT();
  return (
    <dl className="m-0 grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1 text-sm" data-testid={testId}>
      {items.map((f) => (
        <div key={f.labelKey} className="contents">
          <dt className="font-semibold text-[var(--us-text-muted)]">{t(f.labelKey)}</dt>
          <dd className="m-0 break-words" data-testid={f.testId}>
            {f.value}
          </dd>
        </div>
      ))}
    </dl>
  );
}

/** A page's title and its one-line explanation. */
export function PageHeader({ titleKey, introKey, vars, children }: { titleKey: string; introKey?: string; vars?: Record<string, string | number>; children?: ReactNode }) {
  const t = useT();
  return (
    <header className="flex flex-col gap-1">
      <h1 className="m-0 text-xl font-bold">{t(titleKey, vars)}</h1>
      {introKey !== undefined && <p className="m-0 text-sm text-[var(--us-text-muted)]">{t(introKey, vars)}</p>}
      {children}
    </header>
  );
}

/** A titled part of a page. */
export function Part({ titleKey, children, testId, vars }: { titleKey: string; children: ReactNode; testId?: string; vars?: Record<string, string | number> }) {
  const t = useT();
  const id = useId();
  return (
    <section aria-labelledby={id} className="flex flex-col gap-2 rounded-md border border-[var(--us-border)] bg-[var(--us-surface-raised)] p-3" data-testid={testId}>
      <h2 id={id} className="m-0 text-base font-semibold">
        {t(titleKey, vars)}
      </h2>
      {children}
    </section>
  );
}

export interface ChoiceOption {
  value: string;
  /** The catalogue key of the option, or the value itself shown as sent. */
  labelKey?: string;
}

/** A native choice with its label; "" is "any" when `anyKey` is given. */
export function Choice(props: {
  labelKey: string;
  value: string;
  onChange(v: string): void;
  options: readonly ChoiceOption[];
  anyKey?: string;
  name: string;
  required?: boolean;
  testId?: string;
}) {
  const t = useT();
  const id = useId();
  return (
    <div className="flex flex-col gap-1">
      <Label htmlFor={id}>{t(props.labelKey)}</Label>
      <select
        id={id}
        name={props.name}
        value={props.value}
        required={props.required}
        onChange={(e) => props.onChange(e.target.value)}
        className="h-9 rounded-md border border-[var(--us-border-strong)] bg-[var(--us-surface-raised)] px-2 text-sm text-[var(--us-text)]"
        data-testid={props.testId}
      >
        {props.anyKey !== undefined && <option value="">{t(props.anyKey)}</option>}
        {props.options.map((o) => (
          <option key={o.value} value={o.value}>
            {o.labelKey === undefined ? o.value : t(o.labelKey)}
          </option>
        ))}
      </select>
    </div>
  );
}

/** A text input with its label (and an optional hint). */
export function TextInput(props: {
  labelKey: string;
  value: string;
  onChange(v: string): void;
  name: string;
  hintKey?: string;
  required?: boolean;
  maxLength?: number;
  type?: "text" | "datetime-local" | "month" | "number" | "search";
  testId?: string;
  multiline?: boolean;
}) {
  const t = useT();
  const id = useId();
  const hint = useId();
  const common = {
    id,
    name: props.name,
    value: props.value,
    required: props.required,
    maxLength: props.maxLength,
    "aria-describedby": props.hintKey === undefined ? undefined : hint,
    "data-testid": props.testId,
  };
  return (
    <div className="flex flex-col gap-1">
      <Label htmlFor={id}>
        {t(props.labelKey)}
        {props.required === true && <span aria-hidden="true"> *</span>}
      </Label>
      {props.multiline === true ? (
        <Textarea {...common} onChange={(e) => props.onChange(e.target.value)} rows={4} />
      ) : (
        <Input {...common} type={props.type ?? "text"} onChange={(e) => props.onChange(e.target.value)} />
      )}
      {props.hintKey !== undefined && (
        <p id={hint} className="m-0 text-xs text-[var(--us-text-muted)]">
          {t(props.hintKey)}
        </p>
      )}
    </div>
  );
}

/** Saves `blob` as a file named `name` through a temporary object URL. */
export function saveBlob(blob: Blob, name: string): void {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}
