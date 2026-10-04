"use client";

// Form fields the kit does not ship, built on its Field (label, hint,
// required mark, error wiring): a multi-line text and a set of values of
// an enumeration (checkboxes), both registered with react-hook-form
// inside the kit's Form.
import { useController, useFormContext } from "react-hook-form";
import { useT } from "@rootxkit/uspace-ui/i18n";
import { Field, useFieldControl, type FieldBaseProps } from "@rootxkit/uspace-ui/form";
import { Textarea } from "@rootxkit/uspace-ui/ui";

function TextareaControl({ name, rows }: { name: string; rows: number }) {
  const { register } = useFormContext();
  const control = useFieldControl();
  return <Textarea {...register(name)} {...control} rows={rows} spellCheck={false} />;
}

/** Several lines of text, stored as typed. */
export function TextareaField(props: FieldBaseProps & { rows?: number }) {
  const { rows = 4, ...field } = props;
  return (
    <Field {...field}>
      <TextareaControl name={field.name} rows={rows} />
    </Field>
  );
}

function SetControl({ name, values, i18nPrefix }: { name: string; values: readonly string[]; i18nPrefix: string }) {
  const t = useT();
  const control = useFieldControl();
  const { field } = useController({ name });
  const chosen: string[] = Array.isArray(field.value) ? (field.value as string[]) : [];
  return (
    <div role="group" aria-describedby={control["aria-describedby"]} className="flex flex-wrap gap-x-4 gap-y-1" id={control.id} data-testid={`set-${name}`}>
      {values.map((v) => (
        <label key={v} className="flex items-center gap-1 text-sm">
          <input
            type="checkbox"
            checked={chosen.includes(v)}
            disabled={control.disabled}
            onChange={(e) => field.onChange(e.target.checked ? values.filter((x) => x === v || chosen.includes(x)) : chosen.filter((x) => x !== v))}
            onBlur={field.onBlur}
            value={v}
          />
          <span>{t(`${i18nPrefix}.${v}`)}</span>
        </label>
      ))}
    </div>
  );
}

/** A set of values of an enumeration, in the enumeration's order; each labelled `<i18nPrefix>.<value>`. */
export function SetField(props: FieldBaseProps & { values: readonly string[]; i18nPrefix: string }) {
  const { values, i18nPrefix, ...field } = props;
  return (
    <Field {...field}>
      <SetControl name={field.name} values={values} i18nPrefix={i18nPrefix} />
    </Field>
  );
}

/** The value without its empty members ("", null, undefined, an empty list), recursively; what api is sent. */
export function compact<T>(v: T): T {
  if (Array.isArray(v)) return v.map(compact).filter((x) => !isEmpty(x)) as T;
  if (v !== null && typeof v === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, x] of Object.entries(v as Record<string, unknown>)) {
      const c = compact(x);
      if (!isEmpty(c)) out[k] = c;
    }
    return out as T;
  }
  return typeof v === "string" ? (v.trim() as T) : v;
}

function isEmpty(x: unknown): boolean {
  if (x === null || x === undefined) return true;
  if (typeof x === "string") return x.trim() === "";
  if (Array.isArray(x)) return x.length === 0;
  if (typeof x === "object") return Object.keys(x).length === 0;
  return false;
}
