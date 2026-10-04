// The difference between two versions of a zone, member by member: every
// leaf of the two features (and their periods of validity) by its JSON
// path, with the value before and after. It compares what api stored as
// text; it does not judge whether a change matters.

export interface Change {
  path: string;
  before: string | null;
  after: string | null;
}

/** The changes to show: at most this many, then the list says it was cut. A display bound. */
export const DIFF_MAX = 500;

function leaves(v: unknown, path: string, out: Map<string, string>): void {
  if (Array.isArray(v)) {
    if (v.length === 0) out.set(path, "[]");
    v.forEach((x, i) => leaves(x, `${path}[${i}]`, out));
    return;
  }
  if (v !== null && typeof v === "object") {
    const entries = Object.entries(v as Record<string, unknown>);
    if (entries.length === 0) out.set(path, "{}");
    for (const [k, x] of entries) leaves(x, path === "" ? k : `${path}.${k}`, out);
    return;
  }
  out.set(path, JSON.stringify(v));
}

/** The changes from `before` to `after`, in path order, at most DIFF_MAX, and whether more were cut. */
export function diff(before: unknown, after: unknown): { changes: Change[]; truncated: boolean } {
  const a = new Map<string, string>();
  const b = new Map<string, string>();
  leaves(before, "", a);
  leaves(after, "", b);
  const paths = [...new Set([...a.keys(), ...b.keys()])].sort();
  const changes: Change[] = [];
  for (const p of paths) {
    const x = a.get(p) ?? null;
    const y = b.get(p) ?? null;
    if (x !== y) changes.push({ path: p, before: x, after: y });
  }
  return { changes: changes.slice(0, DIFF_MAX), truncated: changes.length > DIFF_MAX };
}
