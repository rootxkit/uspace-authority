// A bounded map keyed by an external id (a track id, a violation id),
// for what the console keeps beside the kit's stores: a track's extras,
// a violation's members. Past `max` the least recently set entry is
// evicted and counted (E-10); nothing is kept without a bound.
export interface KeyedStore<V> {
  set(id: string, v: V): void;
  get(id: string): V | undefined;
  /** Keeps exactly the ids in `keep` (a snapshot replaced the store). */
  retain(keep: ReadonlySet<string>): void;
  /** A stable map between changes, for `useSyncExternalStore`. */
  snapshot(): ReadonlyMap<string, V>;
  subscribe(fn: () => void): () => void;
  /** Entries evicted at the bound since the store was made. */
  evicted(): number;
}

export function createKeyedStore<V>(max: number): KeyedStore<V> {
  if (!(Number.isInteger(max) && max >= 1)) throw new RangeError("createKeyedStore: max must be a whole number of at least 1");
  let map = new Map<string, V>();
  let evicted = 0;
  const listeners = new Set<() => void>();
  const emit = () => {
    for (const fn of listeners) fn();
  };
  return {
    set(id, v) {
      const next = new Map(map);
      // Re-inserted at the end: the order is the order of the last set.
      next.delete(id);
      next.set(id, v);
      while (next.size > max) {
        const oldest = next.keys().next().value;
        if (oldest === undefined) break;
        next.delete(oldest);
        evicted++;
      }
      map = next;
      emit();
    },
    get: (id) => map.get(id),
    retain(keep) {
      let changed = false;
      const next = new Map<string, V>();
      for (const [k, v] of map) {
        if (keep.has(k)) next.set(k, v);
        else changed = true;
      }
      if (!changed) return;
      map = next;
      emit();
    },
    snapshot: () => map,
    subscribe(fn) {
      listeners.add(fn);
      return () => {
        listeners.delete(fn);
      };
    },
    evicted: () => evicted,
  };
}
