#!/usr/bin/env node
// The backstop of no-restricted-imports in CI: no package of
// eslint-rules/restricted.mjs is installed at all, as a direct dependency
// or as a transitive one. It reads every package key of pnpm-lock.yaml
// (lockfile v9, `packages:`), so a forbidden package a dependency pulls
// in fails here even though nothing in web/ imports it. A lockfile with
// no package proves nothing and fails (E-02).
//
//   node scripts/check-lockfile.mjs [pnpm-lock.yaml]
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { RESTRICTED } from "../eslint-rules/restricted.mjs";

// A package key: name@version, quoted when it starts with "@" or holds a
// URL; the name may be scoped.
const KEY = /^ {2}'?((?:@[^/@'\s]+\/)?[^@'\s]+)@/;

/** The names of every package the lockfile installs. */
export function lockfilePackages(text) {
  const names = new Set();
  let inPackages = false;
  for (const line of text.split(/\r?\n/)) {
    if (/^\S/.test(line)) {
      inPackages = /^packages:\s*$/.test(line);
      continue;
    }
    if (!inPackages) continue;
    const m = KEY.exec(line);
    if (m?.[1] !== undefined) names.add(m[1]);
  }
  return names;
}

const PATTERNS = RESTRICTED.flatMap((r) => r.group).map(
  (g) => new RegExp(`^${g.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, "[^/]*")}$`),
);

/** The forbidden packages the lockfile installs, sorted. */
export function forbiddenInLockfile(text) {
  return [...lockfilePackages(text)].filter((n) => PATTERNS.some((p) => p.test(n))).sort();
}

function main(argv) {
  const file = argv[0] ?? "pnpm-lock.yaml";
  const text = readFileSync(file, "utf8");
  const all = lockfilePackages(text);
  if (all.size === 0) {
    console.error(`check-lockfile: no package read from ${file}`);
    return 1;
  }
  const found = forbiddenInLockfile(text);
  if (found.length > 0) {
    for (const n of found) console.error(`check-lockfile: ${n} is installed (${file})`);
    return 1;
  }
  console.log(`check-lockfile: ${all.size} packages in ${file}, none restricted`);
  return 0;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = main(process.argv.slice(2));
}
