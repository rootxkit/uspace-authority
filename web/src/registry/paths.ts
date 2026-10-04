import { mapPath } from "../shell/paths";

/** The registry's paths under /<lang>. */
export function registryPath(lang: string, rest: string): string {
  return `${mapPath(lang)}/registry/${rest}`;
}
