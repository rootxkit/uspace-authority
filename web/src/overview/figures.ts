// The overview's figures from what api and picture-ws answered: counted,
// never judged. A queue read is one page, so its count says whether api
// had more; the sources are counted by the state picture-ws gave each.
import type { SourceState } from "@rootxkit/uspace-ui/model";

export interface QueueCount {
  count: number;
  /** api has more pages: the count is a lower bound. */
  more: boolean;
}

/** The figure of one page of a queue. */
export function queueCount(rows: readonly unknown[], nextCursor: string | undefined): QueueCount {
  return { count: rows.length, more: nextCursor !== undefined };
}

/** Sources by what picture-ws says of them: how many report healthy, how many say something else. */
export function sourceSummary(sources: readonly { state: SourceState }[]): { total: number; healthy: number; disabled: number; attention: number } {
  let healthy = 0;
  let disabled = 0;
  for (const s of sources) {
    if (s.state === "healthy") healthy += 1;
    else if (s.state === "disabled") disabled += 1;
  }
  return { total: sources.length, healthy, disabled, attention: sources.length - healthy - disabled };
}
