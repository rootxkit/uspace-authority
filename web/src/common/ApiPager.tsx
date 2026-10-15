"use client";

// The pages api returned beyond the first: the earlier page while there
// is one before this one, the next while api sent a cursor. When api has
// nothing more either way the pager is not drawn at all, rather than
// drawn disabled under a table that already shows every row.
import { useT } from "@rootxkit/uspace-ui/i18n";
import { Button } from "@rootxkit/uspace-ui/ui";

export function ApiPager(props: {
  hasPrevious: boolean;
  hasNext: boolean;
  onPrevious(): void;
  onNext(): void;
  /** The test id of the pager's next button, `<testId>-next` (and `-previous`). */
  testId?: string;
  /** The catalogue keys of the two buttons; "results from the API" by default. */
  previousKey?: string;
  nextKey?: string;
  size?: "sm" | "default";
}) {
  const t = useT();
  const { hasPrevious, hasNext, testId, previousKey = "authority.act.api_previous", nextKey = "authority.act.api_next", size = "sm" } = props;
  if (!hasPrevious && !hasNext) return null;
  return (
    <div className="flex gap-2" data-testid="api-pager">
      {hasPrevious && (
        <Button type="button" size={size} variant="outline" onClick={props.onPrevious} data-testid={testId === undefined ? "api-previous" : `${testId}-previous`}>
          {t(previousKey)}
        </Button>
      )}
      {hasNext && (
        <Button type="button" size={size} variant="outline" onClick={props.onNext} data-testid={testId === undefined ? "api-next" : `${testId}-next`}>
          {t(nextKey)}
        </Button>
      )}
    </div>
  );
}
