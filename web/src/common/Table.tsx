"use client";

// The kit's shadcn Table in a container that scrolls sideways when the
// table is wider than the page, and can then be reached and scrolled by
// keyboard (WCAG 2.1.1; axe's scrollable-region-focusable). The kit's own
// container is left unclipped so only this one scrolls.
import type { ComponentProps } from "react";
import { Table as KitTable } from "@rootxkit/uspace-ui/ui";

export function Table(props: ComponentProps<typeof KitTable>) {
  return (
    // A region that scrolls must take the keyboard's focus to be scrolled
    // without a pointer (WCAG 2.1.1); the table inside names it by its caption.
    // eslint-disable-next-line jsx-a11y/no-noninteractive-tabindex
    <div tabIndex={0} className="max-w-full overflow-x-auto [&_[data-slot=table-container]]:overflow-visible">
      <KitTable {...props} />
    </div>
  );
}
