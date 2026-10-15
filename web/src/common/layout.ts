// The list pages' layout: the list (and its map) first, the side panels
// beside it only from 90rem (1440 px), where the list keeps about 800 px; below
// that the panels follow the list, two to a row, so the list has the
// page's whole width at 1024 px. Display-only class lists.
export const SIDE_LAYOUT = "grid gap-3 px-4 py-3 min-[90rem]:grid-cols-[minmax(0,1fr)_22rem]";
export const SIDE_PANELS = "grid content-start gap-3 md:grid-cols-2 min-[90rem]:grid-cols-1";
