"use client";

// A zone's ED-318 type as the map's legend draws it: the kit's swatch
// (colour and pattern, so the type reads without colour) and the kit's
// name of the type, on one line. A type the kit does not know is shown
// as api sent it, never dropped.
import { useT } from "@rootxkit/uspace-ui/i18n";
import { ZoneSwatch } from "@rootxkit/uspace-ui/legend";
import { isZoneType } from "@rootxkit/uspace-ui/model";
import { ZONE_TYPE_KEYS, zoneToken } from "@rootxkit/uspace-ui/symbology";

export function ZoneTypeBadge({ type }: { type: string }) {
  const t = useT();
  if (!isZoneType(type)) {
    return (
      <span className="font-mono text-xs whitespace-nowrap" data-testid="zone-type" data-type={type}>
        {type}
      </span>
    );
  }
  return (
    <span
      className="inline-flex items-center gap-1.5 rounded-full border py-0.5 ps-1 pe-2 text-xs font-semibold whitespace-nowrap"
      style={{ borderColor: `var(${zoneToken(type)})` }}
      data-testid="zone-type"
      data-type={type}
    >
      <span className="inline-flex h-3 w-5 shrink-0 overflow-hidden rounded-sm [&>svg]:h-3 [&>svg]:w-5">
        <ZoneSwatch type={type} />
      </span>
      {t(ZONE_TYPE_KEYS[type])}
    </span>
  );
}
