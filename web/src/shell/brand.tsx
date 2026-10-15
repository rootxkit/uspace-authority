"use client";

import { useTheme } from "@rootxkit/uspace-ui/theme";
import { Mark } from "./icons";

/** The brand's logo when the deployment configures one (WEB_BRAND_LOGO_URL), else the neutral mark. */
export function BrandMark() {
  const { brand } = useTheme();
  return brand.logoUrl !== null ? <img src={brand.logoUrl} alt="" className="size-7 object-contain" /> : <Mark />;
}
