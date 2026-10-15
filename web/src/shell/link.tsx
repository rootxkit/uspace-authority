"use client";

import Link from "next/link";
import type { LinkRenderer } from "@rootxkit/uspace-ui/ui";

/** next/link for the kit's frame components, so navigation stays client-side. */
export const renderLink: LinkRenderer = (p) => <Link {...p} />;
