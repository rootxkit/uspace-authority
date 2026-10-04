import { redirect } from "next/navigation";
import { registryPath } from "@/src/registry/paths";

// The registry opens on its operators.
export default async function Registry({ params }: { params: Promise<{ locale: string }> }) {
  const { locale } = await params;
  redirect(registryPath(locale, "operators"));
}
