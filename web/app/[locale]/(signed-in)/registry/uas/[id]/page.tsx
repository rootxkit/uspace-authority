import { UASDetail } from "@/src/registry/uas";

export default async function Page({ params }: { params: Promise<{ id: string }> }) {
  const p = await params;
  return <UASDetail id={decodeURIComponent(p.id)} />;
}
