import { PilotDetail } from "@/src/registry/pilots";

export default async function Page({ params }: { params: Promise<{ id: string }> }) {
  const p = await params;
  return <PilotDetail id={decodeURIComponent(p.id)} />;
}
