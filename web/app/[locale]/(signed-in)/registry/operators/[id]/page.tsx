import { OperatorDetail } from "@/src/registry/operators";

export default async function Page({ params }: { params: Promise<{ id: string }> }) {
  const p = await params;
  return <OperatorDetail id={decodeURIComponent(p.id)} />;
}
