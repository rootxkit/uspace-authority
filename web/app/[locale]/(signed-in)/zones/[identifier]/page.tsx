import { AirspaceDetail } from "@/src/zones/pages";

export default async function Page({ params }: { params: Promise<{ identifier: string }> }) {
  const { identifier } = await params;
  return <AirspaceDetail dataset="zones" identifier={decodeURIComponent(identifier)} />;
}
