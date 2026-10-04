import { CertificateDetail } from "@/src/certificates/pages";

export default async function Page({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return <CertificateDetail id={decodeURIComponent(id)} />;
}
