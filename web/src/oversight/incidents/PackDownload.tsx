"use client";

// Downloading a sealed archive: api re-reads it, checks its hash before a
// byte is served and records the download with the purpose; a mismatch
// is api's 409 evidence_tampered, shown as such. The page shows the hash
// api sent with the archive beside the one recorded at the build; it
// compares nothing itself.
import { useState } from "react";
import { ApiError } from "@rootxkit/uspace-ui/api";
import { useT } from "@rootxkit/uspace-ui/i18n";
import { Button } from "@rootxkit/uspace-ui/ui";
import type { ConsoleClient } from "../../api/client";
import { ProblemText } from "../../common/Problem";
import { TextInput, saveBlob } from "../../common/ui";
import { useClient } from "../../common/useApi";

export type Download = (client: ConsoleClient) => Promise<{ data?: unknown; response: Response }>;

/** The archive's download with what api said of it. */
export function DownloadButton({ download, fileName, disabled, testId }: { download: Download; fileName: string; disabled?: boolean; testId?: string }) {
  const t = useT();
  const client = useClient();
  const [error, setError] = useState<ApiError | null>(null);
  const [served, setServed] = useState<{ hash: string; signature: string } | null>(null);
  const [busy, setBusy] = useState(false);
  return (
    <div className="flex flex-col gap-1">
      <div>
        <Button
          type="button"
          size="sm"
          disabled={disabled === true || busy}
          data-testid={testId ?? "download"}
          onClick={() => {
            setBusy(true);
            setError(null);
            setServed(null);
            download(client)
              .then(({ data, response }) => {
                if (!(data instanceof Blob)) throw new Error("not an archive");
                saveBlob(data, fileName);
                setServed({ hash: response.headers.get("X-Content-SHA256") ?? "", signature: response.headers.get("X-Evidence-Signature") ?? "" });
              })
              .catch((err: unknown) => {
                if (err instanceof ApiError) setError(err);
              })
              .finally(() => setBusy(false));
          }}
        >
          {t("authority.pack.download")}
        </Button>
      </div>
      {served !== null && (
        <p role="status" className="m-0 text-xs" data-testid="download-served">
          {t("authority.pack.served", { hash: served.hash === "" ? "—" : served.hash })}{" "}
          {t(served.signature === "" ? "authority.pack.served_unsigned" : "authority.pack.served_signed")}
        </p>
      )}
      {error !== null && <ProblemText error={error} />}
    </div>
  );
}

/** An incident's pack: the purpose is asked for each download (api records it). */
export function PackDownload(props: {
  recordedHash: string;
  fileName: string;
  download(client: ConsoleClient, purpose: string): Promise<{ data?: unknown; response: Response }>;
}) {
  const t = useT();
  const [purpose, setPurpose] = useState("");
  return (
    <div className="mt-2 flex flex-wrap items-end gap-3" data-testid="pack-download">
      <TextInput name="download_purpose" required maxLength={200} labelKey="authority.pack.download_purpose" value={purpose} onChange={setPurpose} testId="download-purpose" />
      <DownloadButton fileName={props.fileName} disabled={purpose.trim() === ""} download={(c) => props.download(c, purpose.trim())} />
      <p className="m-0 w-full text-xs text-[var(--us-text-muted)]">{t("authority.pack.recorded_hash", { hash: props.recordedHash })}</p>
    </div>
  );
}
