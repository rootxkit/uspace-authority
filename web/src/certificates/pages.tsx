"use client";

// USSP and CISP certificates (WP-16; docs/runbooks/certificates.md),
// admin only: the list, issuing (the client's secret shown once), the
// four facts the status is derived from, suspension, limitation,
// revocation and reinstatement with their reasons, the operating-status
// timeline with a notice received by letter, the public register as the
// public sees it, and the USSP list's publication.
import { useMemo, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { z } from "zod";
import { fmtTimeUTC, useLang, useT } from "@rootxkit/uspace-ui/i18n";
import { EnumField, Form, SelectField, TextField, UTCDateTimeField, shapes } from "@rootxkit/uspace-ui/form";
import { DataTable, columnsFor, tableColumn } from "@rootxkit/uspace-ui/table";
import { Badge, Button, EmptyState, Input, Label } from "@rootxkit/uspace-ui/ui";
import type { components } from "../api/types";
import { must, useConsole, useLoad } from "../authoring/api";
import { SetField, TextareaField, compact } from "../authoring/fields";
import { Act, Can, Facts, Loaded, PageHeader, Section, UTC } from "../authoring/ui";
import { PublicationState } from "../publications/PublicationState";
import { byAt } from "../registry/words";
import { mapPath } from "../shell/paths";

type Certificate = components["schemas"]["Certificate"];
type Status = components["schemas"]["CertificateStatus"];
type Holder = components["schemas"]["CertificateHolder"];
type Service = components["schemas"]["CertificateService"];
type ListPublication = components["schemas"]["ListPublication"];
type Issued = components["schemas"]["CertificateIssued"];

export const STATUSES: readonly Status[] = ["issued", "operating", "ceased", "suspended", "limited", "revoked", "lapsed"];
export const HOLDERS: readonly Holder[] = ["ussp", "cisp"];
/** Annex VI services of a USSP; the CISP's one service is common_information (Annex V). */
export const USSP_SERVICES: readonly Service[] = ["network_identification", "geo_awareness", "flight_authorisation", "traffic_information", "weather", "conformance_monitoring"];
export const CISP_SERVICES: readonly Service[] = ["common_information"];
/** api's CertificateReason.reason maxLength. */
export const REASON_MAX = 1000;
const ENDED: readonly Status[] = ["revoked", "lapsed"];

export function certificatesPath(lang: string, rest = ""): string {
  return `${mapPath(lang)}/certificates${rest === "" ? "" : `/${rest}`}`;
}

function CertStatus({ status }: { status: string }) {
  const t = useT();
  return (
    <Badge variant={status === "operating" ? "secondary" : ENDED.includes(status as Status) || status === "suspended" ? "destructive" : "outline"} data-testid="cert-status" data-status={status}>
      {t(`authority.cert.status.${status}`)}
    </Badge>
  );
}

function CertTabs() {
  const t = useT();
  const { lang } = useLang();
  return (
    <nav aria-label={t("authority.cert.tabs")} className="flex flex-wrap gap-4 border-b border-[var(--us-border)] px-4 py-2 text-sm">
      <Link className="underline-offset-4 hover:underline" href={certificatesPath(lang)}>
        {t("authority.cert.tab.list")}
      </Link>
      <Link className="underline-offset-4 hover:underline" href={certificatesPath(lang, "new")} data-testid="cert-new">
        {t("authority.cert.tab.issue")}
      </Link>
      <Link className="underline-offset-4 hover:underline" href={certificatesPath(lang, "register")} data-testid="cert-register-link">
        {t("authority.cert.tab.register")}
      </Link>
    </nav>
  );
}

export function CertificatesPage() {
  const t = useT();
  const { lang } = useLang();
  const router = useRouter();
  const client = useConsole();
  const [status, setStatus] = useState<Status | "">("");
  const [holder, setHolder] = useState<Holder | "">("");
  const [round, setRound] = useState(0);
  const { state } = useLoad(`certs|${status}|${holder}`, async (c) =>
    must(await c.GET("/v1/certificates", { params: { query: { ...(status === "" ? {} : { status }), ...(holder === "" ? {} : { holder }) } } })),
  );
  const c = columnsFor<Certificate>();
  const cols = useMemo(
    () => [
      c.text("code", { headerKey: "authority.cert.f.code", mono: true }),
      c.text("holder_name", { headerKey: "authority.cert.f.holder_name" }),
      c.enum("holder", "authority.cert.holder", { headerKey: "authority.cert.f.holder" }),
      tableColumn<Certificate, string>({ id: "status", accessorKey: "status", header: () => t("authority.cert.f.status"), cell: (x) => <CertStatus status={x.getValue()} /> }),
      c.utc("valid_until", { headerKey: "authority.cert.f.valid_until" }),
    ],
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [t],
  );
  return (
    <div className="flex flex-col" data-testid="certificates-page">
      <PageHeader titleKey="authority.cert.title" />
      <CertTabs />
      <Can roles={["admin"]} fallback={<p className="m-0 px-4 py-3 text-sm">{t("authority.act.not_your_role")}</p>}>
        <div className="grid gap-3 px-4 py-3 lg:grid-cols-[1fr_24rem]">
          <div className="flex flex-col gap-3">
            <div className="flex flex-wrap gap-3">
              <div className="flex flex-col gap-1">
                <Label htmlFor="cert-status">{t("authority.cert.f.status")}</Label>
                <select id="cert-status" className="rounded border border-[var(--us-border)] bg-[var(--us-surface)] px-2 py-1 text-sm" value={status} onChange={(e) => setStatus(e.target.value as Status | "")}>
                  <option value="">{t("authority.cert.any")}</option>
                  {STATUSES.map((s) => (
                    <option key={s} value={s}>
                      {t(`authority.cert.status.${s}`)}
                    </option>
                  ))}
                </select>
              </div>
              <div className="flex flex-col gap-1">
                <Label htmlFor="cert-holder">{t("authority.cert.f.holder")}</Label>
                <select id="cert-holder" className="rounded border border-[var(--us-border)] bg-[var(--us-surface)] px-2 py-1 text-sm" value={holder} onChange={(e) => setHolder(e.target.value as Holder | "")}>
                  <option value="">{t("authority.cert.any")}</option>
                  {HOLDERS.map((h) => (
                    <option key={h} value={h}>
                      {t(`authority.cert.holder.${h}`)}
                    </option>
                  ))}
                </select>
              </div>
            </div>
            <Loaded state={state} testId="certs">
              {(d) => (
                <DataTable
                  columns={cols}
                  rows={d.certificates}
                  getRowId={(r) => r.id}
                  caption={t("authority.cert.title")}
                  captionHidden
                  toolbar={false}
                  onSelect={(r) => router.push(certificatesPath(lang, r.id))}
                  empty={<EmptyState title={t("authority.cert.empty")} />}
                />
              )}
            </Loaded>
          </div>
          <aside className="flex flex-col gap-3">
            <section className="flex flex-col gap-2 rounded border border-[var(--us-border)] p-3" aria-label={t("authority.cert.list_title")} data-testid="ussp-list">
              <h2 className="m-0 text-base font-semibold">{t("authority.cert.list_title")}</h2>
              <p className="m-0 text-sm">{t("authority.cert.list_intro")}</p>
              <Act
                labelKey="authority.cert.publish_list"
                titleKey="authority.cert.publish_list_title"
                bodyKey="authority.cert.publish_list_body"
                run={async () => must(await client.POST("/v1/certificates/publish-list"))}
                onDone={() => setRound((r) => r + 1)}
                testId="publish-list"
              />
            </section>
            <PublicationState dataset="ussp_list" round={round} />
          </aside>
        </div>
      </Can>
    </div>
  );
}

function ListPublicationLine({ p }: { p: ListPublication }) {
  const t = useT();
  return (
    <p role="status" className="m-0 text-sm" data-testid="list-publication" data-state={p.state}>
      {t(`authority.cert.list_state.${p.state}`, { id: p.publication_id ?? 0, reason: p.reason ?? "" })}
    </p>
  );
}

export function CertificateDetail({ id }: { id: string }) {
  const t = useT();
  const { lang } = useLang();
  const client = useConsole();
  const [round, setRound] = useState(0);
  const [last, setLast] = useState<{ list: ListPublication; tokensUntil?: string | undefined } | null>(null);
  const [limits, setLimits] = useState("");
  const { state } = useLoad(`cert|${id}|${round}`, async (c) => must(await c.GET("/v1/certificates/{id}", { params: { path: { id } } })));
  const done = (r: { list_publication: ListPublication; tokens_valid_until?: string }) => {
    setLast({ list: r.list_publication, tokensUntil: r.tokens_valid_until });
    setRound((x) => x + 1);
  };
  return (
    <div className="flex flex-col" data-testid="certificate-detail">
      <PageHeader titleKey="authority.cert.detail" back={{ href: certificatesPath(lang), labelKey: "authority.cert.title" }} />
      <CertTabs />
      <Can roles={["admin"]} fallback={<p className="m-0 px-4 py-3 text-sm">{t("authority.act.not_your_role")}</p>}>
        <Loaded state={state} testId="cert">
          {(d) => {
            const c = d.certificate;
            const ended = ENDED.includes(c.status);
            const subject = `${c.holder_name} (${c.code})`;
            return (
              <>
                <Section titleKey="authority.cert.facts">
                  <Facts
                    testId="cert-facts"
                    items={[
                      ["authority.cert.f.code", <span key="c" className="font-mono">{c.code}</span>],
                      ["authority.cert.f.holder", t(`authority.cert.holder.${c.holder}`)],
                      ["authority.cert.f.holder_name", c.holder_name],
                      ["authority.cert.f.status", <CertStatus key="s" status={c.status} />],
                      ["authority.cert.f.operations", t(`authority.cert.operations.${c.operations}`)],
                      ["authority.cert.f.limited", t(c.limited ? "common.yes" : "common.no")],
                      ["authority.cert.f.suspended", t(c.suspended ? "common.yes" : "common.no")],
                      ["authority.cert.f.ended_at", <UTC key="e" iso={c.ended_at} />],
                      ["authority.cert.f.status_reason", c.status_reason],
                      ["authority.cert.f.status_changed", byAt(t, lang, c.status_changed_by, c.status_changed_at)],
                      ["authority.cert.f.services", c.services.map((s) => t(`authority.cert.service.${s}`)).join(", ")],
                      ["authority.cert.f.limitations", c.limitations.join("; ")],
                      ["authority.cert.f.conditions", c.conditions],
                      ["authority.cert.f.client_id", <span key="ci" className="font-mono">{c.client_id}</span>],
                      ["authority.cert.f.client_status", d.client_status === undefined ? null : t(`authority.cert.client.${d.client_status}`)],
                      ["authority.cert.f.base_url", c.base_url],
                      ["authority.cert.f.terms_url", c.terms_url],
                      ["authority.cert.f.holder_address", c.holder_address],
                      ["authority.cert.f.holder_email", c.holder_email],
                      ["authority.cert.f.holder_phone", c.holder_phone],
                      ["authority.cert.f.holder_url", c.holder_url],
                      ["authority.cert.f.issued_at", <UTC key="i" iso={c.issued_at} />],
                      ["authority.cert.f.valid_until", <UTC key="v" iso={c.valid_until} />],
                      ["authority.cert.f.lapses_at", c.lapses_at === undefined ? null : t("authority.cert.lapses", { at: fmtTimeUTC(c.lapses_at, lang), unused: c.lapse_unused_after_months, ceased: c.lapse_ceased_after_months })],
                    ]}
                  />
                </Section>
                {last !== null && (
                  <div className="px-4" data-testid="cert-change">
                    <ListPublicationLine p={last.list} />
                    {last.tokensUntil !== undefined && (
                      <p className="m-0 text-sm" data-testid="tokens-valid-until">
                        {t("authority.cert.tokens_valid_until", { at: fmtTimeUTC(last.tokensUntil, lang) })}
                      </p>
                    )}
                  </div>
                )}
                {!ended && (
                  <Section titleKey="authority.cert.acts">
                    <div className="flex flex-wrap items-start gap-3">
                      {!c.suspended && (
                        <Act
                          labelKey="authority.cert.suspend"
                          titleKey="authority.cert.suspend_title"
                          bodyKey="authority.cert.suspend_body"
                          vars={{ subject, client: c.client_id }}
                          reason={{ minLength: 1, maxLength: REASON_MAX }}
                          destructive
                          run={async (reason) => must(await client.POST("/v1/certificates/{id}/suspend", { params: { path: { id } }, body: { reason: reason ?? "" } }))}
                          onDone={done}
                          testId="cert-suspend"
                        />
                      )}
                      {(c.suspended || c.limited) && (
                        <Act
                          labelKey="authority.cert.reinstate"
                          titleKey="authority.cert.reinstate_title"
                          bodyKey={c.suspended ? "authority.cert.reinstate_body_suspended" : "authority.cert.reinstate_body_limited"}
                          vars={{ subject }}
                          reason={{ minLength: 1, maxLength: REASON_MAX }}
                          run={async (reason) => must(await client.POST("/v1/certificates/{id}/reinstate", { params: { path: { id } }, body: { reason: reason ?? "" } }))}
                          onDone={done}
                          testId="cert-reinstate"
                        />
                      )}
                      <div className="flex flex-col gap-1">
                        <Label htmlFor="cert-limits">{t("authority.cert.limit_list")}</Label>
                        <textarea
                          id="cert-limits"
                          className="min-w-64 rounded border border-[var(--us-border)] bg-[var(--us-surface)] p-1 text-sm"
                          rows={3}
                          value={limits}
                          onChange={(e) => setLimits(e.target.value)}
                          data-testid="cert-limits"
                        />
                        <Act
                          labelKey="authority.cert.limit"
                          titleKey="authority.cert.limit_title"
                          bodyKey="authority.cert.limit_body"
                          vars={{ subject, limits: lines(limits).join("; ") }}
                          reason={{ minLength: 1, maxLength: REASON_MAX }}
                          disabled={lines(limits).length === 0}
                          run={async (reason) =>
                            must(await client.POST("/v1/certificates/{id}/limit", { params: { path: { id } }, body: { reason: reason ?? "", limitations: lines(limits) } }))
                          }
                          onDone={(r) => {
                            setLimits("");
                            done(r);
                          }}
                          testId="cert-limit"
                        />
                      </div>
                      <Act
                        labelKey="authority.cert.revoke"
                        titleKey="authority.cert.revoke_title"
                        bodyKey="authority.cert.revoke_body"
                        vars={{ subject, client: c.client_id }}
                        reason={{ minLength: 1, maxLength: REASON_MAX }}
                        destructive
                        run={async (reason) => must(await client.POST("/v1/certificates/{id}/revoke", { params: { path: { id } }, body: { reason: reason ?? "" } }))}
                        onDone={done}
                        testId="cert-revoke"
                      />
                    </div>
                  </Section>
                )}
                <Section titleKey="authority.cert.timeline" testId="cert-timeline">
                  <Timeline c={c} notices={d.notices} />
                  {!ended && <NoticeForm id={id} onDone={(r) => done(r)} />}
                </Section>
                {!ended && (
                  <Section titleKey="authority.cert.edit">
                    <CertificateEdit c={c} onDone={(r) => done(r)} />
                  </Section>
                )}
              </>
            );
          }}
        </Loaded>
      </Can>
    </div>
  );
}

function lines(s: string): string[] {
  return s
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l !== "")
    .slice(0, 50);
}

/** The operating-status timeline: the issue, each notice as recorded (machine or letter), and the status changes api reports. */
function Timeline({ c, notices }: { c: Certificate; notices: components["schemas"]["CertificateNotice"][] }) {
  const t = useT();
  const { lang } = useLang();
  const events = [
    { at: c.issued_at, key: "issued", text: t("authority.cert.tl.issued", { by: c.created_by }) },
    ...notices.map((n) => ({
      at: n.at,
      key: `n${n.id}`,
      text: t(`authority.cert.tl.notice_${n.source}`, { state: t(`authority.cert.notice.${n.state}`), ref: n.reference ?? t("common.dash"), by: n.recorded_by, received: fmtTimeUTC(n.received_at, lang) }),
    })),
    ...(c.operations_started_at === undefined ? [] : [{ at: c.operations_started_at, key: "started", text: t("authority.cert.tl.started") }]),
    ...(c.operations_ceased_at === undefined ? [] : [{ at: c.operations_ceased_at, key: "ceased", text: t("authority.cert.tl.ceased") }]),
    ...(c.ended_at === undefined ? [] : [{ at: c.ended_at, key: "ended", text: t("authority.cert.tl.ended", { status: t(`authority.cert.status.${c.status}`) }) }]),
  ].sort((a, b) => a.at.localeCompare(b.at) || a.key.localeCompare(b.key));
  return (
    <ol className="m-0 flex flex-col gap-1 ps-4 text-sm" data-testid="timeline">
      {events.map((e) => (
        <li key={e.key}>
          <UTC iso={e.at} /> {e.text}
        </li>
      ))}
    </ol>
  );
}

const noticeSchema = z.object({ state: z.enum(["started", "ceased", "restarted"]), at: shapes.utcTime(), reference: z.string().trim().min(1).max(200) });

/** A notice received by letter (the letter's reference required). */
function NoticeForm({ id, onDone }: { id: string; onDone(r: components["schemas"]["CertificateNoticeResult"]): void }) {
  const client = useConsole();
  return (
    <Form
      schema={noticeSchema}
      defaults={{ state: "started", at: "", reference: "" }}
      submitLabelKey="authority.cert.notice_record"
      onSubmit={async (v) => {
        onDone(must(await client.POST("/v1/certificates/{id}/status-notices", { params: { path: { id } }, body: v })));
      }}
    >
      <div className="grid gap-2 md:grid-cols-3" data-testid="notice-form">
        <SelectField
          name="state"
          labelKey="authority.cert.f.notice_state"
          options={[
            { value: "started", labelKey: "authority.cert.notice.started" },
            { value: "ceased", labelKey: "authority.cert.notice.ceased" },
            { value: "restarted", labelKey: "authority.cert.notice.restarted" },
          ]}
          required
        />
        <UTCDateTimeField name="at" labelKey="authority.cert.f.notice_at" required />
        <TextField name="reference" labelKey="authority.cert.f.notice_reference" hintKey="authority.cert.h.notice_reference" required />
      </div>
    </Form>
  );
}

const editSchema = z.object({
  holder_name: z.string().trim().min(1).max(200),
  holder_address: z.string().max(500),
  holder_email: z.string().max(254),
  holder_phone: z.string().max(50),
  holder_url: z.string().max(2048),
  base_url: z.string().max(2048),
  conditions: z.string().max(4000),
  terms_url: z.string().max(2048),
  valid_until: shapes.utcTime(),
});

function CertificateEdit({ c, onDone }: { c: Certificate; onDone(r: components["schemas"]["CertificateChange"]): void }) {
  const client = useConsole();
  return (
    <Form
      schema={editSchema}
      defaults={{
        holder_name: c.holder_name,
        holder_address: c.holder_address,
        holder_email: c.holder_email,
        holder_phone: c.holder_phone,
        holder_url: c.holder_url,
        base_url: c.base_url,
        conditions: c.conditions,
        terms_url: c.terms_url,
        valid_until: c.valid_until,
      }}
      submitLabelKey="authority.registry.save"
      onSubmit={async (v) => {
        // Only what changed is sent; an unchanged member is not rewritten.
        const body: Record<string, string> = {};
        for (const [k, x] of Object.entries(v)) if (x !== (c as unknown as Record<string, unknown>)[k]) body[k] = x;
        onDone(must(await client.PATCH("/v1/certificates/{id}", { params: { path: { id: c.id } }, body })));
      }}
    >
      <div className="grid gap-2 md:grid-cols-2" data-testid="cert-edit-form">
        <TextField name="holder_name" labelKey="authority.cert.f.holder_name" required />
        <TextField name="holder_address" labelKey="authority.cert.f.holder_address" />
        <TextField name="holder_email" type="email" labelKey="authority.cert.f.holder_email" hintKey="authority.cert.h.holder_email" />
        <TextField name="holder_phone" type="tel" labelKey="authority.cert.f.holder_phone" />
        <TextField name="holder_url" type="url" labelKey="authority.cert.f.holder_url" />
        <TextField name="base_url" type="url" labelKey="authority.cert.f.base_url" />
        <TextField name="terms_url" type="url" labelKey="authority.cert.f.terms_url" />
        <UTCDateTimeField name="valid_until" labelKey="authority.cert.f.valid_until" required />
        <TextareaField name="conditions" labelKey="authority.cert.f.conditions" className="md:col-span-2" />
      </div>
    </Form>
  );
}

const issueSchema = z
  .object({
    holder: z.enum(["ussp", "cisp"]),
    holder_name: z.string().trim().min(1).max(200),
    holder_address: z.string().max(500),
    holder_email: z.string().max(254),
    holder_phone: z.string().max(50),
    holder_url: z.string().max(2048),
    code: z.string().trim().regex(/^[A-Z0-9]{1,8}$/, { message: "authority.cert.e.code" }),
    base_url: z.string().max(2048),
    services: z.array(z.string()).min(1).max(7),
    conditions: z.string().max(4000),
    limitations: z.string().max(50_000),
    terms_url: z.string().max(2048),
    valid_from: shapes.utcTime().nullable(),
    valid_until: shapes.utcTime(),
    auth_method: z.enum(["client_secret_post", "private_key_jwt"]),
    jwks: z.string().max(100_000),
  })
  .superRefine((v, ctx) => {
    // A USSP needs its national API and its terms (CertificateInput); a private_key_jwt client its public keys.
    if (v.holder === "ussp" && v.base_url.trim() === "") ctx.addIssue({ code: "custom", path: ["base_url"], message: "form.error.required" });
    if (v.holder === "ussp" && v.terms_url.trim() === "") ctx.addIssue({ code: "custom", path: ["terms_url"], message: "form.error.required" });
    if (v.auth_method === "private_key_jwt" && v.jwks.trim() === "") ctx.addIssue({ code: "custom", path: ["jwks"], message: "form.error.required" });
    if (v.jwks.trim() !== "") {
      try {
        const j: unknown = JSON.parse(v.jwks);
        if (j === null || typeof j !== "object" || Array.isArray(j)) throw new Error("shape");
      } catch {
        ctx.addIssue({ code: "custom", path: ["jwks"], message: "authority.cert.e.jwks" });
      }
    }
  });

export function CertificateIssue() {
  const t = useT();
  const { lang } = useLang();
  const client = useConsole();
  const [issued, setIssued] = useState<Issued | null>(null);
  return (
    <div className="flex flex-col" data-testid="certificate-issue">
      <PageHeader titleKey="authority.cert.issue_title" back={{ href: certificatesPath(lang), labelKey: "authority.cert.title" }} />
      <CertTabs />
      <Can roles={["admin"]} fallback={<p className="m-0 px-4 py-3 text-sm">{t("authority.act.not_your_role")}</p>}>
        {issued === null ? (
          <div className="px-4 py-3">
            <Form
              schema={issueSchema}
              defaults={{
                holder: "ussp",
                holder_name: "",
                holder_address: "",
                holder_email: "",
                holder_phone: "",
                holder_url: "",
                code: "",
                base_url: "",
                services: [],
                conditions: "",
                limitations: "",
                terms_url: "",
                valid_from: null,
                valid_until: "",
                auth_method: "client_secret_post",
                jwks: "",
              }}
              submitLabelKey="authority.cert.issue"
              onSubmit={async (v) => {
                const body = compact({
                  ...v,
                  services: v.services as Service[],
                  limitations: lines(v.limitations),
                  valid_from: v.valid_from ?? undefined,
                  jwks: v.jwks.trim() === "" ? undefined : (JSON.parse(v.jwks) as Record<string, unknown>),
                }) as components["schemas"]["CertificateInput"];
                setIssued(must(await client.POST("/v1/certificates", { body })));
              }}
            >
              <IssueFields />
            </Form>
          </div>
        ) : (
          <Section titleKey="authority.cert.issued" vars={{ code: issued.certificate.code }} testId="cert-issued">
            <Facts
              items={[
                ["authority.cert.f.client_id", <span key="c" className="font-mono">{issued.client.client_id}</span>],
                ["authority.cert.f.scopes", issued.client.scopes.join(" ")],
                ["authority.cert.f.audiences", issued.client.audiences.join(" ")],
              ]}
            />
            {issued.client_secret !== undefined && <SecretOnce secret={issued.client_secret} />}
            <Link className="text-sm underline" href={certificatesPath(lang, issued.certificate.id)}>
              {t("authority.cert.open")}
            </Link>
          </Section>
        )}
      </Can>
    </div>
  );
}

/** The client's secret, shown once (docs/runbooks/certificates.md): hidden until asked, never kept by the page after it leaves. */
function SecretOnce({ secret }: { secret: string }) {
  const t = useT();
  const [shown, setShown] = useState(false);
  return (
    <div role="alert" className="flex flex-col gap-1 rounded border border-[var(--us-severity-warning)] p-2 text-sm" data-testid="client-secret">
      <p className="m-0 font-semibold">{t("authority.cert.secret_once")}</p>
      {shown ? (
        <Input readOnly value={secret} className="font-mono" aria-label={t("authority.cert.secret_label")} data-testid="client-secret-value" />
      ) : (
        <Button type="button" size="sm" variant="outline" className="self-start" onClick={() => setShown(true)} data-testid="client-secret-show">
          {t("authority.cert.secret_show")}
        </Button>
      )}
    </div>
  );
}

function IssueFields() {
  return (
    <div className="grid gap-2 md:grid-cols-2" data-testid="cert-issue-form">
      <EnumField name="holder" values={HOLDERS} i18nPrefix="authority.cert.holder" labelKey="authority.cert.f.holder" required />
      <TextField name="code" labelKey="authority.cert.f.code" hintKey="authority.cert.h.code" required />
      <TextField name="holder_name" labelKey="authority.cert.f.holder_name" required />
      <TextField name="holder_address" labelKey="authority.cert.f.holder_address" />
      <TextField name="holder_email" type="email" labelKey="authority.cert.f.holder_email" hintKey="authority.cert.h.holder_email" />
      <TextField name="holder_phone" type="tel" labelKey="authority.cert.f.holder_phone" />
      <TextField name="holder_url" type="url" labelKey="authority.cert.f.holder_url" />
      <TextField name="base_url" type="url" labelKey="authority.cert.f.base_url" hintKey="authority.cert.h.base_url" />
      <TextField name="terms_url" type="url" labelKey="authority.cert.f.terms_url" hintKey="authority.cert.h.terms_url" />
      <SetField name="services" values={[...USSP_SERVICES, ...CISP_SERVICES]} i18nPrefix="authority.cert.service" labelKey="authority.cert.f.services" hintKey="authority.cert.h.services" required className="md:col-span-2" />
      <UTCDateTimeField name="valid_from" labelKey="authority.cert.f.valid_from" hintKey="authority.cert.h.valid_from" />
      <UTCDateTimeField name="valid_until" labelKey="authority.cert.f.valid_until" required />
      <EnumField name="auth_method" values={["client_secret_post", "private_key_jwt"]} i18nPrefix="authority.cert.auth" labelKey="authority.cert.f.auth_method" required />
      <TextareaField name="jwks" labelKey="authority.cert.f.jwks" hintKey="authority.cert.h.jwks" rows={3} />
      <TextareaField name="conditions" labelKey="authority.cert.f.conditions" className="md:col-span-2" />
      <TextareaField name="limitations" labelKey="authority.cert.f.limitations" hintKey="authority.cert.h.limitations" className="md:col-span-2" />
    </div>
  );
}

/** The public register as the public sees it (GET /v1/certificates/register, no personal data, no contact). */
export function RegisterPreview() {
  const t = useT();
  const { lang } = useLang();
  const { state } = useLoad("register", async (c) => must(await c.GET("/v1/certificates/register")));
  return (
    <div className="flex flex-col" data-testid="register-preview">
      <PageHeader titleKey="authority.cert.register_title" back={{ href: certificatesPath(lang), labelKey: "authority.cert.title" }} />
      <CertTabs />
      <Section titleKey="authority.cert.register_preview">
        <p className="m-0 text-sm">{t("authority.cert.register_intro")}</p>
        <Loaded state={state} testId="register">
          {(r) => (
            <>
              <p className="m-0 text-xs">{t("authority.cert.register_generated", { at: fmtTimeUTC(r.generated_at, lang) })}</p>
              {r.certificates.length === 0 ? (
                <p className="m-0 text-sm">{t("authority.cert.register_empty")}</p>
              ) : (
                <table className="w-full text-sm" data-testid="register-table">
                  <caption className="sr-only">{t("authority.cert.register_title")}</caption>
                  <thead>
                    <tr>
                      <th className="text-start">{t("authority.cert.f.code")}</th>
                      <th className="text-start">{t("authority.cert.f.holder_name")}</th>
                      <th className="text-start">{t("authority.cert.f.holder")}</th>
                      <th className="text-start">{t("authority.cert.f.services")}</th>
                      <th className="text-start">{t("authority.cert.f.status")}</th>
                      <th className="text-start">{t("authority.cert.f.validity")}</th>
                      <th className="text-start">{t("authority.cert.f.limitations")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {r.certificates.map((e) => (
                      <tr key={e.certificate_id} data-code={e.code}>
                        <td className="font-mono">{e.code}</td>
                        <td>{e.holder_name}</td>
                        <td>{t(`authority.cert.holder.${e.holder}`)}</td>
                        <td>{e.services.map((s) => t(`authority.cert.service.${s}`)).join(", ")}</td>
                        <td>
                          <CertStatus status={e.status} />
                        </td>
                        <td>{t("authority.cert.validity", { from: fmtTimeUTC(e.valid_from, lang), until: fmtTimeUTC(e.valid_until, lang) })}</td>
                        <td>{e.limitations.join("; ")}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </>
          )}
        </Loaded>
      </Section>
    </div>
  );
}
