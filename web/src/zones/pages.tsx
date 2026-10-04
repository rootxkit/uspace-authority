"use client";

// The zone and U-space airspace pages (WP-22; docs/runbooks/zones.md
// authoring flow): the versions in force and the drafts on a list and a
// map, the publication with its exact effect and its state, the ED-318
// export at a time, each identifier's versions with the difference
// between two, the approval (designation), the applicability check, and
// the editor. Every act is api's; the roles are the operations' x-roles.
import { useMemo, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { fmtNum, fmtTimeUTC, useLang, useT } from "@rootxkit/uspace-ui/i18n";
import { inputToUtc } from "@rootxkit/uspace-ui/form";
import { DataTable, columnsFor, tableColumn } from "@rootxkit/uspace-ui/table";
import { Badge, Button, EmptyState, Input, Label } from "@rootxkit/uspace-ui/ui";
import { must, outcomeOf, useConsole, useLoad, type Load } from "../authoring/api";
import { Act, Can, Facts, Loaded, PageHeader, ProblemNotice, Section, UTC } from "../authoring/ui";
import type { Role } from "../shell/nav";
import { mapPath } from "../shell/paths";
import { PublicationState } from "../publications/PublicationState";
import type { ZoneVersion } from "./adapt";
import { localText } from "./adapt";
import { PUBLISH_NAMED_MAX, ZONE_STATES, approve, getOne, listAll, listPage, publicationPreview, publish, versions, type Dataset, type ZoneState } from "./calls";
import { diff } from "./diff";
import { ZoneEditor, zonePath } from "./editor/ZoneEditor";
import { ZonesMap } from "./ZonesMap";
import { byAt } from "../registry/words";

/** The operations' x-roles (api/openapi.yaml). */
export const ROLES: Record<Dataset, { read: readonly Role[]; author: readonly Role[]; approve: readonly Role[]; publish: readonly Role[] }> = {
  zones: { read: ["inspector", "admin", "viewer"], author: ["inspector"], approve: ["admin"], publish: ["admin"] },
  uspace_airspace: { read: ["admin"], author: ["admin"], approve: ["admin"], publish: ["admin"] },
};

const base = (ds: Dataset) => (ds === "zones" ? "zones" : "uspace");
const titleOf = (ds: Dataset) => (ds === "zones" ? "authority.zones.title" : "authority.uspace.title");

export function listPath(lang: string, ds: Dataset): string {
  return `${mapPath(lang)}/${base(ds)}`;
}

function StateBadge({ state }: { state: string }) {
  const t = useT();
  return (
    <Badge variant={state === "published" ? "secondary" : state === "superseded" ? "outline" : "default"} data-testid="zone-state" data-state={state}>
      {t(`authority.zone.state.${state}`)}
    </Badge>
  );
}

/** The list and map of one dataset's versions in a state, with the publication. */
export function AirspaceList({ dataset }: { dataset: Dataset }) {
  const t = useT();
  const { lang } = useLang();
  const router = useRouter();
  const [state, setState] = useState<ZoneState | "">("");
  const [cursors, setCursors] = useState<(string | undefined)[]>([undefined]);
  const [round, setRound] = useState(0);
  const after = cursors[cursors.length - 1];
  const { state: load } = useLoad(`${dataset}|list|${state}|${after ?? ""}|${round}`, (c) => listPage(c, dataset, state === "" ? undefined : state, after));
  const c = columnsFor<ZoneVersion>();
  const cols = useMemo(
    () => [
      c.text("identifier", { headerKey: "authority.zone.f.identifier", mono: true }),
      tableColumn<ZoneVersion, unknown>({
        id: "name",
        accessorFn: (z) => localText((z.feature as { properties?: { name?: unknown } }).properties?.name, lang) ?? "",
        header: () => t("authority.zone.f.name"),
      }),
      c.text("type", { headerKey: "authority.zone.f.type" }),
      tableColumn<ZoneVersion, number>({ id: "zone_version", accessorKey: "zone_version", header: () => t("authority.zone.f.zone_version") }),
      tableColumn<ZoneVersion, string>({ id: "state", accessorKey: "state", header: () => t("authority.zone.f.state"), cell: (x) => <StateBadge state={x.getValue()} /> }),
      c.utc("valid_from", { headerKey: dataset === "zones" ? "authority.zone.f.valid_from" : "authority.uspace.f.designated_from" }),
      c.utc("valid_to", { headerKey: dataset === "zones" ? "authority.zone.f.valid_to" : "authority.uspace.f.designated_to" }),
    ],
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [t, lang, dataset],
  );
  return (
    <div className="flex flex-col" data-testid={`${base(dataset)}-page`}>
      <PageHeader titleKey={titleOf(dataset)}>
        <Can roles={ROLES[dataset].author}>
          <Link href={`${listPath(lang, dataset)}/new`} className="text-sm font-semibold underline" data-testid="zone-new">
            {t(dataset === "zones" ? "authority.zone.new" : "authority.uspace.new")}
          </Link>
          {dataset === "zones" && (
            <Link href={`${listPath(lang, dataset)}/import`} className="text-sm font-semibold underline" data-testid="zone-import">
              {t("authority.zone.import")}
            </Link>
          )}
        </Can>
      </PageHeader>
      <div className="grid gap-3 px-4 py-3 lg:grid-cols-[1fr_24rem]">
        <div className="flex flex-col gap-3">
          <div className="flex flex-col gap-1 self-start">
            <Label htmlFor="zone-state-filter">{t("authority.zone.f.state")}</Label>
            <select
              id="zone-state-filter"
              className="rounded border border-[var(--us-border)] bg-[var(--us-surface)] px-2 py-1 text-sm"
              value={state}
              onChange={(e) => {
                setState(e.target.value as ZoneState | "");
                setCursors([undefined]);
              }}
              data-testid="zone-state-filter"
            >
              <option value="">{t("authority.zone.state_any")}</option>
              {ZONE_STATES.map((s) => (
                <option key={s} value={s}>
                  {t(`authority.zone.state.${s}`)}
                </option>
              ))}
            </select>
          </div>
          <Loaded state={load} testId="zones-list">
            {(page) => (
              <>
                <ZonesMap zones={page.rows} onSelect={(id) => router.push(zonePath(lang, dataset, id))} />
                <DataTable
                  columns={cols}
                  rows={page.rows}
                  getRowId={(z) => `${z.identifier}@${z.zone_version}`}
                  caption={t(titleOf(dataset))}
                  captionHidden
                  toolbar={false}
                  onSelect={(z) => router.push(zonePath(lang, dataset, z.identifier))}
                  empty={<EmptyState title={t(state === "" ? "authority.zone.empty_any" : "authority.zone.empty", { state: state === "" ? "" : t(`authority.zone.state.${state}`) })} />}
                />
                <div className="flex gap-2">
                  <Button type="button" size="sm" variant="outline" disabled={cursors.length === 1} onClick={() => setCursors((x) => x.slice(0, -1))}>
                    {t("authority.act.api_previous")}
                  </Button>
                  <Button type="button" size="sm" variant="outline" disabled={page.next === undefined} onClick={() => setCursors((x) => [...x, page.next])}>
                    {t("authority.act.api_next")}
                  </Button>
                </div>
              </>
            )}
          </Loaded>
        </div>
        <aside className="flex flex-col gap-3">
          <Can roles={ROLES[dataset].publish}>
            <PublishPanel dataset={dataset} onPublished={() => setRound((r) => r + 1)} />
          </Can>
          <Can roles={dataset === "zones" ? ["inspector", "admin", "viewer"] : []}>
            <ExportPanel />
          </Can>
          <Can roles={["admin", "inspector", "viewer"]}>
            <PublicationState dataset={dataset} round={round} />
          </Can>
        </aside>
      </div>
    </div>
  );
}

/** The publication with its exact effect: the approved versions, the zones in force with them, the last version. */
function PublishPanel({ dataset, onPublished }: { dataset: Dataset; onPublished(): void }) {
  const t = useT();
  const { lang } = useLang();
  const client = useConsole();
  const [round, setRound] = useState(0);
  const [result, setResult] = useState<{ version: number; published: number; features: number; state: string } | null>(null);
  const clockVars = useClockVars();
  const namedVersions = useNamedVersions();
  const { state } = useLoad(`${dataset}|preview|${round}`, async (c) => {
    const [approved, published] = await Promise.all([listAll(c, dataset, "approved"), listAll(c, dataset, "published")]);
    // In force by api's clock, never the browser's (which may be wrong);
    // only when api sent no Date is the browser's used, and said.
    const apiNowMs = published.serverNowMs ?? approved.serverNowMs;
    const nowMs = apiNowMs ?? Date.now();
    return { ...publicationPreview(approved.rows, published.rows, nowMs), nowMs, apiClock: apiNowMs !== null, complete: approved.complete && published.complete };
  });
  return (
    <section className="flex flex-col gap-2 rounded border border-[var(--us-border)] p-3" aria-label={t("authority.zone.publish_title")} data-testid="publish-panel">
      <h2 className="m-0 text-base font-semibold">{t("authority.zone.publish_title")}</h2>
      <Loaded state={state} testId="publish-preview">
        {(p) => (
          <>
            <p className="m-0 text-sm" data-testid="publish-preview-text">
              {p.approved === 0 ? t("authority.zone.publish_nothing") : t("authority.zone.publish_preview", { approved: fmtNum(p.approved, 0, undefined, lang), in_force: fmtNum(p.inForce, 0, undefined, lang), ...clockVars(p) })}
            </p>
            {!p.complete && <p className="m-0 text-xs">{t("authority.zone.publish_incomplete")}</p>}
            <Act
              labelKey="authority.zone.publish"
              titleKey="authority.zone.publish_confirm_title"
              bodyKey={dataset === "zones" ? "authority.zone.publish_confirm_body" : "authority.uspace.publish_confirm_body"}
              vars={{ versions: namedVersions(p.versions), in_force: fmtNum(p.inForce, 0, undefined, lang), ...clockVars(p) }}
              disabled={p.approved === 0}
              run={() => publish(client, dataset)}
              onDone={(r) => {
                setResult({ version: r.zones_version, published: r.published.length, features: r.publication.feature_count, state: r.publication.state });
                setRound((x) => x + 1);
                onPublished();
              }}
              testId="publish"
            />
          </>
        )}
      </Loaded>
      {result !== null && (
        <p role="status" className="m-0 text-sm" data-testid="publish-result">
          {t("authority.zone.published", { version: result.version, published: result.published, features: fmtNum(result.features, 0, undefined, lang), state: t(`authority.pub.state.${result.state}`) })}
        </p>
      )}
    </section>
  );
}

/** The instant the count in force is at, and whose clock it is. */
function useClockVars(): (p: { nowMs: number; apiClock: boolean }) => { at: string; clock: string } {
  const t = useT();
  const { lang } = useLang();
  return (p) => ({ at: fmtTimeUTC(new Date(p.nowMs).toISOString(), lang), clock: t(p.apiClock ? "authority.zone.clock_api" : "authority.zone.clock_browser") });
}

/** "TSTP001 version 3, TSTP002 version 1 and 4 more": each approved version by name, at most PUBLISH_NAMED_MAX. */
function useNamedVersions(): (vs: readonly { identifier: string; version: number }[]) => string {
  const t = useT();
  const { lang } = useLang();
  return (vs) => {
    const named = vs.slice(0, PUBLISH_NAMED_MAX).map((v) => t("authority.zone.publish_item", { id: v.identifier, version: v.version }));
    if (vs.length > PUBLISH_NAMED_MAX) named.push(t("authority.zone.publish_more", { n: fmtNum(vs.length - PUBLISH_NAMED_MAX, 0, undefined, lang) }));
    return new Intl.ListFormat(lang, { style: "long", type: "conjunction" }).format(named);
  };
}

/** The ED-318 export at a time, or of the zones applying at a time; a download through the BFF. */
function ExportPanel() {
  const t = useT();
  const [mode, setMode] = useState<"at" | "applies_at">("at");
  const [when, setWhen] = useState("");
  const iso = when === "" ? null : inputToUtc(when);
  const href = `/_bff/api/v1/zones/export${iso === null ? "" : `?${mode}=${encodeURIComponent(iso)}`}`;
  return (
    <section className="flex flex-col gap-2 rounded border border-[var(--us-border)] p-3" aria-label={t("authority.zone.export_title")} data-testid="export-panel">
      <h2 className="m-0 text-base font-semibold">{t("authority.zone.export_title")}</h2>
      <div className="flex flex-col gap-1">
        <Label htmlFor="export-mode">{t("authority.zone.export_mode")}</Label>
        <select id="export-mode" className="rounded border border-[var(--us-border)] bg-[var(--us-surface)] px-2 py-1 text-sm" value={mode} onChange={(e) => setMode(e.target.value as "at" | "applies_at")}>
          <option value="at">{t("authority.zone.export_at")}</option>
          <option value="applies_at">{t("authority.zone.export_applies_at")}</option>
        </select>
      </div>
      <div className="flex flex-col gap-1">
        <Label htmlFor="export-when">{t("authority.zone.export_when")}</Label>
        <Input id="export-when" type="datetime-local" step={1} value={when} onChange={(e) => setWhen(e.target.value)} />
      </div>
      <a className="text-sm underline" href={href} download="zones-ed318.geojson" data-testid="export-link">
        {iso === null ? t("authority.zone.export_now") : t("authority.zone.export_download", { at: iso })}
      </a>
    </section>
  );
}

/** One identifier: its newest version, its history, the difference between two versions, and the acts. */
export function AirspaceDetail({ dataset, identifier }: { dataset: Dataset; identifier: string }) {
  const t = useT();
  const { lang } = useLang();
  const client = useConsole();
  const [round, setRound] = useState(0);
  const { state: one } = useLoad(`${dataset}|one|${identifier}|${round}`, (c) => getOne(c, dataset, identifier));
  const [before, setBefore] = useState<(number | undefined)[]>([undefined]);
  const { state: hist } = useLoad(`${dataset}|hist|${identifier}|${before[before.length - 1] ?? ""}|${round}`, (c) => versions(c, dataset, identifier, before[before.length - 1]));
  return (
    <div className="flex flex-col" data-testid="zone-detail">
      <PageHeader titleKey={dataset === "zones" ? "authority.zone.detail" : "authority.uspace.detail"} vars={{ id: identifier }} back={{ href: listPath(lang, dataset), labelKey: titleOf(dataset) }}>
        <Can roles={ROLES[dataset].author}>
          <Link href={`${zonePath(lang, dataset, identifier)}/edit`} className="text-sm font-semibold underline" data-testid="zone-revise">
            {t("authority.zone.revise")}
          </Link>
        </Can>
      </PageHeader>
      <Loaded state={one} testId="zone">
        {(z) => (
          <>
            <Section titleKey="authority.zone.newest" vars={{ version: z.zone_version }}>
              <VersionFacts z={z} dataset={dataset} />
              {z.state === "draft" && (
                <Can roles={ROLES[dataset].approve}>
                  <Act
                    labelKey={dataset === "zones" ? "authority.zone.approve" : "authority.uspace.designate"}
                    titleKey={dataset === "zones" ? "authority.zone.approve_title" : "authority.uspace.designate_title"}
                    bodyKey={dataset === "zones" ? "authority.zone.approve_body" : "authority.uspace.designate_body"}
                    vars={{ id: z.identifier, version: z.zone_version }}
                    run={() => approve(client, dataset, z.identifier, z.zone_version)}
                    onDone={() => setRound((r) => r + 1)}
                    testId="zone-approve"
                  />
                </Can>
              )}
            </Section>
            <ApplicabilityCheck dataset={dataset} identifier={identifier} version={z.zone_version} />
            <div className="px-4 py-3">
              <ZonesMap zones={[z]} testId="zone-map" />
            </div>
            <details className="px-4 py-3">
              <summary className="cursor-pointer text-sm font-semibold">{t("authority.zone.feature_json")}</summary>
              <pre className="max-h-96 overflow-auto rounded bg-[var(--us-surface-sunken)] p-2 text-xs" data-testid="feature-json">
                {JSON.stringify(z.feature, null, 2)}
              </pre>
            </details>
          </>
        )}
      </Loaded>
      <History state={hist} onOlder={(n) => setBefore((b) => [...b, n])} onNewer={() => setBefore((b) => b.slice(0, -1))} canNewer={before.length > 1} />
    </div>
  );
}

function VersionFacts({ z, dataset }: { z: ZoneVersion; dataset: Dataset }) {
  const t = useT();
  const { lang } = useLang();
  const p = (z.feature as { properties?: Record<string, unknown> }).properties ?? {};
  const layer = (z.feature as { geometry?: { layer?: Record<string, unknown> } }).geometry?.layer ?? {};
  const dash = t("common.dash");
  return (
    <>
      <Facts
        testId="zone-facts"
        items={[
          ["authority.zone.f.identifier", <span key="i" className="font-mono">{z.identifier}</span>],
          ["authority.zone.f.name", localText(p["name"], lang)],
          ["authority.zone.f.type", z.type],
          ["authority.zone.f.country", z.country],
          ["authority.zone.f.zone_version", String(z.zone_version)],
          ["authority.zone.f.state", <StateBadge key="s" state={z.state} />],
          [dataset === "zones" ? "authority.zone.f.valid_from" : "authority.uspace.f.designated_from", <UTC key="vf" iso={z.valid_from} />],
          [dataset === "zones" ? "authority.zone.f.valid_to" : "authority.uspace.f.designated_to", <UTC key="vt" iso={z.valid_to} />],
          ["authority.zone.f.limits", t("authority.zone.limits", { lower: String(layer["lower"] ?? dash), lower_ref: String(layer["lowerReference"] ?? dash), upper: String(layer["upper"] ?? dash), upper_ref: String(layer["upperReference"] ?? dash), uom: String(layer["uom"] ?? "m") })],
          ["authority.zone.f.created", byAt(t, lang, z.created_by, z.created_at)],
          ["authority.zone.f.approved", byAt(t, lang, z.approved_by, z.approved_at)],
          ["authority.zone.f.published", z.published_version === undefined ? null : t("authority.zone.published_as", { version: z.published_version, by_at: byAt(t, lang, z.published_by, z.published_at) ?? dash })],
          ...(dataset === "uspace_airspace"
            ? ([
                ["authority.uspace.f.airspace_name", z.designation?.airspace_name],
                ["authority.uspace.f.services_required", z.designation?.services_required.join(", ")],
                ["authority.uspace.f.in_controlled_airspace", z.designation === undefined ? null : t(z.designation.in_controlled_airspace ? "common.yes" : "common.no")],
                ["authority.uspace.f.adjacent_ids", z.designation?.adjacent_ids?.join(", ")],
              ] as const)
            : []),
        ]}
      />
      {z.extensions.length > 0 && (
        <div role="note" className="rounded border border-[var(--us-severity-warning)] p-2 text-xs" data-testid="zone-extensions">
          <p className="m-0 font-semibold">{t("authority.zone.extensions")}</p>
          <ul className="m-0 ps-4">
            {z.extensions.map((e) => (
              <li key={e.field}>
                <span className="font-mono">{e.field}</span>: {e.reason}
              </li>
            ))}
          </ul>
        </div>
      )}
    </>
  );
}

/** api's applicability at a time: applies, does not apply, or unknown with the reason; never one shown as another. */
function ApplicabilityCheck({ dataset, identifier, version }: { dataset: Dataset; identifier: string; version: number }) {
  const t = useT();
  const client = useConsole();
  const [when, setWhen] = useState("");
  const [state, setState] = useState<Load<{ applicability: string; reason?: string; at: string }> | null>(null);
  if (dataset !== "zones") return null;
  return (
    <Section titleKey="authority.zone.applies_title" testId="applies">
      <form
        className="flex flex-wrap items-end gap-2"
        onSubmit={(e) => {
          e.preventDefault();
          const at = inputToUtc(when);
          if (at === null) return;
          setState({ kind: "loading" });
          client
            .GET("/v1/zones/{identifier}/applies", { params: { path: { identifier }, query: { at, zone_version: version } } })
            .then((r) => setState({ kind: "loaded", data: must(r) }))
            .catch((err: unknown) => setState(outcomeOf(err)));
        }}
      >
        <div className="flex flex-col gap-1">
          <Label htmlFor="applies-at">{t("authority.zone.applies_at")}</Label>
          <Input id="applies-at" type="datetime-local" step={1} value={when} onChange={(e) => setWhen(e.target.value)} data-testid="applies-at" />
        </div>
        <Button type="submit" size="sm" disabled={when === ""} data-testid="applies-check">
          {t("authority.zone.applies_check")}
        </Button>
      </form>
      {state?.kind === "loaded" && (
        <p className="m-0 text-sm" data-testid="applies-result" data-applicability={state.data.applicability}>
          {t(`authority.zone.applicability.${state.data.applicability}`, { at: state.data.at })}
          {state.data.reason !== undefined && ` ${t("authority.zone.applicability_reason", { reason: state.data.reason })}`}
        </p>
      )}
      {state?.kind === "refused" && <ProblemNotice error={state.error} />}
      {state?.kind === "failed" && <ProblemNotice error="failed" />}
    </Section>
  );
}

function History({ state, onOlder, onNewer, canNewer }: { state: Load<{ rows: ZoneVersion[]; next: number | undefined }>; onOlder(n: number): void; onNewer(): void; canNewer: boolean }) {
  const t = useT();
  const [pair, setPair] = useState<[number | null, number | null]>([null, null]);
  return (
    <Section titleKey="authority.zone.history" testId="zone-history">
      <Loaded state={state}>
        {(h) => {
          const a = h.rows.find((v) => v.zone_version === pair[0]);
          const b = h.rows.find((v) => v.zone_version === pair[1]);
          const d = a !== undefined && b !== undefined ? diff({ feature: a.feature, valid_from: a.valid_from, valid_to: a.valid_to }, { feature: b.feature, valid_from: b.valid_from, valid_to: b.valid_to }) : null;
          return (
            <>
              <table className="w-full text-sm">
                <caption className="sr-only">{t("authority.zone.history")}</caption>
                <thead>
                  <tr>
                    <th className="text-start">{t("authority.zone.f.zone_version")}</th>
                    <th className="text-start">{t("authority.zone.f.state")}</th>
                    <th className="text-start">{t("authority.zone.f.created")}</th>
                    <th className="text-start">{t("authority.zone.diff_from")}</th>
                    <th className="text-start">{t("authority.zone.diff_to")}</th>
                  </tr>
                </thead>
                <tbody>
                  {h.rows.map((v) => (
                    <tr key={v.zone_version} data-version={v.zone_version}>
                      <td>{v.zone_version}</td>
                      <td>
                        <StateBadge state={v.state} />
                      </td>
                      <td>
                        {v.created_by} <UTC iso={v.created_at} />
                      </td>
                      <td>
                        <input type="radio" name="diff-from" aria-label={t("authority.zone.diff_from_v", { version: v.zone_version })} checked={pair[0] === v.zone_version} onChange={() => setPair([v.zone_version, pair[1]])} />
                      </td>
                      <td>
                        <input type="radio" name="diff-to" aria-label={t("authority.zone.diff_to_v", { version: v.zone_version })} checked={pair[1] === v.zone_version} onChange={() => setPair([pair[0], v.zone_version])} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <div className="flex gap-2">
                <Button type="button" size="sm" variant="outline" disabled={!canNewer} onClick={onNewer}>
                  {t("authority.zone.newer")}
                </Button>
                <Button type="button" size="sm" variant="outline" disabled={h.next === undefined} onClick={() => h.next !== undefined && onOlder(h.next)}>
                  {t("authority.zone.older")}
                </Button>
              </div>
              {d !== null && (
                <div data-testid="zone-diff">
                  <p className="m-0 text-sm font-semibold">{t("authority.zone.diff_title", { from: pair[0] ?? 0, to: pair[1] ?? 0, n: d.changes.length })}</p>
                  {d.changes.length === 0 ? (
                    <p className="m-0 text-sm">{t("authority.zone.diff_none")}</p>
                  ) : (
                    <table className="w-full text-xs">
                      <caption className="sr-only">{t("authority.zone.diff_title", { from: pair[0] ?? 0, to: pair[1] ?? 0, n: d.changes.length })}</caption>
                      <thead>
                        <tr>
                          <th className="text-start">{t("authority.zone.diff_path")}</th>
                          <th className="text-start">{t("authority.zone.diff_before")}</th>
                          <th className="text-start">{t("authority.zone.diff_after")}</th>
                        </tr>
                      </thead>
                      <tbody>
                        {d.changes.map((c) => (
                          <tr key={c.path}>
                            <td className="font-mono">{c.path}</td>
                            <td className="font-mono">{c.before ?? t("common.dash")}</td>
                            <td className="font-mono">{c.after ?? t("common.dash")}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )}
                  {d.truncated && <p className="m-0 text-xs">{t("authority.zone.diff_truncated")}</p>}
                </div>
              )}
            </>
          );
        }}
      </Loaded>
    </Section>
  );
}

/** The editor for a new identifier, or a revision of an existing one, with the published versions drawn beside it. */
export function AirspaceEdit({ dataset, identifier }: { dataset: Dataset; identifier?: string }) {
  const { lang } = useLang();
  const { state: ctx } = useLoad(`${dataset}|context`, async (c) => (await listAll(c, "zones", "published")).rows);
  const { state: one } = useLoad(`${dataset}|edit|${identifier ?? ""}`, async (c) => (identifier === undefined ? null : getOne(c, dataset, identifier)));
  const context = ctx.kind === "loaded" ? ctx.data : [];
  return (
    <div className="flex flex-col" data-testid="zone-edit-page">
      <PageHeader
        titleKey={identifier === undefined ? (dataset === "zones" ? "authority.zone.new" : "authority.uspace.new") : "authority.zone.revise_title"}
        vars={{ id: identifier ?? "" }}
        back={{ href: identifier === undefined ? listPath(lang, dataset) : zonePath(lang, dataset, identifier), labelKey: titleOf(dataset) }}
      />
      <Can roles={ROLES[dataset].author} fallback={<NotAuthor />}>
        <Loaded state={one} testId="zone-edit">
          {(z) => <ZoneEditor dataset={dataset} context={context} {...(z === null ? {} : { revising: z })} />}
        </Loaded>
      </Can>
    </div>
  );
}

function NotAuthor() {
  const t = useT();
  return (
    <p className="m-0 px-4 py-3 text-sm" data-testid="not-your-role">
      {t("authority.act.not_your_role")}
    </p>
  );
}
