"use client";

// What the registry pages share (WP-22; api/openapi.yaml /v1/registry/*,
// docs/runbooks/registry-import.md, registry-portal.md): the section's
// tabs, a status shown in words, the status transition with its
// mandatory reason, and the page-by-page list of a registry kind.
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useState, type ReactNode } from "react";
import { useLang, useT } from "@rootxkit/uspace-ui/i18n";
import { DataTable, type TableColumn } from "@rootxkit/uspace-ui/table";
import { Badge, Button, EmptyState, Label } from "@rootxkit/uspace-ui/ui";
import type { components } from "../api/types";
import type { ConsoleClient } from "../api/client";
import { useLoad } from "../authoring/api";
import { Act, Can, Loaded } from "../authoring/ui";
import { registryPath } from "./paths";

export type RegistryStatus = components["schemas"]["RegistryStatus"];
export type SettableStatus = components["schemas"]["RegistryStatusInput"]["status"];

export const REGISTRY_STATUSES: readonly RegistryStatus[] = ["active", "suspended", "revoked", "expired"];
/** What a registrar may set; `expired` is the expiry job's (RegistryStatusInput). */
export const SETTABLE_STATUSES: readonly SettableStatus[] = ["active", "suspended", "revoked"];
/** api's RegistryStatusInput.reason maxLength; the console requires a reason for every transition. */
export const REASON_MAX = 500;

export { registryPath };

const TABS = [
  ["operators", "authority.registry.tab.operators"],
  ["uas", "authority.registry.tab.uas"],
  ["pilots", "authority.registry.tab.pilots"],
  ["import", "authority.registry.tab.import"],
  ["applications", "authority.registry.tab.applications"],
] as const;

/** The registry's sections. Import and applications are the registrar's (their x-roles). */
export function RegistryTabs() {
  const t = useT();
  const { lang } = useLang();
  const pathname = usePathname();
  const link = (seg: string, key: string) => {
    const href = registryPath(lang, seg);
    const current = pathname === href || pathname.startsWith(`${href}/`);
    return (
      <Link
        key={seg}
        href={href}
        aria-current={current ? "page" : undefined}
        className={current ? "font-bold underline underline-offset-4" : "underline-offset-4 hover:underline"}
      >
        {t(key)}
      </Link>
    );
  };
  return (
    <nav aria-label={t("authority.registry.tabs")} className="flex flex-wrap gap-4 border-b border-[var(--us-border)] px-4 py-2 text-sm" data-testid="registry-tabs">
      {TABS.slice(0, 3).map(([s, k]) => link(s, k))}
      <Can roles={["registrar"]}>{TABS.slice(3).map(([s, k]) => link(s, k))}</Can>
    </nav>
  );
}

/** A registry status in words, marked for the eye too. */
export function StatusBadge({ status }: { status: string }) {
  const t = useT();
  const variant = status === "active" ? "secondary" : status === "suspended" ? "outline" : "destructive";
  return (
    <Badge variant={variant} data-testid="registry-status" data-status={status}>
      {t(`authority.registry.status.${status}`)}
    </Badge>
  );
}

/**
 * The transition of one registry entry: the status chosen here, the
 * reason in the confirmation, then api's status operation. Every
 * transition takes a reason (api requires one for suspended and revoked;
 * the console asks it of all three, so the audit row says why).
 */
export function StatusChange(props: {
  subject: string;
  current: RegistryStatus;
  run(status: SettableStatus, reason: string): Promise<unknown>;
  onDone(): void;
}) {
  const t = useT();
  const [to, setTo] = useState<SettableStatus | "">("");
  return (
    <Can roles={["registrar"]}>
      <div className="flex flex-wrap items-end gap-2" data-testid="status-change">
        <div className="flex flex-col gap-1">
          <Label htmlFor="status-to">{t("authority.registry.status_to")}</Label>
          <select
            id="status-to"
            className="rounded border border-[var(--us-border)] bg-[var(--us-surface)] px-2 py-1 text-sm"
            value={to}
            onChange={(e) => setTo(e.target.value as SettableStatus | "")}
            data-testid="status-to"
          >
            <option value="">{t("form.choose")}</option>
            {SETTABLE_STATUSES.filter((s) => s !== props.current).map((s) => (
              <option key={s} value={s}>
                {t(`authority.registry.status.${s}`)}
              </option>
            ))}
          </select>
        </div>
        <Act
          labelKey="authority.registry.status_apply"
          titleKey="authority.registry.status_confirm_title"
          bodyKey="authority.registry.status_confirm_body"
          vars={{ subject: props.subject, from: t(`authority.registry.status.${props.current}`), to: to === "" ? "" : t(`authority.registry.status.${to}`) }}
          reason={{ minLength: 1 }}
          destructive={to === "revoked"}
          disabled={to === ""}
          run={(reason) => (to === "" ? Promise.reject(new Error("no status")) : props.run(to, (reason ?? "").slice(0, REASON_MAX)))}
          onDone={() => {
            setTo("");
            props.onDone();
          }}
          testId="status-apply"
        />
      </div>
    </Can>
  );
}

export interface Page<Row> {
  rows: Row[];
  next: string | undefined;
}

/**
 * One kind's list, a page at a time with api's cursor (`after` /
 * `next_after`), never all of it: the filters are api's query
 * parameters, the rows what it answered. An empty answer says what was
 * asked; a refusal or a failure is said.
 */
export function RegistryList<Row>(props: {
  queryKey: string;
  read(c: ConsoleClient, after: string | undefined): Promise<Page<Row>>;
  columns: readonly TableColumn<Row>[];
  getRowId(r: Row): string;
  captionKey: string;
  emptyKey: string;
  onSelect(r: Row): void;
  testId: string;
}) {
  const t = useT();
  const [cursors, setCursors] = useState<(string | undefined)[]>([undefined]);
  const after = cursors[cursors.length - 1];
  const { state } = useLoad(`${props.queryKey}|${after ?? ""}`, (c) => props.read(c, after));
  return (
    <div className="flex flex-col gap-2" data-testid={props.testId}>
      <Loaded state={state} testId={props.testId}>
        {(page) => (
          <>
            <DataTable
              columns={props.columns}
              rows={page.rows}
              getRowId={props.getRowId}
              caption={t(props.captionKey)}
              captionHidden
              toolbar={false}
              empty={<EmptyState title={t(props.emptyKey)} />}
              onSelect={props.onSelect}
            />
            <div className="flex gap-2">
              <Button type="button" size="sm" variant="outline" disabled={cursors.length === 1} onClick={() => setCursors((c) => c.slice(0, -1))}>
                {t("ui.previous_page")}
              </Button>
              <Button type="button" size="sm" variant="outline" disabled={page.next === undefined} onClick={() => setCursors((c) => [...c, page.next])} data-testid={`${props.testId}-next`}>
                {t("ui.next_page")}
              </Button>
            </div>
          </>
        )}
      </Loaded>
    </div>
  );
}

/** The filter bar of a list: its controls, applied on submit. */
export function Filters({ children, onApply, labelKey }: { children: ReactNode; onApply(): void; labelKey: string }) {
  const t = useT();
  return (
    <form
      className="flex flex-wrap items-end gap-3"
      aria-label={t(labelKey)}
      onSubmit={(e) => {
        e.preventDefault();
        onApply();
      }}
    >
      {children}
      <Button type="submit" size="sm" data-testid="filters-apply">
        {t("authority.act.search")}
      </Button>
    </form>
  );
}
