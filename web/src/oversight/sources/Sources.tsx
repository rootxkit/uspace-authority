"use client";

// /<locale>/sources (admin): every switch and every source api knows,
// with its switch (enabled, or disabled by type, instance or default
// deny, by whom and why), its health (healthy, stale, lagging with its
// lag, never heard) and its counters (B-11: disabled is never silent).
// A switch is an audited act with a mandatory reason; api answers
// "changed: false" for a switch already in that state, and the page
// says nothing was written.
import { useState } from "react";
import { ApiError } from "@rootxkit/uspace-ui/api";
import { ConfirmDialog } from "@rootxkit/uspace-ui/form";
import { fmtAge, fmtTimeUTC, useLang, useT, type Lang, type Translate } from "@rootxkit/uspace-ui/i18n";
import { Badge, Button, TableBody, TableCaption, TableCell, TableHead, TableHeader, TableRow } from "@rootxkit/uspace-ui/ui";
import { Table } from "../../common/Table";
import type { components } from "../../api/types";
import { LoadNotice, ProblemText } from "../../common/Problem";
import { PageHeader, Part } from "../../common/ui";
import { must, useClient, useLoad } from "../../common/useApi";
import { SOURCE_TYPES } from "../enums";

type S = components["schemas"];

/** api's minimum for a switch's reason (SourceSwitchInput.reason minLength). */
const REASON_MIN_LENGTH = 1;

export function sourceHealthText(t: Translate, s: S["SourceView"], lang: Lang): string {
  if (s.health === "lagging") return t("authority.sources.health.lagging_value", { lag: fmtAge(s.lag_s ?? null, lang) });
  if (s.health === "stale" && s.age_s !== undefined) return t("authority.sources.health.stale_value", { age: fmtAge(s.age_s, lang) });
  return t(`authority.sources.health.${s.health}`);
}

function SwitchButton({ type, instance, enabled, onDone }: { type: S["SourceType"]; instance?: string; enabled: boolean; onDone(r: S["SourceSwitchResult"]): void }) {
  const t = useT();
  const client = useClient();
  const [open, setOpen] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  const target = instance === undefined ? type : `${type}/${instance}`;
  const send = (reason: string) => {
    setError(null);
    const body = { enabled: !enabled, reason };
    const call =
      instance === undefined
        ? client.PUT("/v1/sources/{source_type}", { params: { path: { source_type: type } }, body })
        : client.PUT("/v1/sources/{source_type}/{instance_id}", { params: { path: { source_type: type, instance_id: instance } }, body });
    call
      .then((r) => onDone(must(r)))
      .catch((err: unknown) => {
        if (err instanceof ApiError) setError(err);
      });
  };
  return (
    <div className="flex flex-col gap-1">
      <ConfirmDialog
        open={open}
        onOpenChange={setOpen}
        titleKey={enabled ? "authority.sources.disable_title" : "authority.sources.enable_title"}
        bodyKey={enabled ? "authority.sources.disable_body" : "authority.sources.enable_body"}
        vars={{ name: target }}
        reason={{ required: true, minLength: REASON_MIN_LENGTH }}
        destructive={enabled}
        confirmLabelKey={enabled ? "authority.sources.disable" : "authority.sources.enable"}
        onConfirm={(reason) => {
          setOpen(false);
          send(reason ?? "");
        }}
        trigger={
          <Button type="button" size="sm" variant={enabled ? "destructive" : "outline"} data-testid={`switch-${target}`}>
            {t(enabled ? "authority.sources.disable" : "authority.sources.enable")}
          </Button>
        }
      />
      {error !== null && <ProblemText error={error} />}
    </div>
  );
}

export function Sources() {
  const t = useT();
  const { lang } = useLang();
  const { state, reload } = useLoad("sources", async (c) => must(await c.GET("/v1/sources")));
  const [last, setLast] = useState<S["SourceSwitchResult"] | null>(null);
  const done = (r: S["SourceSwitchResult"]) => {
    setLast(r);
    reload();
  };
  const typeSwitch = (ty: S["SourceType"]) => (state.kind === "loaded" ? state.data.controls.find((c) => c.source_type === ty && c.instance_id === undefined) : undefined);
  return (
    <div className="flex flex-col gap-4 p-4">
      <PageHeader titleKey="authority.sources.title" introKey="authority.sources.intro" />
      <LoadNotice state={state} />
      {last !== null && (
        <p role="status" className="m-0 text-sm" data-testid="switch-result" data-changed={String(last.changed)}>
          {t(last.changed ? "authority.sources.switched" : "authority.sources.unchanged", {
            name: last.control.instance_id === undefined ? last.control.source_type : `${last.control.source_type}/${last.control.instance_id}`,
            version: last.version,
          })}
        </p>
      )}
      {state.kind === "loaded" && (
        <>
          {state.data.default_deny && (
            <p role="note" className="m-0 rounded-md border border-[var(--us-severity-warning)] p-2 text-sm" data-testid="default-deny">
              {t("authority.sources.default_deny")}
            </p>
          )}
          <Part titleKey="authority.sources.types">
            <Table>
              <TableCaption>{t("authority.sources.types_caption", { version: state.data.version })}</TableCaption>
              <TableHeader>
                <TableRow>
                  <TableHead>{t("authority.sources.type")}</TableHead>
                  <TableHead>{t("authority.sources.switch")}</TableHead>
                  <TableHead>{t("authority.sources.changed")}</TableHead>
                  <TableHead>{t("authority.sources.action")}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {SOURCE_TYPES.map((ty) => {
                  const c = typeSwitch(ty);
                  const enabled = c === undefined ? !state.data.default_deny : c.enabled;
                  return (
                    <TableRow key={ty} data-source-type={ty}>
                      <TableCell>{t(`authority.source_type.${ty}`)}</TableCell>
                      <TableCell>
                        {c === undefined
                          ? t(state.data.default_deny ? "authority.sources.no_switch_deny" : "authority.sources.no_switch")
                          : c.enabled
                            ? t("authority.sources.enabled")
                            : t("authority.sources.disabled_by", { who: c.actor, reason: c.reason })}
                      </TableCell>
                      <TableCell>{c === undefined ? "—" : fmtTimeUTC(c.changed_at, lang)}</TableCell>
                      <TableCell>
                        <SwitchButton type={ty} enabled={enabled} onDone={done} />
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </Part>
          <Part titleKey="authority.sources.instances">
            <Table data-testid="sources-table">
              <TableCaption>{t("authority.sources.instances_caption")}</TableCaption>
              <TableHeader>
                <TableRow>
                  <TableHead>{t("authority.sources.source")}</TableHead>
                  <TableHead>{t("authority.sources.switch")}</TableHead>
                  <TableHead>{t("authority.sources.health")}</TableHead>
                  <TableHead>{t("authority.sources.heard")}</TableHead>
                  <TableHead>{t("authority.sources.status_age")}</TableHead>
                  <TableHead>{t("authority.sources.counters")}</TableHead>
                  <TableHead>{t("authority.sources.action")}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {state.data.sources.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={7}>{t("authority.sources.empty")}</TableCell>
                  </TableRow>
                )}
                {state.data.sources.map((s) => {
                  const name = s.instance_id === undefined ? s.source_type : `${s.source_type}/${s.instance_id}`;
                  return (
                    <TableRow key={name} data-source={name} data-health={s.health} data-switch={s.switch}>
                      <TableCell>
                        {t(`authority.source_type.${s.source_type}`)}
                        {s.instance_id !== undefined && <span className="ms-1 font-mono text-xs">{s.instance_id}</span>}
                      </TableCell>
                      <TableCell>
                        {s.switch === "enabled" ? (
                          t("authority.sources.enabled")
                        ) : (
                          <span data-testid="disabled-by">
                            {t(`authority.sources.disabled.${s.disabled_by ?? "instance"}`, { who: s.disabled_by_who ?? "—", reason: s.disabled_reason ?? "—" })}
                          </span>
                        )}
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline">{sourceHealthText(t, s, lang)}</Badge>
                      </TableCell>
                      <TableCell>{s.age_s === undefined ? t("authority.sources.never") : fmtAge(s.age_s, lang)}</TableCell>
                      <TableCell>{s.status_age_s === undefined ? "—" : fmtAge(s.status_age_s, lang)}</TableCell>
                      <TableCell className="font-mono text-xs">
                        {Object.entries(s.counters ?? {})
                          .map(([k, v]) => `${k}=${v}`)
                          .join(" ")}
                      </TableCell>
                      <TableCell>{s.instance_id !== undefined && <SwitchButton type={s.source_type} instance={s.instance_id} enabled={s.switch === "enabled"} onDone={done} />}</TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </Part>
        </>
      )}
    </div>
  );
}
