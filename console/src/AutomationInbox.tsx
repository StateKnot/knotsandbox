import { useEffect, useRef, useState } from "react";
import type { FormEvent } from "react";
import { ApiFailure, unwrap } from "./api.ts";
import type { Schema } from "./api.ts";
import type { Context } from "./App.tsx";
import {
  notificationAckPath,
  notificationEtag,
  notificationId,
  notificationPage,
  notificationReceipt,
  notificationsEnabled,
  scopedNotification,
} from "./notification-inbox.ts";

function message(error: unknown) {
  return error instanceof ApiFailure
    ? `${error.code}${error.requestId ? ` · 请求 ${error.requestId}` : ""}`
    : "请求未完成，请在请求记录核对原请求。";
}
function useRead<T>(key: string, load: (signal: AbortSignal) => Promise<T>) {
  const [state, setState] = useState<{
    key: string;
    data: T | null;
    error: unknown;
    loading: boolean;
  }>({ key, data: null, error: null, loading: true });
  const current = useRef(load);
  current.current = load;
  useEffect(() => {
    const controller = new AbortController();
    let alive = true;
    setState({ key, data: null, error: null, loading: true });
    void current.current(controller.signal).then(
      (data) => {
        if (alive) setState({ key, data, error: null, loading: false });
      },
      (error) => {
        if (alive) setState({ key, data: null, error, loading: false });
      },
    );
    return () => {
      alive = false;
      controller.abort();
    };
  }, [key]);
  return state.key === key
    ? state
    : { key, data: null, error: null, loading: true };
}

export function AutomationInbox({
  context,
  project,
  revision,
  caps,
  capsLoading,
  capsError,
}: {
  context: Context;
  project: string;
  revision: number;
  caps: Schema["Capabilities"] | null;
  capsLoading: boolean;
  capsError: unknown;
}) {
  const enabled = notificationsEnabled(caps, project);
  const blocked = !enabled || capsLoading || !!capsError;
  const [instanceDraft, setInstanceDraft] = useState(""),
    [instance, setInstance] = useState<string | undefined>(),
    [cursor, setCursor] = useState<string | null>(null),
    [detailId, setDetailId] = useState(""),
    [lookup, setLookup] = useState(""),
    [confirmation, setConfirmation] = useState(""),
    [read, setRead] = useState(0),
    [denied, setDenied] = useState(false),
    [pending, setPending] = useState(false),
    [error, setError] = useState<unknown>(null),
    [conflict, setConflict] = useState(false);
  const lifetime = useRef<AbortController | null>(null);
  const writable = useRef(false);
  useEffect(() => {
    const controller = new AbortController();
    lifetime.current = controller;
    return () => {
      controller.abort();
      lifetime.current = null;
    };
  }, []);
  useEffect(() => {
    if (!enabled && !capsLoading) {
      setCursor(null);
      setDetailId("");
      setLookup("");
      setConfirmation("");
    }
  }, [enabled, capsLoading]);
  const scope = `${context.session.tenant_id}:${context.session.principal_id}:${context.session.csrf_token}:${project}:${instance ?? "all"}:${revision}:${read}:${blocked}:${denied}`;
  const list = useRead(`${scope}:list:${cursor ?? "first"}`, async (signal) => {
    if (blocked || denied) return null;
    return notificationPage(
      unwrap(
        await context.api.client.GET("/v1/automation-notifications", {
          params: {
            header: { "X-Tenant-ID": context.session.tenant_id },
            query: {
              project_id: project,
              limit: 20,
              ...(instance ? { instance_id: instance } : {}),
              ...(cursor ? { cursor } : {}),
            },
          },
          signal,
        }),
      ),
      context.session,
      project,
      instance,
    );
  });
  const detail = useRead(`${scope}:detail:${detailId}`, async (signal) => {
    if (blocked || denied || !detailId) return null;
    const result = await context.api.client.GET(
      "/v1/automation-notifications/{id}",
      {
        params: {
          header: { "X-Tenant-ID": context.session.tenant_id },
          path: { id: detailId },
        },
        signal,
      },
    );
    const resource = scopedNotification(
      unwrap(result),
      context.session,
      project,
      instance,
      detailId,
    );
    return {
      resource,
      etag: notificationEtag(result.response, resource.version),
    };
  });
  const row = detail.data?.resource;
  const unresolved =
    !!row &&
    context.journal
      .list(context.session)
      .some(
        (intent) =>
          ["READY", "UNKNOWN", "PENDING"].includes(intent.state) &&
          intent.path === notificationAckPath(row.id),
      );
  writable.current =
    !blocked &&
    !denied &&
    !pending &&
    !conflict &&
    !detail.loading &&
    !!row &&
    row.acknowledged_at === null &&
    !unresolved;
  useEffect(() => {
    const rejected = [list.error, detail.error].find(
      (value) =>
        value instanceof ApiFailure &&
        ([401, 403, 404].includes(value.status ?? 0) ||
          value.code === "INVALID_AUTOMATION_NOTIFICATION"),
    );
    if (rejected) {
      setDenied(true);
      setDetailId("");
      setLookup("");
      setConfirmation("");
      setCursor(null);
      setError(rejected);
    }
  }, [list.error, detail.error]);
  function refresh() {
    setDenied(false);
    setError(null);
    setConflict(false);
    setConfirmation("");
    setCursor(null);
    setRead((value) => value + 1);
  }
  function open(id: string) {
    if (!notificationId(id)) {
      setError(new ApiFailure("INVALID_AUTOMATION_NOTIFICATION"));
      return;
    }
    setDetailId(id);
    setLookup(id);
    setConfirmation("");
    setConflict(false);
    setError(null);
    setRead((value) => value + 1);
  }
  function filter(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const next = instanceDraft.trim().toLowerCase();
    if (next && !notificationId(next)) {
      setError(new ApiFailure("INVALID_INSTANCE_ID"));
      return;
    }
    setInstance(next || undefined);
    setCursor(null);
    setDetailId("");
    setLookup("");
    setConfirmation("");
    setDenied(false);
    setError(null);
    setConflict(false);
    setRead((value) => value + 1);
  }
  async function acknowledge(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const original = detail.data;
    const controller = lifetime.current;
    if (
      !original ||
      !controller ||
      controller.signal.aborted ||
      !writable.current ||
      confirmation !== original.resource.id
    )
      return;
    setPending(true);
    setError(null);
    try {
      await context.perform<Schema["AutomationNotificationReceipt"]>(
        notificationAckPath(original.resource.id),
        {},
        original.etag,
        "POST",
        (value, response) => {
          const receipt = notificationReceipt(
            value,
            context.session,
            project,
            original.resource,
          );
          notificationEtag(response.etag, receipt.resource.version);
        },
      );
      if (!controller.signal.aborted) {
        setConfirmation("");
        setCursor(null);
        setRead((value) => value + 1);
      }
    } catch (failure) {
      if (!controller.signal.aborted) {
        setError(failure);
        if (failure instanceof ApiFailure && failure.status === 412) {
          setConflict(true);
          setConfirmation("");
        }
        if (
          failure instanceof ApiFailure &&
          ([401, 403, 404].includes(failure.status ?? 0) ||
            failure.code === "INVALID_AUTOMATION_NOTIFICATION" ||
            failure.code === "INVALID_NOTIFICATION_ETAG")
        ) {
          setDenied(true);
          setDetailId("");
          setLookup("");
          setConfirmation("");
          setCursor(null);
        }
      }
    } finally {
      if (!controller.signal.aborted) setPending(false);
    }
  }
  return (
    <section
      className="card"
      data-testid="automation-inbox"
      data-project-id={project}
    >
      <h2>自动化异常通知收件箱</h2>
      <p className="notice">
        这是 FAILED 或 OUTCOME_UNKNOWN
        发生时的历史通知，不表示原运行的当前状态。确认只记录已阅，不修复、不重新派发，也不删除通知。请使用原策略和运行
        ID 核对结果。
      </p>
      {blocked && (
        <p role="status">
          {capsLoading
            ? "正在核对通知能力…"
            : "当前部署未提供自动化通知能力，或能力读取未完成。"}
        </p>
      )}
      {!!error && (
        <p role="alert" className="error">
          {message(error)}
        </p>
      )}
      <button onClick={refresh} disabled={blocked || pending}>
        刷新通知
      </button>
      <form className="row" onSubmit={filter}>
        <label>
          实例 ID（可选）
          <input
            aria-label="实例 ID（可选）"
            value={instanceDraft}
            onChange={(event) => setInstanceDraft(event.target.value)}
          />
        </label>
        <button disabled={blocked || pending}>应用实例筛选</button>
      </form>
      {!blocked && !denied && (
        <>
          {list.loading && <p role="status">正在读取通知…</p>}
          {!!list.error && (
            <p role="alert" className="error">
              {message(list.error)}
            </p>
          )}
          {list.data && (
            <>
              <p className="fine">
                列表截止 {list.data.cutoff} · 每页 20
                条；翻页沿同一项目与实例筛选。
              </p>
              <div className="table-wrap">
                <table aria-label="自动化异常通知列表">
                  <thead>
                    <tr>
                      <th>发生时状态 / 时间</th>
                      <th>实例 / 策略 / 运行</th>
                      <th>确认状态</th>
                      <th>查看</th>
                    </tr>
                  </thead>
                  <tbody>
                    {list.data.items.map((item) => (
                      <tr key={item.id} data-notification-id={item.id}>
                        <td>
                          {item.source_status}
                          <small>{item.created_at}</small>
                        </td>
                        <td className="mono">
                          {item.instance_id}
                          <small>策略 {item.automation_id}</small>
                          <small>运行 {item.run_id}</small>
                        </td>
                        <td>{item.acknowledged_at ? "已确认" : "待确认"}</td>
                        <td>
                          <button
                            onClick={() => open(item.id)}
                            disabled={pending}
                          >
                            查看通知 {item.id}
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              {!list.data.items.length && (
                <p className="empty">当前筛选没有通知。</p>
              )}
              {list.data.next_cursor && (
                <button
                  disabled={pending || list.loading}
                  onClick={() => {
                    setCursor(list.data!.next_cursor);
                    setConfirmation("");
                  }}
                >
                  下一页通知
                </button>
              )}
            </>
          )}
          <form
            className="row"
            onSubmit={(event) => {
              event.preventDefault();
              open(lookup.trim().toLowerCase());
            }}
          >
            <label>
              通知 ID
              <input
                aria-label="通知 ID"
                value={lookup}
                onChange={(event) => setLookup(event.target.value)}
              />
            </label>
            <button disabled={pending}>查询通知</button>
          </form>
          {detail.loading && detailId && <p role="status">正在核对通知…</p>}
          {!!detail.error && (
            <p role="alert" className="error">
              {message(detail.error)}
            </p>
          )}
          {row && (
            <section
              data-testid="automation-notification-detail"
              data-notification-id={row.id}
              data-version={row.version}
            >
              <h3>通知 {row.id}</h3>
              <dl>
                <dt>发生时运行状态 / 版本</dt>
                <dd>
                  {row.source_status} / {row.source_run_version}
                </dd>
                <dt>原策略 / 原运行</dt>
                <dd className="mono">
                  {row.automation_id} / {row.run_id}
                </dd>
                <dt>实例</dt>
                <dd className="mono">{row.instance_id}</dd>
                <dt>来源事件 / 发生时间</dt>
                <dd className="mono">
                  {row.source_event_id} / {row.created_at}
                </dd>
                <dt>确认时间 / 确认人</dt>
                <dd>
                  {row.acknowledged_at ?? "尚未确认"} /{" "}
                  {row.acknowledged_by ?? "—"}
                </dd>
              </dl>
              {conflict && (
                <p role="alert">
                  通知版本已变化；先显式刷新通知。未知结果继续在请求记录核对同一原键，不能替换请求。
                </p>
              )}
              {unresolved && (
                <p role="status">
                  此通知已有未确认请求，请在请求记录显式核对或重放原键。
                </p>
              )}
              {!row.acknowledged_at && (
                <form
                  className="row"
                  onSubmit={(event) => {
                    void acknowledge(event);
                  }}
                >
                  <label>
                    输入通知 ID 确认
                    <input
                      aria-label="输入通知 ID 确认"
                      value={confirmation}
                      onChange={(event) => setConfirmation(event.target.value)}
                      autoComplete="off"
                    />
                  </label>
                  <button
                    className="primary"
                    disabled={!writable.current || confirmation !== row.id}
                  >
                    确认通知已阅
                  </button>
                </form>
              )}
            </section>
          )}
        </>
      )}
    </section>
  );
}
