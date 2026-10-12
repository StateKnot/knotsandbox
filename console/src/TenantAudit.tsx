import { useEffect, useState } from "react";
import { ApiFailure, unwrap } from "./api.ts";
import type { Schema } from "./api.ts";
import type { Context } from "./App.tsx";

/** Tenant account history has its own authorization and no project selector. */
export function TenantAudit({
  context,
  revision,
}: {
  context: Context;
  revision: number;
}) {
  const [opened, setOpened] = useState(false);
  const [limit, setLimit] = useState(20);
  const [cursor, setCursor] = useState<string | null>(null);
  const [refresh, setRefresh] = useState(0);
  const { api, session } = context;
  const scope = `${session.tenant_id}:${session.principal_id}:${session.csrf_token}`;
  const key = `${scope}:${limit}:${cursor}:${revision}:${refresh}`;
  const [state, setState] = useState<{
    key: string;
    data: Schema["TenantAuditRecordPage"] | null;
    error: unknown;
    loading: boolean;
  }>({ key: "", data: null, error: null, loading: false });

  useEffect(() => {
    if (!opened) return;
    const controller = new AbortController();
    let alive = true;
    setState({ key, data: null, error: null, loading: true });
    void (async () => {
      try {
        const data = unwrap(
          await api.client.GET("/v1/tenant-audit-records", {
            params: {
              header: { "X-Tenant-ID": session.tenant_id },
              query: { limit, ...(cursor ? { cursor } : {}) },
            },
            signal: controller.signal,
          }),
        );
        if (
          data.items.some(
            (item) =>
              item.tenant_id !== session.tenant_id ||
              !("project_id" in item) ||
              item.project_id !== null,
          )
        )
          throw new ApiFailure("TENANT_AUDIT_SCOPE_MISMATCH");
        // openapi-fetch's Readable type removes pure-null fields. Restore the
        // typed projection only after checking the actual response's null.
        if (alive)
          setState({
            key,
            data: {
              ...data,
              items: data.items.map((item) => ({ ...item, project_id: null })),
            },
            error: null,
            loading: false,
          });
      } catch (error) {
        if (alive) setState({ key, data: null, error, loading: false });
      }
    })();
    return () => {
      alive = false;
      controller.abort();
    };
  }, [api, session.tenant_id, key, opened, cursor, limit]);

  const current = state.key === key ? state : null;
  return (
    <section aria-label="租户账户审计">
      <h2>租户账户审计</h2>
      <p className="muted">
        查看本租户机器身份登记及变更记录，需要独立的 tenant_audit:read
        租户权限。项目操作请在项目安全审计中查看。
      </p>
      <div className="row">
        <label className="field">
          <span>账户审计每页条数</span>
          <select
            aria-label="账户审计每页条数"
            value={limit}
            onChange={(event) => {
              setLimit(Number(event.target.value));
              setCursor(null);
            }}
          >
            {[1, 20, 50].map((value) => (
              <option key={value} value={value}>
                {value}
              </option>
            ))}
          </select>
        </label>
        <button
          disabled={current?.loading}
          onClick={() => {
            setOpened(true);
            setCursor(null);
            setRefresh((value) => value + 1);
          }}
        >
          {opened ? "账户审计第一页" : "读取租户账户审计"}
        </button>
        <button
          disabled={current?.loading || !current?.data?.next_cursor}
          onClick={() => setCursor(current!.data!.next_cursor)}
        >
          账户审计下一页
        </button>
      </div>
      {opened && (!current || current.loading) && (
        <p role="status">正在读取账户审计…</p>
      )}
      {current?.error ? (
        <p className="error" role="alert">
          {current.error instanceof ApiFailure
            ? `${current.error.code}${current.error.requestId ? ` · 请求 ${current.error.requestId}` : ""}`
            : "账户审计读取未完成，请重新读取第一页。"}
        </p>
      ) : null}
      {current?.data && (
        <>
          <p className="fine">分页截止时间 {current.data.cutoff}</p>
          <div className="table-wrap">
            <table>
              <caption className="sr-only">租户账户审计记录</caption>
              <thead>
                <tr>
                  <th>时间 / 动作</th>
                  <th>操作者 / 资源</th>
                  <th>结果 / 请求</th>
                </tr>
              </thead>
              <tbody>
                {current.data.items.map((item) => (
                  <tr key={item.id}>
                    <td>
                      {item.occurred_at}
                      <small className="mono">{item.action}</small>
                    </td>
                    <td className="mono">
                      {item.actor_principal_id ?? "系统"}
                      <small>{item.resource_id ?? "—"}</small>
                    </td>
                    <td>
                      {item.outcome}
                      <small className="mono">{item.request_id}</small>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {!current.data.items.length && <p>当前页暂无账户审计记录。</p>}
        </>
      )}
    </section>
  );
}
