import { useEffect, useState } from "react";
import { ApiFailure, UUID, unwrap } from "./api.ts";
import type { Schema } from "./api.ts";
import type { Context } from "./App.tsx";

type Accounting = Schema["ResourceAccounting"];
const MAX_INTEGER = 9223372036854775807n;
function decimal(value: unknown): value is string {
  return (
    typeof value === "string" &&
    /^(0|[1-9][0-9]{0,18})$/.test(value) &&
    BigInt(value) <= MAX_INTEGER
  );
}

function checkedPage(
  data: Accounting,
  instance: Schema["Instance"],
  project: string,
  launch: string,
  limit: number,
  cursor: string | null,
): Accounting {
  const contract = data.contract;
  if (
    data.instance_id !== instance.id ||
    !UUID.test(data.selected_launch_id) ||
    !UUID.test(data.cluster_epoch) ||
    (launch !== "" && data.selected_launch_id !== launch) ||
    data.pod_resource_evidence !== "NOT_CAPTURED" ||
    !["CAPTURED", "HISTORY_START_NOT_CAPTURED"].includes(
      data.request_evidence,
    ) ||
    (data.request_evidence === "CAPTURED") !== (contract !== null) ||
    !Array.isArray(data.receipts.items) ||
    data.receipts.items.length > limit ||
    !Number.isFinite(Date.parse(data.receipts.cutoff)) ||
    (data.receipts.next_cursor !== null &&
      (typeof data.receipts.next_cursor !== "string" ||
        data.receipts.next_cursor.length < 1 ||
        data.receipts.next_cursor.length > 2048 ||
        data.receipts.next_cursor === cursor)) ||
    (contract !== null &&
      (contract.instance_id !== instance.id ||
        contract.workspace_id !== instance.workspace_id ||
        contract.launch_id !== data.selected_launch_id ||
        contract.cluster_epoch !== data.cluster_epoch ||
        !decimal(contract.cpu_millis) ||
        !decimal(contract.memory_mib) ||
        !decimal(contract.generation)))
  )
    throw new ApiFailure("RESOURCE_ACCOUNTING_RESPONSE_INVALID");
  const ids = new Set<string>();
  for (const row of data.receipts.items) {
    if (
      !UUID.test(row.id) ||
      ids.has(row.id) ||
      (row.account_scope === "TENANT"
        ? row.account_project_id !== null
        : row.account_scope !== "PROJECT" ||
          row.account_project_id !== project) ||
      ![
        "amount",
        "limit_value",
        "account_version",
        "pending_value",
        "allocated_value",
      ].every((field) => decimal(row[field as keyof typeof row])) ||
      (row.generation !== null && !decimal(row.generation)) ||
      (launch !== "" &&
        (row.launch_id !== launch ||
          row.cluster_epoch !== data.cluster_epoch ||
          row.contract_id === null))
    )
      throw new ApiFailure("RESOURCE_ACCOUNTING_RESPONSE_INVALID");
    ids.add(row.id);
  }
  return data;
}

/** Read-only evidence. A quota state never stands in for measured utilization. */
export function ResourceAccounting({
  context,
  instance,
  project,
  revision,
}: {
  context: Context;
  instance: Schema["Instance"];
  project: string;
  revision: number;
}) {
  const { api, session } = context;
  const scope = `${session.tenant_id}:${session.principal_id}:${session.csrf_token}:${project}:${instance.id}:${revision}`;
  const [selection, setSelection] = useState<{
    scope: string;
    launch: string;
    cursor: string | null;
  }>({ scope, launch: "", cursor: null });
  const selected =
    selection.scope === scope ? selection : { scope, launch: "", cursor: null };
  const [draft, setDraft] = useState({ scope, value: "" });
  const [limit, setLimit] = useState(20);
  const [refresh, setRefresh] = useState(0);
  const key = `${scope}:${selected.launch}:${selected.cursor}:${limit}:${refresh}`;
  const [state, setState] = useState<{
    key: string;
    data: Accounting | null;
    error: unknown;
    loading: boolean;
  }>({ key: "", data: null, error: null, loading: true });
  useEffect(() => {
    const controller = new AbortController();
    let alive = true;
    setState({ key, data: null, error: null, loading: true });
    void (async () => {
      try {
        if (instance.project_id !== project)
          throw new ApiFailure("RESOURCE_ACCOUNTING_SCOPE_MISMATCH");
        if (selected.launch !== "" && !UUID.test(selected.launch))
          throw new ApiFailure("INVALID_LAUNCH_ID");
        const data = checkedPage(
          unwrap(
            await api.client.GET("/v1/instances/{id}/resource-accounting", {
              params: {
                path: { id: instance.id },
                header: { "X-Tenant-ID": session.tenant_id },
                query: {
                  limit,
                  ...(selected.launch ? { launch_id: selected.launch } : {}),
                  ...(selected.cursor ? { cursor: selected.cursor } : {}),
                },
              },
              signal: controller.signal,
            }),
          ),
          instance,
          project,
          selected.launch,
          limit,
          selected.cursor,
        );
        if (alive) setState({ key, data, error: null, loading: false });
      } catch (error) {
        if (alive) setState({ key, data: null, error, loading: false });
      }
    })();
    return () => {
      alive = false;
      controller.abort();
    };
  }, [
    api,
    key,
    instance.id,
    instance.workspace_id,
    instance.project_id,
    project,
    session.tenant_id,
    selected.launch,
    selected.cursor,
    limit,
  ]);
  const current = state.key === key ? state : null;
  const data = current?.data;
  return (
    <section aria-label="启动资源与释放账本">
      <h3>启动资源与释放账本</h3>
      <p className="muted">
        租户与项目是两层独立配额，逐条列示，不能相加。账本记录申请和配额状态变化；实际
        Pod 资源尚无可信回读，不提供利用率或节省比例。
      </p>
      <div className="row">
        <label className="field">
          <span>筛选启动 ID</span>
          <input
            aria-label="筛选启动 ID"
            value={draft.scope === scope ? draft.value : ""}
            placeholder="留空读取全部账本"
            onChange={(event) => setDraft({ scope, value: event.target.value })}
          />
        </label>
        <button
          onClick={() => {
            const launch = draft.scope === scope ? draft.value.trim() : "";
            setSelection({ scope, launch, cursor: null });
            setRefresh((value) => value + 1);
          }}
        >
          选择启动
        </button>
        <label className="field">
          <span>资源账本每页条数</span>
          <select
            aria-label="资源账本每页条数"
            value={limit}
            onChange={(event) => {
              setLimit(Number(event.target.value));
              setSelection({ ...selected, cursor: null });
            }}
          >
            {[1, 20, 50, 100].map((value) => (
              <option key={value} value={value}>
                {value}
              </option>
            ))}
          </select>
        </label>
        <button
          onClick={() => {
            setSelection({ ...selected, cursor: null });
            setRefresh((value) => value + 1);
          }}
        >
          资源账本第一页
        </button>
        <button
          disabled={!data?.receipts.next_cursor || current?.loading}
          onClick={() => {
            if (data?.receipts.next_cursor)
              setSelection({ ...selected, cursor: data.receipts.next_cursor });
          }}
        >
          资源账本下一页
        </button>
      </div>
      {(!current || current.loading) && <p role="status">正在读取资源账本…</p>}
      {current?.error ? (
        <p className="error" role="alert">
          {current.error instanceof ApiFailure
            ? current.error.code
            : "资源账本读取未完成，请重新读取第一页。"}
        </p>
      ) : null}
      {data && (
        <>
          <p className="mono">选中启动 {data.selected_launch_id}</p>
          <p>实际 Pod 资源：UNKNOWN · NOT_CAPTURED</p>
          {data.contract ? (
            <dl className="summary-grid" aria-label="启动申请合同">
              <div>
                <dt>申请 CPU</dt>
                <dd>{data.contract.cpu_millis} millicores</dd>
              </div>
              <div>
                <dt>申请内存</dt>
                <dd>{data.contract.memory_mib} MiB</dd>
              </div>
              <div>
                <dt>启动代次</dt>
                <dd>{data.contract.generation}</dd>
              </div>
              <div>
                <dt>来源</dt>
                <dd>{data.contract.source}</dd>
              </div>
            </dl>
          ) : (
            <p>
              启动申请：UNKNOWN ·
              HISTORY_START_NOT_CAPTURED。没有捕获历史合同，不能用当前规格补造。
            </p>
          )}
          <p className="fine">
            账本分页截止时间 {data.receipts.cutoff}；当前页{" "}
            {data.receipts.items.length} 条。
          </p>
          <div className="table-wrap">
            <table aria-label="资源配额状态记录">
              <thead>
                <tr>
                  <th>时间 / 用途</th>
                  <th>配额层级 / 维度</th>
                  <th>授权额 / 单位</th>
                  <th>状态 / 历史</th>
                  <th>账户快照</th>
                  <th>启动归属</th>
                </tr>
              </thead>
              <tbody>
                {data.receipts.items.map((row) => (
                  <tr key={row.id}>
                    <td>
                      {row.captured_at}
                      <small>{row.purpose}</small>
                    </td>
                    <td>
                      {row.account_scope === "TENANT" ? "租户配额" : "项目配额"}
                      <small>{row.dimension}</small>
                    </td>
                    <td>
                      {row.amount}
                      <small>{row.unit}</small>
                    </td>
                    <td>
                      {row.previous_status ? `${row.previous_status} → ` : ""}
                      {row.status}
                      <small>{row.history_start}</small>
                    </td>
                    <td>
                      上限 {row.limit_value}
                      <small>
                        待分配 {row.pending_value} · 已分配{" "}
                        {row.allocated_value}
                      </small>
                      <small>账户版本 {row.account_version}</small>
                    </td>
                    <td className="mono">
                      {row.launch_id ?? "UNKNOWN · 未绑定普通启动"}
                      <small>
                        {row.generation === null
                          ? "代次未知"
                          : `代次 ${row.generation}`}
                      </small>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {data.receipts.items.length === 0 && (
            <p>当前页没有已捕获的配额状态记录；不代表资源用量为零。</p>
          )}
        </>
      )}
    </section>
  );
}
