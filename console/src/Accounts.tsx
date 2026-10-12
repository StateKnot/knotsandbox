import { useEffect, useRef, useState } from "react";
import type { FormEvent, ReactNode } from "react";
import { ApiFailure, ETAG, UUID, unwrap } from "./api.ts";
import type { Schema } from "./api.ts";
import type { Context } from "./App.tsx";
import { localDate, expiry } from "./account-expiry.ts";
import { TenantAudit } from "./TenantAudit.tsx";

// 正式 1..37 的可委派集合；关闭开发模块的动作只显示历史记录。
const actions: Schema["CreateProjectGrant"]["action"][] = [
  "instances:create",
  "instances:read",
  "instances:start",
  "instances:stop",
  "instances:restart",
  "instances:renew",
  "instances:delete",
  "instances:hard_stop",
  "workspaces:read",
  "workspaces:delete",
  "operations:read",
  "events:read",
  "audit:read",
  "capabilities:read",
  "executions:create",
  "executions:read",
  "executions:cancel",
  "executions:output:read",
  "files:read",
  "files:write",
  "backups:create",
  "backups:read",
  "diagnoses:create",
  "diagnoses:read",
  "grants:read",
  "grants:write",
];

function Failure({ error }: { error: unknown }) {
  return error ? (
    <p className="error" role="alert">
      {error instanceof ApiFailure
        ? `${error.code}${error.requestId ? ` · 请求 ${error.requestId}` : ""}`
        : "请求未完成，请核对请求记录后重试"}
    </p>
  ) : null;
}

function Read({
  state,
  children,
}: {
  state: { loading: boolean; error: unknown };
  children: ReactNode;
}) {
  return (
    <>
      {state.loading && <p role="status">正在读取…</p>}
      <Failure error={state.error} />
      {children}
    </>
  );
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

function text(form: FormData, name: string, max: number) {
  const value = String(form.get(name) ?? "");
  if (
    !value ||
    [...value].length > max ||
    /[\u0000-\u001f\u007f-\u009f]/u.test(value)
  )
    throw new ApiFailure("INVALID_IDENTITY_FIELD");
  return value;
}
function oauthClient(form: FormData) {
  const value = text(form, "oauth_client_id", 256);
  // Same Unicode whitespace set as Rust str::trim; ECMAScript trim also treats
  // U+FEFF as whitespace, which is a valid exact OAuth identifier on the server.
  if (
    new TextEncoder().encode(value).length > 256 ||
    /^[\u0009-\u000d\u0020\u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]*$/u.test(
      value,
    )
  )
    throw new ApiFailure("INVALID_IDENTITY_FIELD");
  return value;
}
function etag(response: Response) {
  const value = response.headers.get("etag");
  if (!value || !ETAG.test(value))
    throw new ApiFailure("MISSING_RESOURCE_ETAG");
  return value;
}

export function Accounts({
  context,
  project,
  revision,
  busy,
}: {
  context: Context;
  project: string;
  revision: number;
  busy: boolean;
}) {
  const [clientLimit, setClientLimit] = useState(20),
    [grantLimit, setGrantLimit] = useState(20);
  const [clientCursor, setClientCursor] = useState<string | null>(null),
    [grantCursor, setGrantCursor] = useState<string | null>(null);
  const [clientId, setClientId] = useState(""),
    [grantId, setGrantId] = useState("");
  const [refreshClient, setRefreshClient] = useState(0),
    [refreshGrant, setRefreshGrant] = useState(0);
  const [pending, setPending] = useState(false),
    [error, setError] = useState<unknown>(null),
    [message, setMessage] = useState("");
  const [conflict, setConflict] = useState<string | null>(null);
  const [revoke, setRevoke] = useState(false),
    [createPermanent, setCreatePermanent] = useState(false);
  const alive = useRef(true);
  useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
    };
  }, []);
  const { api, session } = context;
  const scope = `${session.tenant_id}:${session.principal_id}:${session.csrf_token}:${project}`;
  const header = { "X-Tenant-ID": session.tenant_id };
  const clients = useRead(
    `${scope}:clients:${clientLimit}:${clientCursor}:${revision}`,
    async (signal) => {
      const result = unwrap(
        await api.client.GET("/v1/service-clients", {
          params: {
            header,
            query: {
              limit: clientLimit,
              ...(clientCursor ? { cursor: clientCursor } : {}),
            },
          },
          signal,
        }),
      );
      if (result.items.some((item) => item.tenant_id !== session.tenant_id))
        throw new ApiFailure("TENANT_MISMATCH");
      return result;
    },
  );
  const grants = useRead(
    `${scope}:grants:${grantLimit}:${grantCursor}:${revision}`,
    async (signal) => {
      if (!project) return null;
      const result = unwrap(
        await api.client.GET("/v1/projects/{id}/grants", {
          params: {
            header,
            path: { id: project },
            query: {
              limit: grantLimit,
              ...(grantCursor ? { cursor: grantCursor } : {}),
            },
          },
          signal,
        }),
      );
      if (
        result.items.some(
          (item) =>
            item.tenant_id !== session.tenant_id || item.project_id !== project,
        )
      )
        throw new ApiFailure("GRANT_SCOPE_MISMATCH");
      return result;
    },
  );
  const client = useRead(
    `${scope}:client:${clientId}:${refreshClient}`,
    async (signal) => {
      if (!clientId) return null;
      const result = await api.client.GET("/v1/service-clients/{id}", {
        params: { header, path: { id: clientId } },
        signal,
      });
      const resource = unwrap(result);
      if (resource.id !== clientId || resource.tenant_id !== session.tenant_id)
        throw new ApiFailure("TENANT_MISMATCH");
      return { resource, etag: etag(result.response) };
    },
  );
  const grant = useRead(
    `${scope}:grant:${grantId}:${refreshGrant}`,
    async (signal) => {
      if (!project || !grantId) return null;
      const result = await api.client.GET(
        "/v1/projects/{id}/grants/{grant_id}",
        {
          params: { header, path: { id: project, grant_id: grantId } },
          signal,
        },
      );
      const resource = unwrap(result);
      if (
        resource.id !== grantId ||
        resource.tenant_id !== session.tenant_id ||
        resource.project_id !== project
      )
        throw new ApiFailure("GRANT_SCOPE_MISMATCH");
      return { resource, etag: etag(result.response) };
    },
  );
  const unresolved = (path: string) =>
    context.journal
      .list(session)
      .some(
        (row) =>
          row.path === path &&
          ["READY", "PENDING", "UNKNOWN"].includes(row.state),
      );
  const disabled = busy || pending;
  const clientPath = `/v1/service-clients/${clientId}`;
  const grantPath = `/v1/projects/${project}/grants/${grantId}`;

  async function mutate(
    path: string,
    body: unknown,
    version: string | null,
    method: "POST" | "PATCH" | "DELETE",
    after?: () => void,
  ) {
    if (!alive.current) return;
    setPending(true);
    setError(null);
    setMessage("");
    try {
      api.assertActor(session);
      await context.perform(path, body, version, method);
      if (alive.current) {
        setMessage(
          "变更已确认，正在重新读取当前状态；原回执不会覆盖之后的变更。",
        );
        if (path === clientPath) setRefreshClient((n) => n + 1);
        if (path === grantPath) setRefreshGrant((n) => n + 1);
        after?.();
      }
    } catch (error) {
      if (alive.current) {
        setError(error);
        if (error instanceof ApiFailure && error.status === 412)
          setConflict(path);
        setMessage(
          "结果请到请求记录核对。UNKNOWN 只能显式重试原请求，不可重新提交。版本冲突须先重新读取，再决定是否提交新变更。",
        );
      }
    } finally {
      if (alive.current) setPending(false);
    }
  }
  function submit(
    e: FormEvent<HTMLFormElement>,
    build: (
      form: FormData,
    ) => [string, unknown, string | null, "POST" | "PATCH"],
    after?: () => void,
  ) {
    e.preventDefault();
    try {
      const request = build(new FormData(e.currentTarget));
      void mutate(...request, after);
    } catch (error) {
      setError(error);
    }
  }

  return (
    <section className="card">
      <p className="notice">
        机器身份登记只关联现有 IdP
        主体，不创建凭据或自动授予项目权限。启用状态只影响本租户；全局身份目录状态另列。项目授权仍由服务端逐次校验当前权限和到期上限。
      </p>
      <p className="fine">
        未核对请求的原参数（包含名称、签发方和主体标识）保存在当前浏览器同源请求记录中；请勿填写令牌、密钥或客户端密码。
      </p>
      <Failure error={error} />
      <p role="status">{message}</p>
      <h2>机器身份</h2>
      <div className="row">
        <label className="field">
          <span>机器身份每页条数</span>
          <select
            aria-label="机器身份每页条数"
            value={clientLimit}
            disabled={disabled}
            onChange={(e) => {
              setClientLimit(Number(e.target.value));
              setClientCursor(null);
              setClientId("");
            }}
          >
            {[1, 20, 50].map((n) => (
              <option key={n} value={n}>
                {n}
              </option>
            ))}
          </select>
        </label>
        <button
          disabled={disabled || clients.loading}
          onClick={() => {
            setClientCursor(null);
            setClientId("");
            context.changed();
          }}
        >
          机器身份第一页
        </button>
        <button
          disabled={disabled || clients.loading || !clients.data?.next_cursor}
          onClick={() => {
            setClientCursor(clients.data!.next_cursor);
            setClientId("");
          }}
        >
          机器身份下一页
        </button>
      </div>
      <Read state={clients}>
        {clients.data && (
          <div className="table-wrap">
            <table>
              <caption className="sr-only">当前租户机器身份</caption>
              <thead>
                <tr>
                  <th>名称 / 主体</th>
                  <th>租户登记</th>
                  <th>全局目录</th>
                  <th>查看</th>
                </tr>
              </thead>
              <tbody>
                {clients.data.items.map((item) => (
                  <tr key={item.id}>
                    <td>
                      {item.display_name}
                      <small className="mono">{item.principal_id}</small>
                    </td>
                    <td>{item.enabled ? "已启用" : "已禁用"}</td>
                    <td>{item.identity_enabled ? "已启用" : "已禁用"}</td>
                    <td>
                      <button
                        className="link"
                        disabled={disabled}
                        aria-label={`查看机器身份 ${item.display_name}`}
                        onClick={() => {
                          setClientId(item.id);
                          setError(null);
                        }}
                      >
                        查看
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {!clients.data.items.length && <p>当前页暂无机器身份。</p>}
          </div>
        )}
      </Read>
      <form
        className="form-grid"
        data-testid="service-client-register"
        onSubmit={(e) =>
          submit(
            e,
            (form) => [
              "/v1/service-clients",
              {
                issuer: text(form, "issuer", 2048),
                subject: text(form, "subject", 512),
                client_id: oauthClient(form),
                display_name: text(form, "display_name", 128),
              } satisfies Schema["RegisterServiceClient"],
              null,
              "POST",
            ],
            () => {
              setClientCursor(null);
            },
          )
        }
      >
        <label className="field">
          <span>OIDC签发方</span>
          <input
            name="issuer"
            aria-label="OIDC签发方"
            aria-describedby="account-issuer-help"
            type="url"
            maxLength={2048}
            autoComplete="off"
            required
          />
          <small id="account-issuer-help">须与此 API 部署配置完全一致。</small>
        </label>
        <label className="field">
          <span>主体标识</span>
          <input
            name="subject"
            aria-label="主体标识"
            aria-describedby="account-subject-help"
            maxLength={512}
            autoComplete="off"
            required
          />
          <small id="account-subject-help">
            现有服务账号的不可变 sub，由 IdP 管理员提供。
          </small>
        </label>
        <label className="field">
          <span>OAuth客户端标识</span>
          <input
            name="oauth_client_id"
            aria-label="OAuth客户端标识"
            maxLength={256}
            autoComplete="off"
            required
          />
          <small>
            须与服务 token 的 client_id 或 Keycloak azp 一致；最多 256 个 UTF-8
            字节，不能全为空白。
          </small>
        </label>
        <label className="field">
          <span>显示名称</span>
          <input name="display_name" maxLength={128} required />
        </label>
        <button
          className="primary"
          disabled={disabled || unresolved("/v1/service-clients")}
        >
          登记机器身份
        </button>
      </form>
      {clientId && clients.data && (
        <Read state={client}>
          {client.data && (
            <div data-testid="service-client-detail">
              <h3>机器身份详情</h3>
              <p className="mono">
                登记 {client.data.resource.id} · 主体{" "}
                {client.data.resource.principal_id}
              </p>
              <p className="mono">
                签发方 {client.data.resource.issuer}
                <br />
                sub {client.data.resource.subject}
                <br />
                client {client.data.resource.client_id ?? "待管理员绑定"}
              </p>
              <p>
                全局身份目录：
                {client.data.resource.identity_enabled ? "已启用" : "已禁用"}
              </p>
              <button
                disabled={disabled}
                onClick={() => {
                  setRefreshClient((n) => n + 1);
                  setConflict(null);
                  setError(null);
                }}
              >
                重新读取机器身份
              </button>
              <form
                key={`${clientId}:${client.data.etag}`}
                className="form-grid"
                onSubmit={(e) =>
                  submit(e, (form) => [
                    clientPath,
                    {
                      display_name: text(form, "display_name", 128),
                      enabled: form.has("enabled"),
                    } satisfies Schema["UpdateServiceClient"],
                    client.data!.etag,
                    "PATCH",
                  ])
                }
              >
                <label className="field">
                  <span>机器身份名称</span>
                  <input
                    name="display_name"
                    defaultValue={client.data.resource.display_name}
                    maxLength={128}
                    required
                  />
                </label>
                <label className="check">
                  <input
                    name="enabled"
                    type="checkbox"
                    defaultChecked={client.data.resource.enabled}
                  />
                  启用此租户机器身份
                </label>
                <button
                  className="primary"
                  disabled={
                    disabled ||
                    unresolved(clientPath) ||
                    conflict === clientPath
                  }
                >
                  保存机器身份
                </button>
              </form>
            </div>
          )}
        </Read>
      )}
      <hr />
      <TenantAudit context={context} revision={revision} />
      <hr />
      <h2>项目授权</h2>
      {!project ? (
        <p>选择项目后可以查看和管理该项目的授权。</p>
      ) : (
        <>
          <p className="mono">当前项目 {project}</p>
          <p className="muted">
            到期时间使用浏览器本地时区。无到期时间需要持久授权；启用或延长授权必须同时具有
            grants:write 和目标动作权限。禁用、撤销及到期记录仍保留。
          </p>
          <div className="row">
            <label className="field">
              <span>授权每页条数</span>
              <select
                aria-label="授权每页条数"
                value={grantLimit}
                disabled={disabled}
                onChange={(e) => {
                  setGrantLimit(Number(e.target.value));
                  setGrantCursor(null);
                  setGrantId("");
                  setRevoke(false);
                }}
              >
                {[1, 20, 50].map((n) => (
                  <option key={n} value={n}>
                    {n}
                  </option>
                ))}
              </select>
            </label>
            <button
              disabled={disabled || grants.loading}
              onClick={() => {
                setGrantCursor(null);
                setGrantId("");
                setRevoke(false);
                context.changed();
              }}
            >
              授权第一页
            </button>
            <button
              disabled={disabled || grants.loading || !grants.data?.next_cursor}
              onClick={() => {
                setGrantCursor(grants.data!.next_cursor);
                setGrantId("");
                setRevoke(false);
              }}
            >
              授权下一页
            </button>
          </div>
          <Read state={grants}>
            {grants.data && (
              <div className="table-wrap">
                <table>
                  <caption className="sr-only">当前项目授权</caption>
                  <thead>
                    <tr>
                      <th>主体 / 动作</th>
                      <th>状态</th>
                      <th>到期时间</th>
                      <th>查看</th>
                    </tr>
                  </thead>
                  <tbody>
                    {grants.data.items.map((item) => (
                      <tr key={item.id}>
                        <td className="mono">
                          {item.principal_id}
                          <small>{item.action}</small>
                        </td>
                        <td>
                          {item.revoked_at
                            ? "已撤销"
                            : !item.enabled
                              ? "已禁用"
                              : item.expires_at &&
                                  Date.parse(item.expires_at) <= Date.now()
                                ? "已到期"
                                : "已启用"}
                        </td>
                        <td>
                          {item.expires_at
                            ? new Date(item.expires_at).toLocaleString(
                                "zh-CN",
                                { hour12: false },
                              )
                            : "无到期时间"}
                        </td>
                        <td>
                          <button
                            className="link"
                            disabled={disabled}
                            aria-label={`查看授权 ${item.action} ${item.principal_id}`}
                            onClick={() => {
                              setGrantId(item.id);
                              setRevoke(false);
                              setError(null);
                            }}
                          >
                            查看
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {!grants.data.items.length && <p>当前页暂无项目授权。</p>}
              </div>
            )}
          </Read>
          <form
            className="form-grid"
            data-testid="grant-create"
            onSubmit={(e) =>
              submit(
                e,
                (form) => {
                  const principal = String(form.get("principal_id"));
                  const action = String(
                    form.get("action"),
                  ) as Schema["CreateProjectGrant"]["action"];
                  if (!UUID.test(principal) || !actions.includes(action))
                    throw new ApiFailure("INVALID_GRANT_TARGET");
                  return [
                    `/v1/projects/${project}/grants`,
                    {
                      principal_id: principal,
                      action,
                      expires_at: expiry(form, "permanent", "expires_at"),
                    } satisfies Schema["CreateProjectGrant"],
                    null,
                    "POST",
                  ];
                },
                () => {
                  setGrantCursor(null);
                },
              )
            }
          >
            <label className="field">
              <span>授权主体 UUID</span>
              <input
                name="principal_id"
                aria-label="授权主体 UUID"
                aria-describedby="account-principal-help"
                pattern={UUID.source}
                required
                autoComplete="off"
              />
              <small id="account-principal-help">
                须已登记在本租户，可使用上方机器身份的主体 UUID。
              </small>
            </label>
            <label className="field">
              <span>授权动作</span>
              <select name="action" aria-label="授权动作">
                {actions.map((action) => (
                  <option key={action} value={action}>
                    {action}
                  </option>
                ))}
              </select>
            </label>
            <label className="field">
              <span>授权到期时间</span>
              <input
                name="expires_at"
                type="datetime-local"
                step="0.001"
                required={!createPermanent}
                disabled={createPermanent}
              />
            </label>
            <label className="check">
              <input
                name="permanent"
                type="checkbox"
                checked={createPermanent}
                onChange={(e) => setCreatePermanent(e.target.checked)}
              />
              授权无到期时间
            </label>
            <button
              className="primary"
              disabled={
                disabled || unresolved(`/v1/projects/${project}/grants`)
              }
            >
              创建项目授权
            </button>
          </form>
          {grantId && grants.data && (
            <Read state={grant}>
              {grant.data && (
                <GrantEditor
                  key={`${grantId}:${grant.data.etag}`}
                  resource={grant.data.resource}
                  refreshingDisabled={disabled}
                  disabled={
                    disabled || unresolved(grantPath) || conflict === grantPath
                  }
                  revoke={revoke}
                  setRevoke={setRevoke}
                  refresh={() => {
                    setRefreshGrant((n) => n + 1);
                    setConflict(null);
                    setError(null);
                  }}
                  submit={(e) =>
                    submit(e, (form) => [
                      grantPath,
                      {
                        enabled: form.has("enabled"),
                        expires_at: expiry(
                          form,
                          "permanent",
                          "expires_at",
                          grant.data!.resource.expires_at,
                        ),
                      } satisfies Schema["UpdateProjectGrant"],
                      grant.data!.etag,
                      "PATCH",
                    ])
                  }
                  remove={() =>
                    void mutate(
                      grantPath,
                      null,
                      grant.data!.etag,
                      "DELETE",
                      () => setRevoke(false),
                    )
                  }
                />
              )}
            </Read>
          )}
        </>
      )}
    </section>
  );
}

function GrantEditor({
  resource,
  disabled,
  refreshingDisabled,
  revoke,
  setRevoke,
  refresh,
  submit,
  remove,
}: {
  resource: Schema["ProjectGrant"];
  disabled: boolean;
  refreshingDisabled: boolean;
  revoke: boolean;
  setRevoke: (value: boolean) => void;
  refresh: () => void;
  submit: (e: FormEvent<HTMLFormElement>) => void;
  remove: () => void;
}) {
  const [permanent, setPermanent] = useState(resource.expires_at === null);
  const immutable = !actions.includes(
    resource.action as Schema["CreateProjectGrant"]["action"],
  );
  return (
    <div data-testid="grant-detail">
      <h3>项目授权详情</h3>
      <p className="mono">
        授权 {resource.id} · 主体 {resource.principal_id} · {resource.action}
      </p>
      <button disabled={refreshingDisabled} onClick={refresh}>
        重新读取项目授权
      </button>
      {immutable ? (
        <p className="notice">
          此引导或非委派动作仅可查看，不能通过控制台修改。
        </p>
      ) : (
        <>
          <form className="form-grid" onSubmit={submit}>
            <label className="check">
              <input
                name="enabled"
                type="checkbox"
                defaultChecked={resource.enabled}
              />
              启用此项目授权
            </label>
            <label className="field">
              <span>此授权到期时间</span>
              <input
                name="expires_at"
                type="datetime-local"
                step="0.001"
                defaultValue={localDate(resource.expires_at)}
                required={!permanent}
                disabled={permanent}
              />
            </label>
            <label className="check">
              <input
                name="permanent"
                type="checkbox"
                checked={permanent}
                onChange={(e) => setPermanent(e.target.checked)}
              />
              此授权无到期时间
            </label>
            <button className="primary" disabled={disabled}>
              保存项目授权
            </button>
          </form>
          {!revoke ? (
            <button
              className="danger"
              disabled={disabled || resource.revoked_at !== null}
              onClick={() => setRevoke(true)}
            >
              撤销项目授权
            </button>
          ) : (
            <div className="notice">
              <p>
                将撤销主体 {resource.principal_id} 的 {resource.action}{" "}
                授权；记录保留。请核对当前项目和主体。
              </p>
              <div className="row">
                <button className="danger" disabled={disabled} onClick={remove}>
                  确认撤销项目授权
                </button>
                <button disabled={disabled} onClick={() => setRevoke(false)}>
                  取消撤销
                </button>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}
