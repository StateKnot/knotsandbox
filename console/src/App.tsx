import { useEffect, useMemo, useRef, useState } from "react";
import { Accounts } from "./Accounts.tsx";
import { AutomationInbox } from "./AutomationInbox.tsx";
import {
  notificationAckId,
  notificationEtag,
  notificationReceipt,
  notificationsEnabled,
  scopedNotification,
} from "./notification-inbox.ts";
import type { FormEvent, ReactNode } from "react";
import {
  ApiFailure,
  BrowserApi,
  EventStreamError,
  UUID,
  ETAG,
  unwrap,
  validateSession,
  instanceActionPath,
} from "./api.ts";
import type { Schema, Session } from "./api.ts";
import { IntentJournal, JOURNAL_SLOT } from "./journal.ts";
import type { Intent, ReceiptValidator } from "./journal.ts";
import {
  MAX_FILE_BYTES,
  sha,
  stageFile,
  verifiedDownload,
  workspacePath,
} from "./files.ts";
import {
  automationActionPath,
  automationCreatePath,
  buildCreateAutomation,
  scopedAutomation,
  scopedAutomationRun,
  isAutomationId,
  automationContract,
  automationSupports,
} from "./automation.ts";
import type { AutomationContract } from "./automation.ts";
import { runtimeMetrics, runtimeMetricUnits } from "./runtime-metrics.ts";
type Instance = Schema["Instance"];
function errorText(error: unknown) {
  return error instanceof ApiFailure
    ? `${error.code}${error.requestId ? ` · 请求 ${error.requestId}` : ""}`
    : "请求未完成，请检查连接后重试";
}
function date(value: string | null) {
  return value
    ? new Date(value).toLocaleString("zh-CN", { hour12: false })
    : "尚无观测";
}
function headers(session: Session) {
  return { "X-Tenant-ID": session.tenant_id };
}
function Badge({ value }: { value: string }) {
  return (
    <span
      className={`badge ${["RUNNING", "SUCCEEDED", "AVAILABLE", "FRESH", "COMPLETE"].includes(value) ? "good" : ["ERROR", "FAILED", "LOST", "QUARANTINED"].includes(value) ? "bad" : "neutral"}`}
    >
      {value}
    </span>
  );
}
function Json({ value }: { value: unknown }) {
  return (
    <pre className="json" tabIndex={0}>
      {JSON.stringify(value, null, 2)}
    </pre>
  );
}
function ErrorView({ error }: { error: unknown }) {
  return error ? (
    <p role="alert" className="error">
      {errorText(error)}
    </p>
  ) : null;
}
function Field({
  label,
  children,
  hint,
}: {
  label: string;
  children: ReactNode;
  hint?: string;
}) {
  return (
    <label className="field">
      <span>{label}</span>
      {children}
      {hint && <small>{hint}</small>}
    </label>
  );
}
function useRemote<T>(
  key: string,
  load: (signal: AbortSignal) => Promise<T>,
  keep = false,
) {
  const [state, set] = useState<{
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
    set((previous) => ({
      key,
      data: keep ? previous.data : null,
      error: null,
      loading: true,
    }));
    void current.current(controller.signal).then(
      (data) => {
        if (alive) set({ key, data, error: null, loading: false });
      },
      (error) => {
        if (alive) set({ key, data: null, error, loading: false });
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
function Remote({
  state,
  children,
}: {
  state: { loading: boolean; error: unknown };
  children: ReactNode;
}) {
  return (
    <>
      {state.loading && (
        <p className="muted" role="status">
          正在读取…
        </p>
      )}
      <ErrorView error={state.error} />
      {children}
    </>
  );
}
function Login({
  api,
  onSession,
}: {
  api: BrowserApi;
  onSession: (s: Session) => void;
}) {
  const [tenant, setTenant] = useState(""),
    [pending, setPending] = useState(false),
    [error, setError] = useState<unknown>(null);
  async function submit(e: FormEvent) {
    e.preventDefault();
    if (!UUID.test(tenant)) {
      setError(new ApiFailure("INVALID_TENANT_ID"));
      return;
    }
    setPending(true);
    setError(null);
    try {
      const { data } = await api.raw<Schema["BrowserLoginChallenge"]>(
        "/auth/login",
        "POST",
        { tenant_id: tenant },
      );
      const url = new URL(data.authorization_url);
      if (url.protocol !== "https:" || url.username || url.password)
        throw new ApiFailure("INVALID_IDENTITY_REDIRECT");
      location.assign(url.href);
    } catch (error) {
      setError(error);
      setPending(false);
    }
  }
  return (
    <main className="login">
      <a className="wordmark" href="/">
        ◈ SANDBOX <span>CONTROL</span>
      </a>
      <section className="login-card">
        <p className="eyebrow">企业云沙箱</p>
        <h1>进入你的工作空间</h1>
        <p className="muted">
          使用独立身份服务或企业统一身份服务登录。租户权限由服务端实时验证。
        </p>
        <form onSubmit={submit}>
          <Field label="租户 ID" hint="由管理员提供的 UUID。">
            <input
              required
              autoComplete="off"
              value={tenant}
              onChange={(e) => setTenant(e.target.value.trim())}
              placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
            />
          </Field>
          <button className="primary" disabled={pending}>
            {pending ? "正在跳转…" : "继续安全登录 →"}
          </button>
          <ErrorView error={error} />
        </form>
        <button
          className="link"
          onClick={() => {
            setPending(true);
            void api
              .raw<Session>("/auth/session")
              .then(({ data }) => onSession(data))
              .catch(setError)
              .finally(() => setPending(false));
          }}
          disabled={pending}
        >
          重新检查已有会话
        </button>
      </section>
      <p className="muted fine">
        浏览器只接收加密传输的会话 cookie。OAuth 凭证保留在服务端。
      </p>
    </main>
  );
}
export interface Context {
  api: BrowserApi;
  session: Session;
  journal: IntentJournal;
  changed: () => void;
  perform: <T>(
    path: string,
    body: unknown,
    etag: string | null,
    method?: "POST" | "PATCH" | "DELETE",
    validateReceipt?: ReceiptValidator<T>,
  ) => Promise<T>;
}
export function App() {
  const [session, setSession] = useState<Session | null>(null),
    [initial, setInitial] = useState(true),
    [authError, setAuthError] = useState<unknown>(null);
  const sessionRef = useRef(session);
  sessionRef.current = session;
  const [api] = useState(
    () => new BrowserApi(location.origin, () => setSession(null)),
  );
  const [journal] = useState(() => new IntentJournal(localStorage));
  const [projectDraft, setProjectDraft] = useState(""),
    [project, setProject] = useState(""),
    [selected, setSelected] = useState<string | null>(null),
    [revision, setRevision] = useState(0),
    [page, setPage] = useState<
      | "instances"
      | "history"
      | "requests"
      | "capabilities"
      | "accounts"
      | "notifications"
    >("instances");
  const [busy, setBusy] = useState(false),
    [notice, setNotice] = useState(""),
    [mutationError, setMutationError] = useState<unknown>(null);
  const changed = () => setRevision((v) => v + 1);
  useEffect(() => {
    const updated = (event: StorageEvent) => {
      if (
        event.storageArea === localStorage &&
        (event.key === JOURNAL_SLOT || event.key === null)
      )
        setRevision((v) => v + 1);
    };
    window.addEventListener("storage", updated);
    return () => window.removeEventListener("storage", updated);
  }, []);
  useEffect(() => {
    let alive = true;
    void api
      .raw<Session>("/auth/session")
      .then(
        ({ data }) => {
          if (alive) {
            const validated = validateSession(data);
            api.setSession(validated);
            setSession(validated);
          }
        },
        (error) => {
          if (alive && (!(error instanceof ApiFailure) || error.status !== 401))
            setAuthError(error);
        },
      )
      .catch((error) => {
        if (alive) setAuthError(error);
      })
      .finally(() => {
        if (alive) setInitial(false);
      });
    return () => {
      alive = false;
      api.cancelAll();
    };
  }, [api]);
  useEffect(() => {
    api.setSession(session);
    if (!session && !initial) {
      api.cancelAll();
      setSelected(null);
      setProject("");
      setProjectDraft("");
      setNotice("");
      setMutationError(null);
    }
  }, [api, session, initial]);
  useEffect(() => {
    journal.forgetPayloads();
  }, [
    journal,
    session?.tenant_id,
    session?.principal_id,
    session?.csrf_token,
    project,
    selected,
  ]);
  const caps = useRemote(
    project && session
      ? `${session.tenant_id}:${session.principal_id}:${session.csrf_token}:${project}:${revision}`
      : "empty",
    async (signal) =>
      project && session
        ? unwrap(
            await api.client.GET("/v1/capabilities", {
              params: {
                header: headers(session),
                query: { project_id: project },
              },
              signal,
            }),
          )
        : null,
  );
  useEffect(() => {
    const features = checkedAutomationFeatures(caps.data, project);
    if (
      (caps.data && !features.scheduled && !features.event) ||
      (!caps.loading && !caps.error && !caps.data) ||
      (caps.error instanceof ApiFailure &&
        [401, 403, 404].includes(caps.error.status ?? 0))
    )
      if (journal.forgetPayloads()) setRevision((value) => value + 1);
  }, [journal, caps.data, caps.error, caps.loading, project]);
  const list = useRemote(
    project && session
      ? `list:${session.tenant_id}:${session.principal_id}:${session.csrf_token}:${project}:${revision}`
      : "empty",
    async (signal) =>
      project && session
        ? unwrap(
            await api.client.GET("/v1/instances", {
              params: {
                header: headers(session),
                query: { project_id: project, limit: 50 },
              },
              signal,
            }),
          )
        : null,
  );
  async function perform<T>(
    path: string,
    body: unknown,
    etag: string | null,
    method: "POST" | "PATCH" | "DELETE" = "POST",
    validateReceipt?: ReceiptValidator<T>,
  ): Promise<T> {
    if (!session || busy) throw new ApiFailure("REQUEST_ALREADY_PENDING");
    const actorSession = session;
    const currentSession = () =>
      sessionRef.current?.csrf_token === actorSession.csrf_token &&
      sessionRef.current?.tenant_id === actorSession.tenant_id &&
      sessionRef.current?.principal_id === actorSession.principal_id;
    setBusy(true);
    setMutationError(null);
    let intent: Intent | null = null;
    try {
      intent = await journal.create(session, path, body, etag, method);
      if (!currentSession())
        throw new ApiFailure("BROWSER_SESSION_CHANGED", 401);
      const result = await journal.execute<T>(
        api,
        session,
        intent.key,
        validateReceipt,
      );
      if (currentSession()) {
        setNotice(
          `回执已确认 · 幂等键 ${intent.key}。请重新读取资源或操作的当前状态。`,
        );
        changed();
      }
      return result;
    } catch (error) {
      if (currentSession()) {
        setMutationError(error);
        if (intent)
          setNotice(`请求 ${intent.key} 已记录，请在“请求记录”中核对结果。`);
        changed();
      }
      throw error;
    } finally {
      setBusy(false);
    }
  }
  async function logout() {
    setBusy(true);
    api.cancelAll();
    try {
      await api.raw("/auth/logout", "POST");
      api.setSession(null);
      setSession(null);
      setAuthError(null);
    } catch (error) {
      setMutationError(error);
      setNotice("退出尚未确认，请重试退出。");
    } finally {
      setBusy(false);
    }
  }
  if (initial)
    return (
      <main className="login">
        <p role="status">正在验证安全会话…</p>
      </main>
    );
  if (!session)
    return (
      <>
        <ErrorView error={authError} />
        <Login
          api={api}
          onSession={(s) => {
            api.setSession(s);
            setSession(s);
            setAuthError(null);
          }}
        />
      </>
    );
  const context: Context = { api, session, journal, changed, perform };
  return (
    <div className="shell">
      <aside>
        <a className="wordmark" href="/">
          ◈ SANDBOX <span>CONTROL</span>
        </a>
        <p className="eyebrow sidebar-label">资源管理</p>
        <nav aria-label="主导航">
          {(
            [
              ["instances", "实例"],
              ["history", "操作 / 事件 / 审计"],
              ["requests", "请求记录"],
              ["capabilities", "服务能力"],
              ["accounts", "账户与授权"],
              ["notifications", "自动化通知"],
            ] as const
          ).map(([id, label]) => (
            <button
              key={id}
              className={page === id ? "nav active" : "nav"}
              aria-current={page === id ? "page" : undefined}
              onClick={() => setPage(id)}
            >
              {label}
            </button>
          ))}
        </nav>
        <div className="sidebar-footer">
          <span className="live-dot" />
          服务端实时鉴权<p className="fine">租户 {session.tenant_id}</p>
        </div>
      </aside>
      <div className="content">
        <header>
          <div>
            <p className="eyebrow">CLOUD SANDBOX</p>
            <h1>
              {page === "instances"
                ? "实例控制台"
                : page === "history"
                  ? "可追溯记录"
                  : page === "requests"
                    ? "请求记录"
                    : page === "accounts"
                      ? "账户与项目授权"
                      : page === "notifications"
                        ? "自动化异常通知"
                        : "服务能力"}
            </h1>
          </div>
          <div className="header-actions">
            <span className="fine">
              会话最长至 {date(session.absolute_expires_at)}
            </span>
            <button disabled={busy} onClick={logout}>
              退出
            </button>
          </div>
        </header>
        <form
          className="project-bar"
          onSubmit={(e) => {
            e.preventDefault();
            if (UUID.test(projectDraft)) {
              setProject(projectDraft);
              setSelected(null);
              setNotice("");
              setMutationError(null);
            } else setMutationError(new ApiFailure("INVALID_PROJECT_ID"));
          }}
        >
          <Field label="项目 ID">
            <input
              autoComplete="off"
              required
              value={projectDraft}
              placeholder="管理员分配的项目 UUID"
              onChange={(e) => setProjectDraft(e.target.value.trim())}
            />
          </Field>
          <button className="primary" disabled={busy}>
            进入项目
          </button>
          <button type="button" disabled={!project || busy} onClick={changed}>
            刷新
          </button>
        </form>
        <div aria-live="polite">
          {notice && <p className="notice">{notice}</p>}
        </div>
        <ErrorView error={mutationError} />
        {page === "accounts" ? (
          <Accounts
            key={`${session.tenant_id}:${session.principal_id}:${session.csrf_token}:${project}`}
            context={context}
            project={project}
            revision={revision}
            busy={busy}
          />
        ) : page === "requests" ? (
          <Requests
            key={`${session.tenant_id}:${session.principal_id}:${session.csrf_token}:${project}`}
            context={context}
            project={project}
            revision={revision}
            caps={caps.data}
            capsLoading={caps.loading}
            capsError={caps.error}
          />
        ) : !project ? (
          <section className="empty">
            <span>◈</span>
            <h2>选择项目以查看资源</h2>
            <p>输入已授权项目的 ID。API 会校验当前成员和项目权限。</p>
          </section>
        ) : (
          <>
            {page === "notifications" && (
              <AutomationInbox
                key={`${session.tenant_id}:${session.principal_id}:${session.csrf_token}:${project}`}
                context={context}
                project={project}
                revision={revision}
                caps={caps.data}
                capsLoading={caps.loading}
                capsError={caps.error}
              />
            )}
            {page === "instances" && (
              <>
                <div className="section-heading">
                  <div>
                    <h2>实例</h2>
                    <p className="muted">
                      实际观测状态与目标状态分别显示。租期结束后，计算资源将进入安全停止流程。
                    </p>
                  </div>
                </div>
                <Remote state={list}>
                  {list.data && (
                    <>
                      <InstanceTable
                        items={list.data.items}
                        select={setSelected}
                      />
                      {list.data.next_after && (
                        <InstanceNext
                          context={context}
                          project={project}
                          after={list.data.next_after}
                          select={setSelected}
                        />
                      )}
                    </>
                  )}
                </Remote>
                {caps.data && (
                  <CreateInstance
                    context={context}
                    project={project}
                    caps={caps.data}
                  />
                )}
                <Remote state={caps}>{null}</Remote>
                {selected && (
                  <InstancePane
                    key={`${session.tenant_id}:${session.principal_id}:${session.csrf_token}:${selected}:${project}`}
                    context={context}
                    id={selected}
                    project={project}
                    revision={revision}
                    caps={caps.data}
                    capsLoading={caps.loading}
                    capsError={caps.error}
                  />
                )}
              </>
            )}
            {page === "history" && (
              <History
                key={`${session.tenant_id}:${session.principal_id}:${session.csrf_token}:${project}:${selected ?? ""}`}
                context={context}
                project={project}
                instance={selected}
              />
            )}
            {page === "capabilities" && (
              <Remote state={caps}>
                {caps.data && (
                  <section className="card">
                    <h2>当前部署能力</h2>
                    <p className="muted">
                      以下为真实 API
                      配置。能力开启不代表依赖健康、隔离认证或当前调用者具有权限。
                    </p>
                    <dl className="feature-list">
                      {Object.entries(caps.data.api_features ?? {}).map(
                        ([name, enabled]) => (
                          <div key={name}>
                            <dt>{name}</dt>
                            <dd>
                              <Badge
                                value={
                                  enabled === true ? "ENABLED" : "UNAVAILABLE"
                                }
                              />
                            </dd>
                          </div>
                        ),
                      )}
                    </dl>
                    <Json
                      value={{
                        limits: caps.data.limits,
                        flavors: caps.data.flavors,
                        runtime_certification: caps.data.runtime_certification,
                        build_version: caps.data.build_version,
                      }}
                    />
                  </section>
                )}
              </Remote>
            )}
          </>
        )}
        <footer>
          Sandbox Platform · 所有资源操作均进入服务端权限校验与审计
        </footer>
      </div>
    </div>
  );
}
function InstanceTable({
  items,
  select,
}: {
  items: Instance[];
  select: (id: string) => void;
}) {
  return items.length ? (
    <div className="table-wrap">
      <table>
        <caption className="sr-only">项目实例及观测状态</caption>
        <thead>
          <tr>
            <th>实例 / ID</th>
            <th>实际状态</th>
            <th>目标状态</th>
            <th>资源</th>
            <th>计算租期</th>
            <th>观测时间</th>
          </tr>
        </thead>
        <tbody>
          {items.map((i) => (
            <tr key={i.id}>
              <td>
                <button className="link" onClick={() => select(i.id)}>
                  {i.name}
                </button>
                <small className="mono">{i.id}</small>
              </td>
              <td>
                <Badge value={i.observed_state} />
              </td>
              <td>{i.desired_state}</td>
              <td>
                {i.cpu_millis / 1000} vCPU · {i.memory_mib / 1024} GiB
              </td>
              <td>{date(i.compute_lease_expires_at)}</td>
              <td>{date(i.observed_at)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  ) : (
    <section className="empty">
      <h3>项目中暂无实例</h3>
      <p>创建实例后，等待操作完成再使用。</p>
    </section>
  );
}
function InstanceNext({
  context,
  project,
  after,
  select,
}: {
  context: Context;
  project: string;
  after: string;
  select: (id: string) => void;
}) {
  const [cursor, setCursor] = useState<string | null>(null);
  const page = useRemote(cursor ?? "not-loaded", async (signal) =>
    cursor
      ? unwrap(
          await context.api.client.GET("/v1/instances", {
            params: {
              header: headers(context.session),
              query: { project_id: project, limit: 50, after: cursor },
            },
            signal,
          }),
        )
      : null,
  );
  return (
    <>
      <Remote state={page}>
        {page.data && <InstanceTable items={page.data.items} select={select} />}
      </Remote>
      <button
        disabled={page.loading}
        onClick={() => setCursor(page.data?.next_after ?? after)}
      >
        读取下一页
      </button>
    </>
  );
}
function CreateInstance({
  context,
  project,
  caps,
}: {
  context: Context;
  project: string;
  caps: Schema["Capabilities"];
}) {
  const [open, setOpen] = useState(false),
    [pending, setPending] = useState(false),
    [error, setError] = useState<unknown>(null);
  async function submit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const data = new FormData(e.currentTarget);
    setPending(true);
    setError(null);
    try {
      await context.perform(
        "/v1/instances",
        {
          project_id: project,
          name: String(data.get("name")),
          template_version_id: String(data.get("template")),
          security_profile_id: String(data.get("security")),
          flavor: String(data.get("flavor")),
          workspace: { size_gib: Number(data.get("size")) },
          ttl_seconds: Number(data.get("ttl")),
        },
        null,
      );
      setOpen(false);
    } catch (error) {
      setError(error);
    } finally {
      setPending(false);
    }
  }
  return (
    <section className="card compact">
      <button
        className="primary"
        onClick={() => setOpen((v) => !v)}
        disabled={caps.api_features?.instance_lifecycle !== true}
      >
        ＋ 创建实例
      </button>
      {open && (
        <form onSubmit={submit} className="form-grid">
          <Field label="实例名称">
            <input
              name="name"
              required
              pattern="[a-z0-9](?:[a-z0-9-]*[a-z0-9])?"
              maxLength={63}
            />
          </Field>
          <Field label="已批准模板版本 ID">
            <input name="template" required pattern={UUID.source} />
          </Field>
          <Field label="已批准安全策略版本 ID">
            <input name="security" required pattern={UUID.source} />
          </Field>
          <Field label="规格">
            <select name="flavor">
              {caps.flavors.map((f) => (
                <option key={f.name} value={f.name}>
                  {f.name}
                </option>
              ))}
            </select>
          </Field>
          <Field label="工作区 GiB">
            <input
              name="size"
              type="number"
              required
              min={20}
              max={1024}
              defaultValue={20}
            />
          </Field>
          <Field label="计算租期（秒）">
            <input
              name="ttl"
              type="number"
              required
              min={60}
              max={86400}
              defaultValue={3600}
            />
          </Field>
          <div className="wide">
            <p className="muted">
              模板和策略 ID
              必须由管理员批准；创建请求仍会校验实时配额和项目策略。
            </p>
            <button disabled={pending} className="primary">
              {pending ? "正在受理…" : "提交创建请求"}
            </button>
            <ErrorView error={error} />
          </div>
        </form>
      )}
    </section>
  );
}
function Confirm({
  label,
  target,
  children,
  run,
  disabled = false,
}: {
  label: string;
  target: string;
  children: ReactNode;
  run: () => Promise<unknown>;
  disabled?: boolean;
}) {
  const dialog = useRef<HTMLDialogElement>(null);
  const [typed, setTyped] = useState(""),
    [pending, setPending] = useState(false),
    [error, setError] = useState<unknown>(null);
  return (
    <>
      <button
        className="danger"
        disabled={disabled}
        onClick={() => {
          setTyped("");
          setError(null);
          dialog.current?.showModal();
        }}
      >
        {label}
      </button>
      <dialog
        ref={dialog}
        onCancel={(e) => {
          if (pending) e.preventDefault();
        }}
      >
        <form
          onSubmit={async (e) => {
            e.preventDefault();
            if (typed !== target || disabled || pending) return;
            setPending(true);
            try {
              await run();
              dialog.current?.close();
            } catch (error) {
              setError(error);
            } finally {
              setPending(false);
            }
          }}
        >
          <h2>{label}</h2>
          {children}
          <Field label={`输入 ${target} 确认`}>
            <input
              value={typed}
              autoComplete="off"
              autoFocus
              onChange={(e) => setTyped(e.target.value)}
            />
          </Field>
          <div className="row">
            <button
              type="button"
              disabled={pending}
              onClick={() => dialog.current?.close()}
            >
              取消
            </button>
            <button
              className="danger"
              disabled={typed !== target || pending || disabled}
            >
              {pending ? "正在提交…" : "确认提交"}
            </button>
          </div>
          <ErrorView error={error} />
        </form>
      </dialog>
    </>
  );
}
function InstancePane({
  context,
  id,
  project,
  revision,
  caps,
  capsLoading,
  capsError,
}: {
  context: Context;
  id: string;
  revision: number;
  project: string;
  caps: Schema["Capabilities"] | null;
  capsLoading: boolean;
  capsError: unknown;
}) {
  const automation = useAutomationFeatures(
    caps,
    capsLoading,
    capsError,
    project,
  );
  const [tab, setTab] = useState("details");
  const detail = useRemote(
    `${id}:${revision}`,
    async (signal) =>
      unwrap(
        await context.api.client.GET("/v1/instances/{id}/details", {
          params: { header: headers(context.session), path: { id } },
          signal,
        }),
      ),
    true,
  );
  const instance = detail.data?.instance;
  return (
    <section className="card instance-pane">
      <div className="section-heading">
        <div>
          <p className="eyebrow">INSTANCE DETAILS</p>
          <h2>{instance?.name ?? "实例详情"}</h2>
          <p className="mono muted">{id}</p>
        </div>
        <button onClick={context.changed}>刷新详情</button>
      </div>
      <Remote state={detail}>
        {detail.data && (
          <>
            <div className="summary-grid">
              <div>
                <small>实际状态</small>
                <Badge value={detail.data.instance.observed_state} />
              </div>
              <div>
                <small>计算租期</small>
                <strong>
                  {detail.data.compute_lease.remaining_seconds} 秒
                </strong>
              </div>
              <div>
                <small>工作区</small>
                <strong>
                  {detail.data.workspace.size_gib} GiB ·{" "}
                  {detail.data.workspace.status}
                </strong>
              </div>
              <div>
                <small>持续健康观测</small>
                <strong>{detail.data.runtime_health.status}</strong>
              </div>
            </div>
            <p className="muted fine">
              快照 {date(detail.data.as_of)} · 持续运行健康{" "}
              尚未配置持续健康观测，不能据此判断实例当前运行健康。
            </p>
            <div className="tabs" role="tablist" aria-label="实例信息">
              {[
                ["details", "详情与安全"],
                ["security", "安全防护"],
                ["metrics", "监控"],
                ["execute", "执行与输出"],
                ["files", "文件"],
                ["diagnosis", "健康诊断"],
                ["backup", "备份"],
                ["automation", "定时与自动化"],
              ].map(([value, label]) => (
                <button
                  key={value}
                  id={`tab-${value}`}
                  role="tab"
                  aria-selected={tab === value}
                  tabIndex={tab === value ? 0 : -1}
                  onKeyDown={(e) => {
                    if (
                      !["ArrowLeft", "ArrowRight", "Home", "End"].includes(
                        e.key,
                      )
                    )
                      return;
                    e.preventDefault();
                    const buttons = [
                      ...e.currentTarget.parentElement!.querySelectorAll<HTMLButtonElement>(
                        '[role="tab"]',
                      ),
                    ];
                    const current = buttons.indexOf(e.currentTarget);
                    const next =
                      e.key === "Home"
                        ? 0
                        : e.key === "End"
                          ? buttons.length - 1
                          : (current +
                              (e.key === "ArrowRight" ? 1 : -1) +
                              buttons.length) %
                            buttons.length;
                    buttons[next]!.click();
                    buttons[next]!.focus();
                  }}
                  aria-controls={`panel-${value}`}
                  onClick={() => setTab(value!)}
                >
                  {label}
                </button>
              ))}
            </div>
            {tab !== "diagnosis" && tab !== "automation" && (
              <div
                role="tabpanel"
                id={`panel-${tab}`}
                aria-labelledby={`tab-${tab}`}
                tabIndex={0}
              >
                {tab === "details" && (
                  <>
                    <Lifecycle
                      context={context}
                      instance={detail.data.instance}
                    />
                    <div className="detail-grid">
                      <section>
                        <h3>安全策略</h3>
                        <dl>
                          <dt>策略</dt>
                          <dd>{detail.data.security_policy.name}</dd>
                          <dt>版本</dt>
                          <dd>{detail.data.security_policy.version}</dd>
                          <dt>批准状态</dt>
                          <dd>
                            <Badge value={detail.data.security_policy.status} />
                          </dd>
                        </dl>
                        <h3>模板</h3>
                        <dl>
                          <dt>名称</dt>
                          <dd>{detail.data.template.name}</dd>
                          <dt>版本</dt>
                          <dd>{detail.data.template.version}</dd>
                          <dt>批准状态</dt>
                          <dd>
                            <Badge value={detail.data.template.status} />
                          </dd>
                        </dl>
                      </section>
                      <section>
                        <h3>当前启动验证</h3>
                        <dl>
                          <dt>验证结果</dt>
                          <dd>
                            {detail.data.launch_readiness.status ===
                            "VERIFIED_CURRENT_LAUNCH"
                              ? "已验证当前启动"
                              : "当前启动尚未验证"}
                          </dd>
                          <dt>验证时间</dt>
                          <dd>
                            {date(detail.data.launch_readiness.verified_at)}
                          </dd>
                          <dt>匹配当前运行代次</dt>
                          <dd>
                            {detail.data.launch_readiness.matches_current_launch
                              ? "是"
                              : "未确认"}
                          </dd>
                          <dt>匹配当前集群代次</dt>
                          <dd>
                            {detail.data.launch_readiness
                              .matches_current_cluster_epoch
                              ? "是"
                              : "未确认"}
                          </dd>
                        </dl>
                        <h3>生命周期观测</h3>
                        <dl>
                          <dt>实际状态</dt>
                          <dd>
                            <Badge
                              value={detail.data.instance.observed_state}
                            />
                          </dd>
                          <dt>最近观测时间</dt>
                          <dd>{date(detail.data.instance.observed_at)}</dd>
                        </dl>
                      </section>
                    </div>
                    <details>
                      <summary>技术证据：实例、工作区、模板与启动观测</summary>
                      <Json value={detail.data} />
                    </details>
                  </>
                )}
                {tab === "security" && (
                  <SecurityPanel
                    context={context}
                    id={id}
                    revision={revision}
                    enabled={caps?.api_features?.instance_security === true}
                  />
                )}
                {tab === "metrics" && (
                  <Metrics
                    context={context}
                    id={id}
                    enabled={caps?.api_features?.runtime_metrics === true}
                  />
                )}
                {tab === "execute" && (
                  <ExecutionPanel
                    context={context}
                    instance={detail.data.instance}
                    revision={revision}
                  />
                )}
                {tab === "files" && (
                  <FilesPanel
                    context={context}
                    instance={detail.data.instance}
                    revision={revision}
                    enabled={caps?.api_features?.file_transfer === true}
                  />
                )}
                {tab === "backup" && (
                  <BackupPanel
                    context={context}
                    instance={detail.data.instance}
                    revision={revision}
                    enabled={
                      caps?.project_id === project &&
                      caps?.api_features?.backup_restore === true
                    }
                  />
                )}
              </div>
            )}
          </>
        )}
      </Remote>
      {tab === "automation" && (
        <div
          role="tabpanel"
          id="panel-automation"
          aria-labelledby="tab-automation"
          tabIndex={0}
        >
          <AutomationPanel
            key={`${automation.features.scheduled}:${automation.features.event}`}
            context={context}
            id={id}
            project={project}
            features={automation.features}
            blocked={automation.blocked}
          />
        </div>
      )}
      {tab === "diagnosis" && (
        <div
          role="tabpanel"
          id="panel-diagnosis"
          aria-labelledby="tab-diagnosis"
          tabIndex={0}
        >
          <DiagnosisPanel
            context={context}
            id={id}
            project={project}
            revision={revision}
            enabled={caps?.api_features?.control_plane_diagnoses === true}
          />
        </div>
      )}
    </section>
  );
}
const SECURITY_FINDINGS: Record<
  Schema["InstanceSecurity"]["findings"][number],
  string
> = {
  TEMPLATE_NOT_APPROVED: "绑定模板未获批准",
  SECURITY_POLICY_NOT_APPROVED: "绑定安全策略未获批准",
  POLICY_DOCUMENT_UNAVAILABLE: "策略文档摘要不可用",
  POLICY_PROFILE_UNSUPPORTED: "策略超出当前支持的隔离配置",
  HISTORICAL_CLUSTER_EPOCH: "实例属于历史集群代次",
  PLATFORM_SAFE_MODE: "平台处于安全模式",
  COMPUTE_LEASE_EXPIRED: "计算租期已到期",
  COMPUTE_NO_LONGER_DESIRED: "实例当前不要求运行",
  WORKSPACE_UNAVAILABLE: "工作区当前不可用",
};
function SecurityPanel({
  context,
  id,
  revision,
  enabled,
}: {
  context: Context;
  id: string;
  revision: number;
  enabled: boolean;
}) {
  const result = useRemote(`${id}:${revision}:${enabled}`, async (signal) =>
    enabled
      ? unwrap(
          await context.api.client.GET("/v1/instances/{id}/security", {
            params: { header: headers(context.session), path: { id } },
            signal,
          }),
        )
      : null,
  );
  if (!enabled) return <p className="muted">当前部署未提供安全详情。</p>;
  const value = result.data;
  return (
    <Remote state={result}>
      {value && (
        <>
          <p className="muted fine">
            安全配置快照 {date(value.as_of)} · 期望配置与运行验证分别展示。
          </p>
          <div className="summary-grid">
            <div>
              <small>网络策略是否生效</small>
              <strong>暂无独立验证</strong>
            </div>
            <div>
              <small>运行时隔离</small>
              <strong>暂无独立验证</strong>
            </div>
            <div>
              <small>镜像验证</small>
              <strong>暂无独立验证</strong>
            </div>
            <div>
              <small>拒绝记录</small>
              <strong>尚未采集</strong>
            </div>
          </div>
          <p className="muted">
            模板批准、对象记录和历史启动验证不能证明当前隔离已生效。
          </p>
          <div className="detail-grid">
            <section>
              <h3>期望安全配置</h3>
              <dl>
                <dt>安全策略</dt>
                <dd>
                  {value.desired.security_policy.name} · 版本{" "}
                  {value.desired.security_policy.version}
                </dd>
                <dt>批准状态</dt>
                <dd>
                  <Badge value={value.desired.security_policy.status} />
                </dd>
                <dt>支持的网络配置</dt>
                <dd>
                  {value.desired.security_policy.profile === "DENY_ALL_WITH_DNS"
                    ? "默认拒绝，仅允许受控 DNS"
                    : "未确认受支持的配置"}
                </dd>
                <dt>运行时</dt>
                <dd>{value.desired.runtime_controls.runtime_class}</dd>
                <dt>执行用户</dt>
                <dd>非 root · UID {value.desired.runtime_controls.user_id}</dd>
                <dt>根文件系统</dt>
                <dd>只读</dd>
                <dt>权限约束</dt>
                <dd>禁止特权与提权；移除全部 capabilities</dd>
                <dt>宿主命名空间</dt>
                <dd>不共享网络、PID 或 IPC</dd>
                <dt>服务账户令牌</dt>
                <dd>不挂载</dd>
                <dt>镜像摘要</dt>
                <dd className="mono">{value.desired.template.image_digest}</dd>
                <dt>策略内容摘要</dt>
                <dd className="mono">
                  {value.desired.security_policy.rules_sha256 ?? "不可用"}
                </dd>
              </dl>
            </section>
            <section>
              <h3>已有观测记录</h3>
              <dl>
                <dt>策略对象</dt>
                <dd>
                  {value.observations.policy_object.status === "RECORDED"
                    ? "账本已记录对象"
                    : "尚无可用对象记录"}
                </dd>
                <dt>记录时间</dt>
                <dd>{date(value.observations.policy_object.observed_at)}</dd>
                <dt>对象记录代次</dt>
                <dd>
                  {value.observations.policy_object.recorded_generation ??
                    "尚无记录"}
                </dd>
                <dt>历史启动验证</dt>
                <dd>
                  {value.observations.launch_validation.status ===
                  "HISTORICAL_RECORDED"
                    ? "已有历史记录"
                    : "尚无可用历史记录"}
                </dd>
                <dt>匹配当前启动</dt>
                <dd>
                  {value.observations.launch_validation.matches_current_launch
                    ? "是"
                    : "未确认"}
                </dd>
                <dt>匹配当前集群代次</dt>
                <dd>
                  {value.observations.launch_validation
                    .matches_current_cluster_epoch
                    ? "是"
                    : "未确认"}
                </dd>
                <dt>控制面节点授权</dt>
                <dd>
                  {value.observations.node_authorization.status ===
                  "COVERS_COMPUTE_LEASE"
                    ? "授权期限覆盖计算租期"
                    : value.observations.node_authorization.status ===
                        "EXPIRED_OR_INSUFFICIENT"
                      ? "授权已过期或不足"
                      : "尚无可用授权记录"}
                </dd>
                <dt>授权截止</dt>
                <dd>
                  {date(value.observations.node_authorization.valid_until)}
                </dd>
              </dl>
              <h3>当前守卫检查</h3>
              {value.findings.length ? (
                <ul>
                  {value.findings.map((code) => (
                    <li key={code}>{SECURITY_FINDINGS[code]}</li>
                  ))}
                </ul>
              ) : (
                <p className="muted">
                  未发现当前守卫阻断项；独立运行验证仍未知。
                </p>
              )}
              <h3>关联操作</h3>
              {value.active_operation.state === "REDACTED" ? (
                <p className="muted">无当前操作详情权限。</p>
              ) : value.active_operation.resource ? (
                <p>
                  {value.active_operation.resource.kind} ·{" "}
                  {value.active_operation.resource.status}
                  {value.active_operation.resource.error
                    ? ` · ${value.active_operation.resource.error.code}`
                    : ""}
                </p>
              ) : (
                <p className="muted">
                  {value.active_operation.state === "NONE"
                    ? "当前无关联操作。"
                    : "当前操作记录不可用。"}
                </p>
              )}
            </section>
          </div>
          <details>
            <summary>安全详情与证据</summary>
            <Json value={value} />
          </details>
        </>
      )}
    </Remote>
  );
}
function Lifecycle({
  context,
  instance,
}: {
  context: Context;
  instance: Instance;
}) {
  const [renew, setRenew] = useState(""),
    [error, setError] = useState<unknown>(null);
  const etag = `"${instance.spec_version}"`;
  async function start() {
    try {
      await context.perform(instanceActionPath(instance.id, "start"), {}, etag);
    } catch (error) {
      setError(error);
    }
  }
  return (
    <section className="lifecycle">
      <h3>生命周期管理</h3>
      <div className="row">
        <button className="primary" onClick={start}>
          启动
        </button>
        <Confirm
          label="停止实例"
          target={instance.name}
          run={() =>
            context.perform(instanceActionPath(instance.id, "stop"), {}, etag)
          }
        >
          <p>停止计算实例并保留工作区。停止受理后仍需等待可信运行环境确认。</p>
        </Confirm>
        <Confirm
          label="重启实例"
          target={instance.name}
          run={() =>
            context.perform(
              instanceActionPath(instance.id, "restart"),
              {},
              etag,
            )
          }
        >
          <p>当前进程会被终止；运行中的执行和文件操作可能无法完成。</p>
        </Confirm>
        <Confirm
          label="删除实例"
          target={instance.name}
          run={() =>
            context.perform(`/v1/instances/${instance.id}`, {}, etag, "DELETE")
          }
        >
          <p>删除计算实例。工作区有独立生命周期，请核对保留期限和备份。</p>
        </Confirm>
      </div>
      <form
        className="row"
        onSubmit={async (e) => {
          e.preventDefault();
          try {
            await context.perform(
              instanceActionPath(instance.id, "renew"),
              { expires_at: new Date(renew).toISOString() },
              etag,
            );
          } catch (error) {
            setError(error);
          }
        }}
      >
        <Field label="续期至本地时间">
          <input
            type="datetime-local"
            required
            value={renew}
            onChange={(e) => setRenew(e.target.value)}
          />
        </Field>
        <button>提交续期</button>
      </form>
      <p className="fine muted">
        当前版本 {instance.spec_version} · 有并发变更时 API 返回
        412，请刷新后重新核对。
      </p>
      <ErrorView error={error} />
    </section>
  );
}
function Metrics({
  context,
  id,
  enabled,
}: {
  context: Context;
  id: string;
  enabled: boolean;
}) {
  const [metric, setMetric] = useState<Schema["RuntimeMetric"]>("VM_CPU_CORES"),
    [revision, setRevision] = useState(0);
  const result = useRemote(
    `${id}:${metric}:${revision}:${enabled}`,
    async (signal) => {
      if (!enabled) return null;
      const end = new Date(),
        start = new Date(end.getTime() - 15 * 60000);
      return unwrap(
        await context.api.client.GET("/v1/instances/{id}/metrics", {
          params: {
            header: headers(context.session),
            path: { id },
            query: {
              metric,
              start: start.toISOString(),
              end: end.toISOString(),
              step_seconds: 15,
            },
          },
          signal,
        }),
      );
    },
  );
  if (!enabled)
    return (
      <p className="notice">
        当前部署未开启运行时指标。请由管理员配置独立指标读取服务。
      </p>
    );
  const points = result.data?.series.points ?? [];
  const fresh = points.filter((p) => p.status === "FRESH" && p.value !== null);
  const max = Math.max(1, ...fresh.map((p) => p.value ?? 0));
  return (
    <section>
      <div className="row">
        <Field label="指标">
          <select
            value={metric}
            onChange={(e) =>
              setMetric(e.target.value as Schema["RuntimeMetric"])
            }
          >
            {Object.entries(runtimeMetrics).map(([value, info]) => (
              <option key={value} value={value}>
                {info.label}
              </option>
            ))}
          </select>
        </Field>
        <button onClick={() => setRevision((v) => v + 1)}>
          查询最近 15 分钟
        </button>
      </div>
      <p className="fine muted">{runtimeMetrics[metric].description}</p>
      <p className="fine muted">
        缺失、过期或当前节点不支持的指标保留为空，不代表用量为零。
      </p>
      <Remote state={result}>
        {result.data && (
          <>
            <p className="muted">
              单位 {runtimeMetricUnits[result.data.series.unit]}（
              {result.data.series.unit}） · 数据源 {result.data.series.source} ·
              查询 {date(result.data.queried_at)}
            </p>
            <svg
              className="metric-chart"
              viewBox="0 0 800 180"
              role="img"
              aria-label={`${runtimeMetrics[metric].label}；最近15分钟指标；缺失或过期数据留空`}
            >
              <line
                x1="0"
                x2="800"
                y1="160"
                y2="160"
                stroke="currentColor"
                opacity=".2"
              />
              {points.map((p, index) =>
                p.status === "FRESH" && p.value !== null ? (
                  <circle
                    key={index}
                    cx={
                      points.length < 2
                        ? 400
                        : (index / (points.length - 1)) * 800
                    }
                    cy={160 - (p.value / max) * 140}
                    r="2.5"
                    fill="currentColor"
                  />
                ) : null,
              )}
            </svg>
            <div className="table-wrap">
              <table>
                <caption>指标观测明细（最近 20 个点）</caption>
                <thead>
                  <tr>
                    <th>计算时间</th>
                    <th>实际观测时间</th>
                    <th>数值</th>
                    <th>状态</th>
                    <th>采集副本</th>
                  </tr>
                </thead>
                <tbody>
                  {points.slice(-20).map((p, i) => (
                    <tr key={i}>
                      <td>{date(p.evaluated_at)}</td>
                      <td>{date(p.observed_at)}</td>
                      <td>{p.value ?? "—"}</td>
                      <td>
                        <Badge value={p.status} />
                      </td>
                      <td>{p.collector_replica ?? "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {!points.length && (
              <p className="notice">当前启动没有可用指标点。</p>
            )}
          </>
        )}
      </Remote>
    </section>
  );
}
function ExecutionPanel({
  context,
  instance,
  revision,
}: {
  context: Context;
  instance: Instance;
  revision: number;
}) {
  const [argv, setArgv] = useState(""),
    [executionId, setExecutionId] = useState(""),
    [lookup, setLookup] = useState(""),
    [error, setError] = useState<unknown>(null),
    [pending, setPending] = useState(false);
  const execution = useRemote(`${executionId}:${revision}`, async (signal) =>
    executionId
      ? unwrap(
          await context.api.client.GET("/v1/executions/{id}", {
            params: {
              header: headers(context.session),
              path: { id: executionId },
            },
            signal,
          }),
        )
      : null,
  );
  async function submit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setPending(true);
    setError(null);
    const form = new FormData(e.currentTarget);
    try {
      const value: unknown = JSON.parse(argv);
      if (
        !Array.isArray(value) ||
        !value.length ||
        value.some((v) => typeof v !== "string") ||
        value.length > 64
      )
        throw new ApiFailure("INVALID_ARGV");
      const receipt = await context.perform<{ resource: Schema["Execution"] }>(
        `/v1/instances/${instance.id}/executions`,
        {
          argv: value,
          public_env: {},
          cwd: String(form.get("cwd")),
          timeout_seconds: Number(form.get("timeout")),
          output_limit_bytes: Number(form.get("output")),
          on_timeout: "HARD_STOP_INSTANCE",
        },
        `"${instance.spec_version}"`,
      );
      setExecutionId(receipt.resource.id);
      setLookup(receipt.resource.id);
    } catch (error) {
      setError(error);
    } finally {
      setPending(false);
    }
  }
  return (
    <section>
      <h3>执行命令</h3>
      <p className="notice">
        argv
        与环境必须不含秘密；参数存入私有操作记录。超时或取消将申请终止整个实例。结果未知时不得重新执行。
      </p>
      <form className="form-grid" onSubmit={submit}>
        <Field label="argv JSON 数组">
          <textarea
            rows={4}
            required
            value={argv}
            placeholder='["可执行程序", "非敏感参数"]'
            onChange={(e) => setArgv(e.target.value)}
          />
        </Field>
        <Field label="工作目录">
          <input
            name="cwd"
            defaultValue="/workspace"
            required
            pattern="/workspace(?:/.*)?"
          />
        </Field>
        <Field label="超时秒数">
          <input
            name="timeout"
            type="number"
            min={1}
            max={3600}
            defaultValue={60}
            required
          />
        </Field>
        <Field label="输出限制（字节）">
          <input
            name="output"
            type="number"
            min={0}
            max={16777216}
            defaultValue={1048576}
            required
          />
        </Field>
        <label className="wide check">
          <input type="checkbox" required />
          我授权超时后停止整个实例，并确认参数不包含秘密
        </label>
        <button className="primary" disabled={pending}>
          提交一次执行
        </button>
      </form>
      <ErrorView error={error} />
      <form
        className="row"
        onSubmit={(e) => {
          e.preventDefault();
          if (UUID.test(lookup)) setExecutionId(lookup);
          else setError(new ApiFailure("INVALID_EXECUTION_ID"));
        }}
      >
        <Field label="查询执行 ID">
          <input
            value={lookup}
            onChange={(e) => setLookup(e.target.value.trim())}
            required
          />
        </Field>
        <button>查询</button>
        <button type="button" onClick={context.changed}>
          刷新状态
        </button>
      </form>
      <Remote state={execution}>
        {execution.data && (
          <>
            <div className="row">
              <Badge value={execution.data.status} />
              <span>
                终止 {execution.data.termination_status} · 输出{" "}
                {execution.data.output_status}
              </span>
            </div>
            {execution.data.status === "OUTCOME_UNKNOWN" && (
              <p className="error">
                命令执行结果未知。即使实例已终止，也无法据此判断命令的副作用。
              </p>
            )}
            <Confirm
              label="取消执行并停止实例"
              target={execution.data.id}
              run={() =>
                context.perform(
                  `/v1/executions/${execution.data!.id}/cancel`,
                  {},
                  `"${execution.data!.version}"`,
                )
              }
            >
              <p>取消后，需要可信实例终止确认；取消受理不代表进程已停止。</p>
            </Confirm>
            <Output context={context} id={execution.data.id} />
            <details>
              <summary>执行元数据</summary>
              <Json value={execution.data} />
            </details>
          </>
        )}
      </Remote>
    </section>
  );
}
function Output({ context, id }: { context: Context; id: string }) {
  const [after, setAfter] = useState(-1),
    [text, setText] = useState(""),
    [error, setError] = useState<unknown>(null),
    [pending, setPending] = useState(false),
    [status, setStatus] = useState("PENDING");
  const decoders = useRef({
    stdout: new TextDecoder(),
    stderr: new TextDecoder(),
  });
  useEffect(() => {
    setAfter(-1);
    setText("");
    setError(null);
    decoders.current = { stdout: new TextDecoder(), stderr: new TextDecoder() };
  }, [id]);
  async function read() {
    setPending(true);
    setError(null);
    try {
      const value = unwrap(
        await context.api.client.GET("/v1/executions/{id}/output", {
          params: {
            header: headers(context.session),
            path: { id },
            query: { after_segment: after, limit: 2 },
          },
        }),
      );
      let addition = "";
      for (const segment of value.segments)
        for (const frame of segment.frames) {
          const bytes = Uint8Array.from(atob(frame.data), (c) =>
            c.charCodeAt(0),
          );
          addition += decoders.current[frame.stream]
            .decode(bytes, { stream: true })
            .replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g, "�");
        }
      setText((v) => (v + addition).slice(-1024 * 1024));
      if (value.next_after_segment !== null) setAfter(value.next_after_segment);
      setStatus(
        `${value.output_status} · 本页清单校验 ${value.manifest_verified ? "通过" : "尚无最终清单"}`,
      );
    } catch (error) {
      setError(error);
    } finally {
      setPending(false);
    }
  }
  return (
    <section className="output">
      <div className="row">
        <h3>执行输出</h3>
        <span className="fine">{status}</span>
        <button onClick={read} disabled={pending}>
          读取下一段
        </button>
      </div>
      <p className="fine muted">
        以纯文本显示，最多保留最近 1 MiB。不会解释
        HTML、终端转义序列或运行输出中的代码。
      </p>
      <pre tabIndex={0} aria-label="执行输出">
        {text || "尚未读取输出"}
      </pre>
      <ErrorView error={error} />
    </section>
  );
}
function scopedDiagnosis(
  value: Schema["Diagnosis"],
  diagnosisId: string,
  session: Session,
  project: string,
  instanceId: string,
) {
  const sameId = (actual: unknown, expected: string) =>
    typeof actual === "string" &&
    UUID.test(actual) &&
    actual.toLowerCase() === expected.toLowerCase();
  if (
    !value ||
    !sameId(value.id, diagnosisId) ||
    !sameId(value.tenant_id, session.tenant_id) ||
    !sameId(value.project_id, project) ||
    !sameId(value.instance_id, instanceId)
  )
    throw new ApiFailure("DIAGNOSIS_SCOPE_MISMATCH");
  if (
    !["PENDING", "COMPLETE", "FAILED", "EXPIRED"].includes(value.status) ||
    !Number.isFinite(Date.parse(value.deadline)) ||
    !Number.isFinite(Date.parse(value.retention_until)) ||
    (value.status === "COMPLETE" && !value.report) ||
    (value.status !== "COMPLETE" && value.report !== null)
  )
    throw new ApiFailure("INVALID_DIAGNOSIS_RESPONSE");
  if (value.report) {
    const statuses = ["HEALTHY", "WARNING", "CRITICAL", "UNKNOWN"];
    if (
      !statuses.includes(value.report.overall) ||
      !Array.isArray(value.report.checks) ||
      value.report.checks.some(
        (check) =>
          !check ||
          !statuses.includes(check.status) ||
          typeof check.rule !== "string" ||
          typeof check.code !== "string" ||
          typeof check.recommendation !== "string" ||
          !["INSTANCE", "OPERATIONS", "EXECUTIONS"].includes(
            check.evidence_scope,
          ) ||
          !Array.isArray(check.evidence) ||
          check.evidence.some(
            (evidence) =>
              !evidence ||
              ![
                "CONTROL_PLANE_SNAPSHOT",
                "LIFECYCLE_RECONCILER",
                "LAUNCH_VALIDATION",
                "NODE_CERTIFICATION",
                "OPERATION_LEDGER",
                "EXECUTION_LEDGER",
              ].includes(evidence.source) ||
              (evidence.state !== null && typeof evidence.state !== "string") ||
              (evidence.resource_id !== null &&
                !UUID.test(evidence.resource_id)) ||
              (evidence.observed_at !== null &&
                !Number.isFinite(Date.parse(evidence.observed_at))) ||
              (evidence.deadline !== null &&
                !Number.isFinite(Date.parse(evidence.deadline))),
          ),
      )
    )
      throw new ApiFailure("INVALID_DIAGNOSIS_RESPONSE");
  }
  return value;
}
function DiagnosisPanel({
  context,
  id,
  project,
  revision,
  enabled,
  initialId = "",
  readOnly = false,
}: {
  context: Context;
  id: string;
  project: string;
  revision: number;
  enabled: boolean;
  initialId?: string;
  readOnly?: boolean;
}) {
  const [diagnosisId, setDiagnosisId] = useState(initialId),
    [lookup, setLookup] = useState(initialId),
    [includeOperations, setIncludeOperations] = useState(false),
    [includeExecutions, setIncludeExecutions] = useState(false),
    [error, setError] = useState<unknown>(null),
    [pending, setPending] = useState(false),
    [read, setRead] = useState({ version: 0, automatic: false }),
    [stopped, setStopped] = useState(false);
  const alive = useRef(true);
  const polling = useRef({
    id: initialId,
    deadline: null as number | null,
    polls: 0,
  });
  useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
    };
  }, []);
  function open(diagnosis: string, deadline: number | null = null) {
    if (polling.current.id !== diagnosis)
      polling.current = { id: diagnosis, deadline, polls: 0 };
    setDiagnosisId(diagnosis);
    setLookup(diagnosis);
    setError(null);
    setStopped(false);
    setRead((previous) => ({
      version: previous.version + 1,
      automatic: false,
    }));
  }
  const report = useRemote(
    `${diagnosisId}:${revision}:${read.version}`,
    async (signal) => {
      if (!diagnosisId) return null;
      const automaticDeadline = read.automatic
        ? polling.current.deadline
        : null;
      const remaining = (polling.current.deadline ?? Infinity) - Date.now();
      if (read.automatic && remaining <= 0)
        throw new ApiFailure("DIAGNOSIS_REFRESH_DEADLINE");
      const value = scopedDiagnosis(
        unwrap(
          await context.api.client.GET("/v1/diagnoses/{id}", {
            params: {
              header: headers(context.session),
              path: { id: diagnosisId },
            },
            signal:
              read.automatic && Number.isFinite(remaining)
                ? AbortSignal.any([
                    signal,
                    AbortSignal.timeout(Math.max(1, Math.ceil(remaining))),
                  ])
                : signal,
          }),
        ),
        diagnosisId,
        context.session,
        project,
        id,
      );
      if (signal.aborted || polling.current.id !== diagnosisId)
        throw new ApiFailure("REQUEST_INTERRUPTED");
      if (
        read.automatic &&
        (automaticDeadline === null || Date.now() >= automaticDeadline)
      )
        throw new ApiFailure("DIAGNOSIS_REFRESH_DEADLINE");
      const deadline = Date.parse(value.deadline);
      if (
        polling.current.deadline !== null &&
        polling.current.deadline !== deadline
      )
        throw new ApiFailure("INVALID_DIAGNOSIS_RESPONSE");
      polling.current.deadline ??= deadline;
      return value;
    },
  );
  useEffect(() => {
    if (report.loading || report.error || report.data?.status !== "PENDING")
      return;
    const remaining = polling.current.deadline! - Date.now();
    if (remaining <= 0 || polling.current.polls >= 60) {
      setStopped(true);
      return;
    }
    const timer = window.setTimeout(
      () => {
        if (Date.now() >= polling.current.deadline!) {
          setStopped(true);
          return;
        }
        polling.current.polls++;
        setRead((previous) => ({
          version: previous.version + 1,
          automatic: true,
        }));
      },
      Math.min(2000, remaining),
    );
    return () => window.clearTimeout(timer);
  }, [report.loading, report.error, report.data]);
  async function create() {
    setPending(true);
    setError(null);
    try {
      const result = await context.perform<Schema["DiagnosisAccepted"]>(
        `/v1/instances/${id}/diagnoses`,
        {
          include_operations: includeOperations,
          include_executions: includeExecutions,
        },
        null,
      );
      if (!alive.current) return;
      if (!result?.resource || !UUID.test(result.resource.id))
        throw new ApiFailure("INVALID_DIAGNOSIS_RESPONSE");
      const accepted = scopedDiagnosis(
        result.resource,
        result.resource.id,
        context.session,
        project,
        id,
      );
      open(accepted.id, Date.parse(accepted.deadline));
    } catch (error) {
      if (alive.current) setError(error);
    } finally {
      if (alive.current) setPending(false);
    }
  }
  return (
    <section>
      <h3>健康诊断</h3>
      <p className="muted">
        控制面证据报告显示观测边界与异常，不能证明持续运行健康。UNKNOWN
        表示证据不足；REDACTED 表示当前权限不允许读取该类证据。
      </p>
      {!readOnly && (
        <>
          <Field label="包含操作证据">
            <input
              type="checkbox"
              checked={includeOperations}
              onChange={(e) => setIncludeOperations(e.target.checked)}
              disabled={pending}
            />
          </Field>
          <Field label="包含执行证据">
            <input
              type="checkbox"
              checked={includeExecutions}
              onChange={(e) => setIncludeExecutions(e.target.checked)}
              disabled={pending}
            />
          </Field>
          <button
            className="primary"
            disabled={!enabled || pending}
            onClick={create}
          >
            创建诊断报告
          </button>
          {!enabled && <p className="notice">当前部署未开启控制面诊断。</p>}
        </>
      )}
      <form
        className="row"
        onSubmit={(e) => {
          e.preventDefault();
          if (UUID.test(lookup)) open(lookup);
          else setError(new ApiFailure("INVALID_DIAGNOSIS_ID"));
        }}
      >
        <Field label="诊断 ID">
          <input
            value={lookup}
            onChange={(e) => setLookup(e.target.value.trim())}
            required
          />
        </Field>
        <button disabled={pending}>查询报告</button>
        <button
          type="button"
          disabled={!diagnosisId || pending}
          onClick={() => open(diagnosisId)}
        >
          刷新报告
        </button>
      </form>
      <ErrorView error={error} />
      <Remote state={report}>
        {report.data && (
          <div
            data-testid="diagnosis-report"
            data-diagnosis-id={report.data.id}
            data-tenant-id={report.data.tenant_id}
            data-project-id={report.data.project_id}
            data-instance-id={report.data.instance_id}
          >
            <Badge value={report.data.status} />
            <p>
              报告 <span className="mono">{report.data.id}</span>
            </p>
            <p>
              实例 <span className="mono">{report.data.instance_id}</span> ·
              项目 <span className="mono">{report.data.project_id}</span>
            </p>
            <p className="fine">
              请求时运行代次{" "}
              {Number.isSafeInteger(report.data.requested_generation)
                ? report.data.requested_generation
                : "无法精确展示"}{" "}
              · 启动{" "}
              <span className="mono">{report.data.requested_launch_id}</span> ·
              集群代次 <span className="mono">{report.data.cluster_epoch}</span>
            </p>
            <p>
              规则集 {report.data.ruleset_version} · 快照{" "}
              {date(report.data.snapshot_at)} · 保留至{" "}
              {date(report.data.retention_until)}
            </p>
            {report.data.status === "PENDING" && (
              <p className="notice">
                正在收集证据 · 服务器期限 {date(report.data.deadline)}。
                {stopped
                  ? "自动刷新已停止，可显式重新读取同一报告。"
                  : "等待期间仅刷新此报告。"}
              </p>
            )}
            {report.data.status === "FAILED" && (
              <p className="error">
                诊断失败 · {report.data.failure_code ?? "未提供失败原因"}
              </p>
            )}
            {report.data.status === "EXPIRED" && (
              <p className="notice">报告已过保留期限，证据不再可读。</p>
            )}
            {report.data.report && (
              <>
                <p>
                  总体结论 <Badge value={report.data.report.overall} />
                </p>
                <div className="table-wrap">
                  <table aria-label="诊断检查">
                    <thead>
                      <tr>
                        <th>规则</th>
                        <th>状态</th>
                        <th>代码</th>
                        <th>证据</th>
                        <th>建议</th>
                      </tr>
                    </thead>
                    <tbody>
                      {report.data.report.checks.map((check, index) => (
                        <tr key={`${check.rule}:${index}`}>
                          <td>
                            {check.rule}
                            <small>{check.evidence_scope}</small>
                          </td>
                          <td>
                            <Badge
                              value={
                                check.code === "EVIDENCE_REDACTED"
                                  ? "REDACTED"
                                  : check.status
                              }
                            />
                          </td>
                          <td>{check.code}</td>
                          <td>
                            {check.evidence.length
                              ? check.evidence.map(
                                  (evidence, evidenceIndex) => (
                                    <div key={evidenceIndex}>
                                      <span>
                                        {evidence.source} ·{" "}
                                        {evidence.state ?? "UNKNOWN"}
                                      </span>
                                      <small>
                                        观测 {date(evidence.observed_at)} · 期限{" "}
                                        {date(evidence.deadline)}
                                      </small>
                                      {evidence.resource_id && (
                                        <small className="mono">
                                          {evidence.resource_id}
                                        </small>
                                      )}
                                    </div>
                                  ),
                                )
                              : "尚无可读取证据"}
                          </td>
                          <td>{check.recommendation}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </>
            )}
          </div>
        )}
      </Remote>
    </section>
  );
}
function BackupPanel({
  context,
  instance,
  revision,
  enabled,
}: {
  context: Context;
  instance: Instance;
  revision: number;
  enabled: boolean;
}) {
  const [backupId, setBackupId] = useState(""),
    [lookup, setLookup] = useState(""),
    [error, setError] = useState<unknown>(null),
    [pending, setPending] = useState(false);
  const workspace = useRemote(
    `${instance.workspace_id}:${revision}:${enabled}`,
    async (signal) =>
      enabled
        ? unwrap(
            await context.api.client.GET("/v1/workspaces/{id}", {
              params: {
                header: headers(context.session),
                path: { id: instance.workspace_id },
              },
              signal,
            }),
          )
        : null,
  );
  const backup = useRemote(
    `${backupId}:${revision}:${enabled}`,
    async (signal) =>
      enabled && backupId
        ? unwrap(
            await context.api.client.GET("/v1/backups/{id}", {
              params: {
                header: headers(context.session),
                path: { id: backupId },
              },
              signal,
            }),
          )
        : null,
  );
  async function create(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    if (!enabled || !workspace.data) return;
    const form = new FormData(e.currentTarget);
    setPending(true);
    setError(null);
    try {
      const result = await context.perform<Schema["BackupAccepted"]>(
        `/v1/workspaces/${instance.workspace_id}/backups`,
        {
          profile_id: String(form.get("profile")),
          retention_days: Number(form.get("retention")),
        },
        `"${workspace.data.spec_version}"`,
      );
      setBackupId(result.resource.id);
      setLookup(result.resource.id);
    } catch (error) {
      setError(error);
    } finally {
      setPending(false);
    }
  }
  if (!enabled)
    return (
      <section>
        <h3>工作区冷备份</h3>
        <p className="notice">当前部署未提供工作区备份服务。</p>
      </section>
    );
  return (
    <section>
      <h3>工作区冷备份</h3>
      <p className="notice">
        冷备份要求计算实例已停止且可信终止已确认，并使用经认证、启用的独立备份配置。AVAILABLE
        才表示备份可用。恢复功能是否可用以服务能力为准。
      </p>
      <Remote state={workspace}>
        {workspace.data && (
          <>
            <form className="form-grid" onSubmit={create}>
              <Field label="已批准备份配置 ID">
                <input name="profile" pattern={UUID.source} required />
              </Field>
              <Field label="保留天数">
                <input
                  name="retention"
                  type="number"
                  min={31}
                  max={3650}
                  defaultValue={31}
                  required
                />
              </Field>
              <button className="primary" disabled={pending}>
                提交冷备份请求
              </button>
            </form>
            <p className="fine">
              工作区 {workspace.data.id} · 版本 {workspace.data.spec_version} ·{" "}
              {workspace.data.status}
            </p>
            <Confirm
              label="永久删除工作区"
              target={workspace.data.id}
              run={() =>
                context.perform(
                  `/v1/workspaces/${instance.workspace_id}`,
                  {},
                  `"${workspace.data!.spec_version}"`,
                  "DELETE",
                )
              }
            >
              <p>
                工作区数据会进入不可逆的底层删除流程。请先核对独立备份是否可恢复。
              </p>
            </Confirm>
          </>
        )}
      </Remote>
      <form
        className="row"
        onSubmit={(e) => {
          e.preventDefault();
          if (UUID.test(lookup)) setBackupId(lookup);
          else setError(new ApiFailure("INVALID_BACKUP_ID"));
        }}
      >
        <Field label="备份 ID">
          <input
            value={lookup}
            onChange={(e) => setLookup(e.target.value.trim())}
            required
          />
        </Field>
        <button>查询备份</button>
        <button type="button" onClick={context.changed}>
          刷新
        </button>
      </form>
      <ErrorView error={error} />
      <Remote state={backup}>
        {backup.data && (
          <>
            <Badge value={backup.data.status} />
            <p>
              {backup.data.consistency} · 保留至{" "}
              {date(backup.data.retention_until)}
            </p>
            <Json value={backup.data} />
          </>
        )}
      </Remote>
    </section>
  );
}
function FilesPanel({
  context,
  instance,
  revision,
  enabled,
}: {
  context: Context;
  instance: Instance;
  revision: number;
  enabled: boolean;
}) {
  const [path, setPath] = useState(""),
    [file, setFile] = useState<File | null>(null),
    [replace, setReplace] = useState(false),
    [transferId, setTransferId] = useState(""),
    [lookup, setLookup] = useState(""),
    [error, setError] = useState<unknown>(null),
    [pending, setPending] = useState(false),
    [progress, setProgress] = useState("");
  const active = useRef<AbortController | null>(null);
  useEffect(() => () => active.current?.abort(), []);
  const transfer = useRemote(`${transferId}:${revision}`, async (signal) =>
    transferId
      ? unwrap(
          await context.api.client.GET("/v1/file-transfers/{id}", {
            params: {
              header: headers(context.session),
              path: { id: transferId },
            },
            signal,
          }),
        )
      : null,
  );
  async function upload(t: Schema["FileTransfer"], selected: File) {
    const controller = new AbortController();
    active.current = controller;
    setProgress("正在核对文件摘要…");
    if (
      (await sha(new Uint8Array(await selected.arrayBuffer()))) !==
      t.expected_sha256
    )
      throw new ApiFailure("LOCAL_FILE_CHANGED");
    await stageFile(
      context.api,
      context.session,
      t,
      selected,
      controller.signal,
      (index) => setProgress(`已确认第 ${index + 1} 个分片`),
    );
    controller.signal.throwIfAborted();
    setProgress("分片已核验，正在提交内容清单…");
    await context.perform(
      `/v1/file-transfers/${t.id}/content/commit`,
      {},
      `"${t.version}"`,
    );
    setProgress("上传内容已受理，等待实例内写入确认。");
  }
  async function create(direction: "UPLOAD" | "DOWNLOAD") {
    setPending(true);
    setError(null);
    try {
      const validPath = workspacePath(path);
      let body: Schema["CreateFileUpload"] | Schema["CreateFileDownload"];
      if (direction === "UPLOAD") {
        if (!file || file.size > MAX_FILE_BYTES)
          throw new ApiFailure("FILE_LIMIT_EXCEEDED");
        setProgress("正在计算文件 SHA-256…");
        body = {
          direction: "UPLOAD",
          path: validPath,
          byte_length: file.size,
          sha256: await sha(new Uint8Array(await file.arrayBuffer())),
          replace,
          timeout_seconds: 300,
        };
      } else
        body = {
          direction: "DOWNLOAD",
          path: validPath,
          max_bytes: MAX_FILE_BYTES,
          timeout_seconds: 300,
        };
      const receipt = await context.perform<Schema["FileTransferAccepted"]>(
        `/v1/instances/${instance.id}/file-transfers`,
        body,
        `"${instance.spec_version}"`,
      );
      setTransferId(receipt.resource.id);
      setLookup(receipt.resource.id);
      if (direction === "UPLOAD" && file) await upload(receipt.resource, file);
      else setProgress("下载任务已受理。等待状态 SUCCEEDED 后保存。");
    } catch (error) {
      setError(error);
      setProgress(
        "传输尚未完成；请使用已记录的传输 ID 核对，失败不会自动重传。",
      );
    } finally {
      setPending(false);
      context.changed();
    }
  }
  async function save() {
    if (!transfer.data) return;
    setPending(true);
    setError(null);
    const controller = new AbortController();
    active.current = controller;
    try {
      const blob = await verifiedDownload(
        context.api,
        context.session,
        transfer.data,
        controller.signal,
      );
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = transfer.data.path.split("/").at(-1) ?? "workspace-file";
      link.rel = "noopener";
      link.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      setProgress("完整文件已通过长度与 SHA-256 校验。");
    } catch (error) {
      setError(error);
    } finally {
      setPending(false);
    }
  }
  return (
    <section>
      <h3>工作区文件</h3>
      <p className="notice">
        文件路径限定在 /workspace 内；不跟随符号链接。单文件上限 100
        MiB。超时策略申请停止整个实例；传输结果未知时不会自动重发。
      </p>
      {!enabled && <p className="notice">当前部署未配置文件传输服务。</p>}
      <div className="form-grid">
        <Field label="相对路径">
          <input
            required
            value={path}
            onChange={(e) => setPath(e.target.value)}
            placeholder="src/main.py"
          />
        </Field>
        <Field label="选择本地文件">
          <input
            type="file"
            onChange={(e) => setFile(e.target.files?.[0] ?? null)}
          />
        </Field>
        <label className="check">
          <input
            type="checkbox"
            checked={replace}
            onChange={(e) => setReplace(e.target.checked)}
          />
          允许替换现有文件
        </label>
        <div className="row">
          <button
            className="primary"
            disabled={!enabled || pending || !file}
            onClick={() => create("UPLOAD")}
          >
            上传文件
          </button>
          <button
            disabled={!enabled || pending}
            onClick={() => create("DOWNLOAD")}
          >
            申请下载
          </button>
          <button
            disabled={!pending}
            onClick={() => {
              active.current?.abort();
              setProgress("本地数据请求已取消；已受理传输仍需查询最终状态。");
            }}
          >
            取消本地等待
          </button>
        </div>
      </div>
      <p role="status">{progress}</p>
      <ErrorView error={error} />
      <form
        className="row"
        onSubmit={(e) => {
          e.preventDefault();
          if (UUID.test(lookup)) setTransferId(lookup);
          else setError(new ApiFailure("INVALID_TRANSFER_ID"));
        }}
      >
        <Field label="传输 ID">
          <input
            value={lookup}
            onChange={(e) => setLookup(e.target.value.trim())}
            required
          />
        </Field>
        <button>查询</button>
        <button type="button" onClick={context.changed}>
          刷新
        </button>
      </form>
      <Remote state={transfer}>
        {transfer.data && (
          <>
            <Badge value={transfer.data.status} />
            <p>
              {transfer.data.path} · 内容 {transfer.data.content_status} · 进程{" "}
              {transfer.data.process_status} · 写入{" "}
              {transfer.data.storage_writer_status}
            </p>
            {transfer.data.status === "WAITING_UPLOAD" && file && (
              <button
                disabled={pending}
                onClick={async () => {
                  setPending(true);
                  setError(null);
                  try {
                    await upload(transfer.data!, file);
                  } catch (error) {
                    setError(error);
                  } finally {
                    setPending(false);
                    context.changed();
                  }
                }}
              >
                核对摘要并继续上传（显式重传相同分片）
              </button>
            )}
            {transfer.data.direction === "DOWNLOAD" && (
              <button
                className="primary"
                disabled={pending || transfer.data.status !== "SUCCEEDED"}
                onClick={save}
              >
                校验并保存下载文件
              </button>
            )}
            <Json value={transfer.data} />
          </>
        )}
      </Remote>
    </section>
  );
}
function LiveEvents({
  context,
  project,
  instance,
}: {
  context: Context;
  project: string;
  instance: string | null;
}) {
  type RecentEvent = {
    id: string;
    eventType: string;
    aggregateId: string;
    operationId: string | null;
    occurredAt: string;
    observedAt: string;
    sequence: string;
  };
  type View = {
    state:
      "IDLE" | "CONNECTING" | "LIVE" | "STOPPED" | "RESET_REQUIRED" | "DENIED";
    cursor: string;
    sequence: string;
    observedAt: string | null;
    rows: RecentEvent[];
    error: unknown;
  };
  const empty = (): View => ({
    state: "IDLE",
    cursor: "",
    sequence: "",
    observedAt: null,
    rows: [],
    error: null,
  });
  const [view, setView] = useState<View>(empty),
    [running, setRunning] = useState(false);
  const memory = useRef(view),
    active = useRef<AbortController | null>(null);
  function publish(next: View) {
    memory.current = next;
    setView(next);
  }
  useEffect(
    () => () => {
      active.current?.abort();
      active.current = null;
    },
    [],
  );
  async function connect(rebuild = false) {
    if (active.current) return;
    if (rebuild) publish(empty());
    const cursor = memory.current.cursor;
    const controller = new AbortController();
    active.current = controller;
    setRunning(true);
    publish({ ...memory.current, state: "CONNECTING", error: null });
    try {
      for await (const message of context.api.eventStream({
        session: context.session,
        projectId: project,
        ...(instance ? { instanceId: instance } : {}),
        ...(cursor ? { lastEventId: cursor } : {}),
        signal: controller.signal,
      })) {
        if (active.current !== controller || controller.signal.aborted) return;
        const previous = memory.current,
          observedAt = new Date().toISOString();
        if (
          previous.sequence &&
          BigInt(message.sequence) < BigInt(previous.sequence)
        )
          throw new ApiFailure("INVALID_EVENT_STREAM");
        let rows = previous.rows;
        if (message.type === "domain.event") {
          const event = message.event;
          if (
            !rows.some((row) => row.id.toLowerCase() === event.id.toLowerCase())
          )
            rows = [
              {
                id: event.id,
                eventType: event.event_type,
                aggregateId: event.aggregate_id,
                operationId: event.operation_id,
                occurredAt: event.occurred_at,
                observedAt,
                sequence: message.sequence,
              },
              ...rows,
            ].slice(0, 50);
        }
        publish({
          state: "LIVE",
          cursor: message.cursor,
          sequence: message.sequence,
          observedAt,
          rows,
          error: null,
        });
      }
      if (active.current === controller && !controller.signal.aborted)
        publish({ ...memory.current, state: "STOPPED" });
    } catch (error) {
      if (active.current !== controller || controller.signal.aborted) return;
      const failure =
        error instanceof EventStreamError
          ? new ApiFailure(
              error.code,
              error.status ?? null,
              error.requestId ?? null,
            )
          : error instanceof ApiFailure
            ? error
            : new ApiFailure("EVENT_STREAM_INTERRUPTED");
      const denied =
        [401, 403, 404].includes(failure.status ?? 0) ||
        [
          "UNAUTHENTICATED",
          "PERMISSION_DENIED",
          "RESOURCE_NOT_FOUND",
          "NOT_FOUND",
          "BROWSER_LOGIN_REQUIRED",
          "BROWSER_SESSION_CHANGED",
          "REQUEST_SCOPE_REJECTED",
          "AUTHORITY_REVOKED",
          "AUTHORIZATION_REVOKED",
        ].includes(failure.code);
      const reset =
        [400, 409, 410].includes(failure.status ?? 0) ||
        [
          "INVALID_CURSOR",
          "EVENT_CURSOR_EXPIRED",
          "EVENT_HISTORY_UNAVAILABLE",
          "EVENT_CURSOR_AHEAD",
        ].includes(failure.code);
      publish({
        ...(denied || reset ? empty() : memory.current),
        state: denied ? "DENIED" : reset ? "RESET_REQUIRED" : "STOPPED",
        error: failure,
      });
    } finally {
      if (active.current === controller) {
        active.current = null;
        setRunning(false);
      }
    }
  }
  function stop() {
    active.current?.abort();
    publish({ ...memory.current, state: "STOPPED" });
  }
  return (
    <section
      data-testid="event-stream-panel"
      data-state={view.state}
      data-cursor={view.cursor}
    >
      <h3>实时事件提示</h3>
      <p className="muted">
        主动连接后仅展示最近 50 条事件元数据，按事件 ID
        去重。此提示不替代完整历史快照，也不代表操作已完成或当前运行健康。断点和提示只保存在当前页面内存中。
      </p>
      <div className="row">
        {view.state === "IDLE" && (
          <button onClick={() => void connect()}>开启实时提示</button>
        )}
        <button disabled={!running} onClick={stop}>
          停止实时提示
        </button>
        {view.cursor && (
          <button disabled={running} onClick={() => void connect()}>
            从原断点重连
          </button>
        )}
        {view.state !== "IDLE" && (
          <button disabled={running} onClick={() => void connect(true)}>
            重建实时基线
          </button>
        )}
      </div>
      <p role="status" data-testid="event-stream-state">
        {view.state === "IDLE"
          ? "尚未连接"
          : view.state === "CONNECTING"
            ? "正在建立连接"
            : view.state === "LIVE"
              ? "实时连接已建立"
              : view.state === "DENIED"
                ? "访问已拒绝，原证据已清除"
                : view.state === "RESET_REQUIRED"
                  ? "原断点不可用，须显式重建基线"
                  : running
                    ? "正在停止连接"
                    : "实时连接已停止，请显式重连"}
      </p>
      {view.cursor && (
        <p className="fine">
          <span>基线已确认</span> · 已消费序号 {view.sequence} · 最近观察{" "}
          {date(view.observedAt)}。停止后保留原断点。
        </p>
      )}
      {view.state === "RESET_REQUIRED" && (
        <p className="notice">
          重建会清除当前断点与提示，并从服务器最新位置建立新基线；此前未核对的历史请使用快照查询。
        </p>
      )}
      <ErrorView error={view.error} />
      <div className="table-wrap">
        <table aria-label="最近实时事件">
          <thead>
            <tr>
              <th>事件 ID / 类型</th>
              <th>资源 ID</th>
              <th>操作 ID</th>
              <th>事件时间</th>
              <th>观察时间 / 序号</th>
            </tr>
          </thead>
          <tbody>
            {view.rows.map((row) => (
              <tr key={row.id.toLowerCase()} data-event-id={row.id}>
                <td className="mono">
                  {row.id}
                  <small>{row.eventType}</small>
                </td>
                <td className="mono">{row.aggregateId}</td>
                <td className="mono">{row.operationId ?? "—"}</td>
                <td>{date(row.occurredAt)}</td>
                <td>
                  {date(row.observedAt)}
                  <small>{row.sequence}</small>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {!view.rows.length && <p className="empty">当前页面尚无实时事件提示。</p>}
    </section>
  );
}
function History({
  context,
  project,
  instance,
}: {
  context: Context;
  project: string;
  instance: string | null;
}) {
  const [kind, setKind] = useState<"operations" | "events" | "audit-records">(
      "operations",
    ),
    [cursor, setCursor] = useState<string | null>(null),
    [revision, setRevision] = useState(0);
  const params = {
    header: headers(context.session),
    query: {
      project_id: project,
      limit: 50,
      ...(instance ? { instance_id: instance } : {}),
      ...(cursor ? { cursor } : {}),
    },
  };
  const page = useRemote(
    `${kind}:${cursor}:${revision}:${instance}`,
    async (signal) => {
      switch (kind) {
        case "operations":
          return unwrap(
            await context.api.client.GET("/v1/operations", { params, signal }),
          );
        case "events":
          return unwrap(
            await context.api.client.GET("/v1/events", { params, signal }),
          );
        case "audit-records":
          return unwrap(
            await context.api.client.GET("/v1/audit-records", {
              params,
              signal,
            }),
          );
      }
    },
  );
  const columns =
    kind === "operations"
      ? ["id", "kind", "status", "stage", "updated_at"]
      : kind === "events"
        ? ["id", "event_type", "aggregate_id", "operation_id", "occurred_at"]
        : [
            "id",
            "action",
            "outcome",
            "actor_principal_id",
            "request_id",
            "occurred_at",
          ];
  return (
    <section className="card">
      <div className="row">
        <Field label="记录类型">
          <select
            value={kind}
            onChange={(e) => {
              setKind(e.target.value as typeof kind);
              setCursor(null);
            }}
          >
            <option value="operations">操作记录</option>
            <option value="events">事件</option>
            <option value="audit-records">安全审计</option>
          </select>
        </Field>
        <button
          onClick={() => {
            setCursor(null);
            setRevision((v) => v + 1);
          }}
        >
          读取最新快照
        </button>
      </div>
      <p className="fine muted">
        项目 {project}
        {instance ? ` · 实例 ${instance}` : " · 全项目"}
        。下一页沿用原始查询快照，切换筛选会重新分页。
      </p>
      <Remote state={page}>
        {page.data && (
          <>
            <p className="fine">快照截点 {date(page.data.cutoff)}</p>
            <div className="table-wrap">
              <table>
                <caption className="sr-only">服务端记录</caption>
                <thead>
                  <tr>
                    {columns.map((c) => (
                      <th key={c}>{c}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {page.data.items.map((item) => (
                    <tr key={item.id}>
                      {columns.map((c) => (
                        <td key={c} className="mono">
                          {String(
                            (item as unknown as Record<string, unknown>)[c] ??
                              "—",
                          )}
                        </td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {!page.data.items.length && (
              <p className="empty">当前快照暂无记录。</p>
            )}
            <button
              disabled={!page.data.next_cursor}
              onClick={() => setCursor(page.data!.next_cursor)}
            >
              读取下一页
            </button>
          </>
        )}
      </Remote>
      {kind === "events" && (
        <LiveEvents
          key={`${context.session.tenant_id}:${context.session.principal_id}:${context.session.csrf_token}:${project}:${instance ?? ""}`}
          context={context}
          project={project}
          instance={instance}
        />
      )}
    </section>
  );
}
function checkedAutomationFeatures(
  caps: Schema["Capabilities"] | null,
  project: string,
): AutomationFeatures {
  const unavailable: AutomationFeatures = {
    scheduled: false,
    event: false,
    maxTtl: 60,
    contract: null,
  };
  const maxTtl = caps?.limits?.ttl_seconds?.maximum;
  return caps &&
    caps.project_id === project &&
    typeof caps.api_features?.scheduled_tasks === "boolean" &&
    typeof caps.api_features?.event_automation === "boolean"
    ? {
        scheduled: caps.api_features.scheduled_tasks,
        event: caps.api_features.event_automation,
        maxTtl:
          typeof maxTtl === "number" &&
          Number.isSafeInteger(maxTtl) &&
          maxTtl >= 60
            ? maxTtl
            : 60,
        contract:
          typeof maxTtl === "number" &&
          Number.isSafeInteger(maxTtl) &&
          maxTtl >= 60
            ? automationContract(caps.automation)
            : null,
      }
    : unavailable;
}
function useAutomationFeatures(
  caps: Schema["Capabilities"] | null,
  loading: boolean,
  error: unknown,
  project: string,
) {
  const known = useRef(checkedAutomationFeatures(null, project));
  if (caps || (!loading && !error))
    known.current = checkedAutomationFeatures(caps, project);
  else if (
    error instanceof ApiFailure &&
    [401, 403, 404].includes(error.status ?? 0)
  ) {
    known.current = checkedAutomationFeatures(null, project);
  }
  return { features: known.current, blocked: loading || !caps || !!error };
}
type AutomationFeatures = {
  scheduled: boolean;
  event: boolean;
  maxTtl: number;
  contract: AutomationContract | null;
};
const AUTOMATION_ACTIONS = [
  ["START", "启动计算"],
  ["STOP", "停止计算"],
  ["RESTART", "重启计算"],
  ["DELETE", "删除计算（保留工作区）"],
  ["RENEW", "延长计算租期"],
  ["EXECUTE", "执行非敏感命令"],
  ["BACKUP", "创建冷备份"],
] as const;
function automationEtag(response: Response, version: number): string {
  const etag = response.headers.get("etag");
  if (
    !Number.isSafeInteger(version) ||
    version < 1 ||
    !etag ||
    !ETAG.test(etag) ||
    etag !== `"${version}"`
  )
    throw new ApiFailure("INVALID_AUTOMATION_ETAG");
  return etag;
}
function automationPage<T extends { id: string }>(
  page: { items: T[]; next_cursor: string | null; cutoff: string },
  validate: (item: T) => T,
) {
  if (
    !page ||
    !Array.isArray(page.items) ||
    page.items.length > 20 ||
    !(
      page.next_cursor === null ||
      (typeof page.next_cursor === "string" &&
        page.next_cursor.length > 0 &&
        page.next_cursor.length <= 4096)
    ) ||
    !Number.isFinite(Date.parse(page.cutoff))
  )
    throw new ApiFailure("INVALID_AUTOMATION_PAGE");
  const items = page.items.map(validate);
  if (new Set(items.map((item) => item.id)).size !== items.length)
    throw new ApiFailure("INVALID_AUTOMATION_PAGE");
  return { ...page, items };
}
function AutomationPanel({
  context,
  id,
  project,
  features,
  blocked,
  initialId = "",
  detailOnly = false,
}: {
  context: Context;
  id: string;
  project: string;
  features: AutomationFeatures;
  blocked: boolean;
  initialId?: string;
  detailOnly?: boolean;
}) {
  const enabled = features.scheduled || features.event;
  const contract = features.contract;
  const contractKey = contract
    ? `${features.maxTtl}:${JSON.stringify(contract)}`
    : "unavailable";
  const requestedPolicy = useRef(initialId);
  const [policyId, setPolicyId] = useState(initialId),
    [lookup, setLookup] = useState(initialId),
    [cursor, setCursor] = useState<string | null>(null),
    [runCursor, setRunCursor] = useState<string | null>(null),
    [runId, setRunId] = useState(""),
    [runLookup, setRunLookup] = useState(""),
    [read, setRead] = useState(0),
    [runsRead, setRunsRead] = useState(0),
    [action, setAction] =
      useState<Schema["Automation"]["action_kind"]>("RENEW"),
    [trigger, setTrigger] = useState<Schema["Automation"]["trigger_kind"]>(
      features.scheduled ? "ONCE" : "EVENT",
    ),
    [proposal, setProposal] = useState<Schema["CreateAutomation"] | null>(null),
    [draftVersion, setDraftVersion] = useState(0),
    [pending, setPending] = useState(false),
    [error, setError] = useState<unknown>(null),
    [denied, setDenied] = useState(false),
    [conflict, setConflict] = useState(false);
  const lifetime = useRef<AbortController | null>(null);
  const unresolved = context.journal
    .list(context.session)
    .some(
      (row) =>
        ["READY", "UNKNOWN", "PENDING"].includes(row.state) &&
        (row.path === automationCreatePath(id) ||
          (isAutomationId(policyId) &&
            (["pause", "resume", "revoke"] as const).some(
              (action) => row.path === automationActionPath(policyId, action),
            ))),
    );
  const writable = useRef(false);
  writable.current = enabled && !blocked && !denied && !unresolved;
  const creatable = useRef(false);
  creatable.current = writable.current && contract !== null;
  const proposalContract = useRef("");
  const currentContractKey = useRef(contractKey);
  currentContractKey.current = contractKey;
  useEffect(() => {
    // Discard only unsubmitted form/proposal data. Durable UNKNOWN intent keys,
    // digests, original in-memory payloads and accepted receipts stay intact.
    setProposal(null);
    setDraftVersion((v) => v + 1);
    proposalContract.current = "";
  }, [contractKey]);
  useEffect(() => {
    const controller = new AbortController();
    lifetime.current = controller;
    return () => {
      controller.abort();
      lifetime.current = null;
    };
  }, []);
  const scope = `${context.session.tenant_id}:${context.session.principal_id}:${context.session.csrf_token}:${project}:${id}`;
  const list = useRemote(
    `${scope}:list:${cursor ?? "first"}:${read}:${enabled}:${denied}`,
    async (signal) => {
      if (!enabled || denied || detailOnly) return null;
      return automationPage(
        unwrap(
          await context.api.client.GET("/v1/automations", {
            params: {
              header: headers(context.session),
              query: {
                project_id: project,
                instance_id: id,
                limit: 20,
                ...(cursor ? { cursor } : {}),
              },
            },
            signal,
          }),
        ),
        (item) => scopedAutomation(item, context.session, project, id),
      );
    },
  );
  const detail = useRemote(
    `${scope}:policy:${policyId}:${read}:${enabled}:${denied}`,
    async (signal) => {
      if (!enabled || denied || !policyId) return null;
      const result = await context.api.client.GET("/v1/automations/{id}", {
        params: { header: headers(context.session), path: { id: policyId } },
        signal,
      });
      const value = scopedAutomation(
        unwrap(result),
        context.session,
        project,
        id,
        policyId,
      );
      return { value, etag: automationEtag(result.response, value.version) };
    },
  );
  const policy = detail.data?.value ?? null;
  const resumable = useRef(false);
  resumable.current =
    !!contract &&
    !!policy &&
    automationSupports(contract, policy.action_kind, policy.trigger_kind) &&
    (policy.trigger_kind === "EVENT" ? features.event : features.scheduled);
  const runs = useRemote(
    `${scope}:runs:${policyId}:${runCursor ?? "first"}:${runsRead}:${detail.data?.etag ?? "unread"}:${denied}`,
    async (signal) => {
      if (!policy || denied) return null;
      return automationPage(
        unwrap(
          await context.api.client.GET("/v1/automations/{id}/runs", {
            params: {
              header: headers(context.session),
              path: { id: policy.id },
              query: {
                project_id: project,
                instance_id: id,
                limit: 20,
                ...(runCursor ? { cursor: runCursor } : {}),
              },
            },
            signal,
          }),
        ),
        (item) =>
          scopedAutomationRun(item, context.session, project, policy.id),
      );
    },
  );
  const exactRun = useRemote(
    `${scope}:run:${policyId}:${runId}:${runsRead}:${detail.data?.etag ?? "unread"}:${denied}`,
    async (signal) => {
      if (!policy || !runId || denied) return null;
      return scopedAutomationRun(
        unwrap(
          await context.api.client.GET("/v1/automation-runs/{id}", {
            params: { header: headers(context.session), path: { id: runId } },
            signal,
          }),
        ),
        context.session,
        project,
        policy.id,
        runId,
      );
    },
  );
  function rejectScope(failure: unknown) {
    if (
      !(failure instanceof ApiFailure) ||
      !(
        [401, 403, 404].includes(failure.status ?? 0) ||
        failure.code === "AUTOMATION_SCOPE_REJECTED" ||
        failure.code === "INVALID_AUTOMATION_INPUT"
      )
    )
      return;
    setDenied(true);
    setPolicyId("");
    setLookup("");
    setRunId("");
    setRunLookup("");
    setCursor(null);
    setRunCursor(null);
    setProposal(null);
    setDraftVersion((v) => v + 1);
    context.journal.forgetPayloads();
    setError(failure);
  }
  useEffect(() => {
    const rejection = [
      list.error,
      detail.error,
      runs.error,
      exactRun.error,
    ].find(
      (value) =>
        value instanceof ApiFailure &&
        ([401, 403, 404].includes(value.status ?? 0) ||
          value.code === "INVALID_AUTOMATION_INPUT"),
    );
    if (rejection) rejectScope(rejection);
  }, [list.error, detail.error, runs.error, exactRun.error]);
  function openPolicy(value: string) {
    if (!isAutomationId(value)) {
      setError(new ApiFailure("INVALID_AUTOMATION_ID"));
      return;
    }
    value = value.toLowerCase();
    requestedPolicy.current = value;
    setPolicyId(value);
    setLookup(value);
    setRunId("");
    setRunLookup("");
    setRunCursor(null);
    setConflict(false);
    setError(null);
    setRead((v) => v + 1);
  }
  function reread() {
    setPolicyId(requestedPolicy.current);
    setLookup(requestedPolicy.current);
    setConflict(false);
    setDenied(false);
    setError(null);
    setRunId("");
    setRunLookup("");
    setRunCursor(null);
    setCursor(null);
    setRead((v) => v + 1);
  }
  async function create() {
    if (
      !proposal ||
      !creatable.current ||
      proposalContract.current !== currentContractKey.current ||
      pending
    )
      throw new ApiFailure("AUTOMATION_WRITE_DISABLED");
    setPending(true);
    setError(null);
    const controller = lifetime.current;
    try {
      if (!controller) throw new ApiFailure("REQUEST_INTERRUPTED");
      const result = await context.api.client.GET("/v1/instances/{id}", {
        params: { header: headers(context.session), path: { id } },
        signal: controller.signal,
      });
      const instance = unwrap(result);
      if (
        instance.id !== id ||
        instance.tenant_id !== context.session.tenant_id ||
        instance.project_id !== project
      )
        throw new ApiFailure("AUTOMATION_SCOPE_REJECTED");
      const etag = automationEtag(result.response, instance.spec_version);
      if (
        controller.signal.aborted ||
        !creatable.current ||
        proposalContract.current !== currentContractKey.current
      )
        throw new ApiFailure("REQUEST_INTERRUPTED");
      const receipt = await context.perform<Schema["AutomationReceipt"]>(
        automationCreatePath(id),
        proposal,
        etag,
      );
      const value = scopedAutomation(
        receipt.resource,
        context.session,
        project,
        id,
      );
      if (!controller.signal.aborted) {
        setProposal(null);
        setDraftVersion((v) => v + 1);
        setCursor(null);
        openPolicy(value.id);
      }
    } catch (failure) {
      if (controller && !controller.signal.aborted) {
        setError(failure);
        rejectScope(failure);
      }
      throw failure;
    } finally {
      if (controller && !controller.signal.aborted) setPending(false);
    }
  }
  async function change(next: "pause" | "resume" | "revoke") {
    if (
      !writable.current ||
      !detail.data ||
      detail.loading ||
      conflict ||
      pending
    )
      throw new ApiFailure("REREAD_AUTOMATION_FIRST");
    if (next === "resume" && !resumable.current)
      throw new ApiFailure("AUTOMATION_CONTRACT_UNAVAILABLE");
    const original = detail.data;
    const controller = lifetime.current;
    if (!controller || controller.signal.aborted)
      throw new ApiFailure("REQUEST_INTERRUPTED");
    setPending(true);
    setError(null);
    try {
      const receipt = await context.perform<Schema["AutomationReceipt"]>(
        automationActionPath(original.value.id, next),
        {},
        original.etag,
      );
      scopedAutomation(
        receipt.resource,
        context.session,
        project,
        id,
        original.value.id,
      );
      if (!controller.signal.aborted) setRead((v) => v + 1);
    } catch (failure) {
      if (!controller.signal.aborted) {
        setError(failure);
        rejectScope(failure);
        if (failure instanceof ApiFailure && failure.status === 412)
          setConflict(true);
      }
      throw failure;
    } finally {
      if (!controller.signal.aborted) setPending(false);
    }
  }
  if (!enabled)
    return <p className="muted">当前部署未提供定时或事件自动化 API。</p>;
  return (
    <section
      data-testid="automation-panel"
      data-instance-id={id}
      data-project-id={project}
    >
      <h3>定时与自动化</h3>
      <p className="notice">
        规则在有限授权期限内申请业务操作。能力合同不代表你拥有授权、worker
        可用或实云认证；SUBMITTED 仅表示受理，OUTCOME_UNKNOWN
        必须核对同一运行，不能替换或补发。暂停不取消已受理操作；永久撤销不可恢复。浏览器不运行调度器，不自动提交或重试。
      </p>
      {blocked && (
        <p role="status">正在核对能力或能力读取未完成；暂不可提交新请求。</p>
      )}
      {!contract && (
        <p role="status">
          自动化创建合同缺失、不完整或版本不受支持；新建与恢复策略已禁用。仍可读取原策略、暂停、撤销及核对原请求。
        </p>
      )}
      {unresolved && (
        <p role="status">
          先在请求记录核对原请求；未知结果只能显式重放原键与原参数。
        </p>
      )}
      <ErrorView error={error} />
      <div className="row">
        <button disabled={blocked || pending} onClick={reread}>
          重新读取策略
        </button>
      </div>
      {!denied && (
        <>
          {!detailOnly && (
            <Remote state={list}>
              {list.data && (
                <>
                  <p className="fine">
                    列表截止 {date(list.data.cutoff)} · 每页 20
                    条，断点仅用于同一项目与实例。
                  </p>
                  <div className="table-wrap">
                    <table aria-label="自动化策略列表">
                      <caption>自动化策略列表</caption>
                      <thead>
                        <tr>
                          <th>名称 / 策略 ID</th>
                          <th>动作 / 触发</th>
                          <th>状态</th>
                          <th>预算 / 到期</th>
                          <th>查看</th>
                        </tr>
                      </thead>
                      <tbody>
                        {list.data.items.map((item) => (
                          <tr key={item.id} data-automation-id={item.id}>
                            <td>
                              {item.name}
                              <small className="mono">{item.id}</small>
                            </td>
                            <td>
                              {item.action_kind} / {item.trigger_kind}
                            </td>
                            <td>
                              <Badge value={item.status} />
                            </td>
                            <td>
                              {item.emitted_runs} / {item.run_budget}
                              <small>{date(item.delegation_expires_at)}</small>
                            </td>
                            <td>
                              <button
                                aria-label={`查看策略 ${item.id}`}
                                onClick={() => openPolicy(item.id)}
                              >
                                查看策略
                              </button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                  {!list.data.items.length && <p>当前页暂无自动化策略。</p>}
                  <button
                    disabled={list.loading || !list.data.next_cursor}
                    onClick={() => setCursor(list.data!.next_cursor)}
                  >
                    策略下一页
                  </button>
                </>
              )}
            </Remote>
          )}
          <form
            className="row"
            onSubmit={(e) => {
              e.preventDefault();
              openPolicy(lookup);
            }}
          >
            <Field label="策略 ID">
              <input
                value={lookup}
                onChange={(e) => setLookup(e.target.value.trim())}
                required
                pattern={UUID.source}
              />
            </Field>
            <button disabled={pending}>查询策略</button>
          </form>
          <Remote state={detail}>
            {policy && (
              <section
                data-testid="automation-detail"
                data-automation-id={policy.id}
                data-status={policy.status}
                data-version={policy.version}
              >
                <h4>{policy.name}</h4>
                <Badge value={policy.status} />
                <p className="mono">{policy.id}</p>
                <dl>
                  <dt>实例 / 工作区</dt>
                  <dd className="mono">
                    {policy.instance_id} / {policy.workspace_id}
                  </dd>
                  <dt>动作与触发</dt>
                  <dd>
                    {policy.action_kind} / {policy.trigger_kind}
                  </dd>
                  <dt>UTC 单次时间 / UTC cron</dt>
                  <dd>
                    {policy.scheduled_at ??
                      policy.cron_expression ??
                      "事件触发"}
                  </dd>
                  <dt>精确事件类型 / 聚合 ID</dt>
                  <dd>
                    {policy.event_type ?? "—"} /{" "}
                    {policy.event_aggregate_id ?? "—"}
                  </dd>
                  <dt>委派到期（UTC）</dt>
                  <dd>{policy.delegation_expires_at}</dd>
                  <dt>次数 / 间隔 / 允许延迟</dt>
                  <dd>
                    {policy.emitted_runs} / {policy.run_budget} 次 ·{" "}
                    {policy.minimum_interval_seconds} / {policy.grace_seconds}{" "}
                    秒
                  </dd>
                  <dt>下次到期（UTC）</dt>
                  <dd>{policy.next_due_at ?? "暂无"}</dd>
                </dl>
                {conflict && (
                  <p role="alert">
                    版本已变化。先明确重新读取策略，不能替换未知请求的原版本或原键。
                  </p>
                )}
                {
                  <div className="row">
                    {policy.status === "ACTIVE" && (
                      <Confirm
                        label="暂停策略"
                        target={id}
                        disabled={
                          blocked ||
                          pending ||
                          detail.loading ||
                          conflict ||
                          unresolved
                        }
                        run={() => change("pause")}
                      >
                        <p>暂停后不产生新运行；不会取消已受理的操作。</p>
                      </Confirm>
                    )}
                    {policy.status === "PAUSED" && (
                      <Confirm
                        label="恢复策略"
                        target={id}
                        disabled={
                          blocked ||
                          !resumable.current ||
                          pending ||
                          detail.loading ||
                          conflict ||
                          unresolved
                        }
                        run={() => change("resume")}
                      >
                        <p>恢复时仍会校验当前授权；不会补发错过的触发。</p>
                      </Confirm>
                    )}
                    {["ACTIVE", "PAUSED"].includes(policy.status) && (
                      <Confirm
                        label="永久撤销策略"
                        target={id}
                        disabled={
                          blocked ||
                          pending ||
                          detail.loading ||
                          conflict ||
                          unresolved
                        }
                        run={() => change("revoke")}
                      >
                        <p>
                          撤销不可恢复；已受理操作仍按其原生命周期完成。需要新规则时须重新授权。
                        </p>
                      </Confirm>
                    )}
                  </div>
                }
                <button
                  disabled={pending || runs.loading}
                  onClick={() => {
                    setRunCursor(null);
                    setRunsRead((v) => v + 1);
                  }}
                >
                  刷新运行历史
                </button>
                <Remote state={runs}>
                  {runs.data && (
                    <>
                      <p className="fine">
                        运行历史截止 {date(runs.data.cutoff)}
                      </p>
                      <div className="table-wrap">
                        <table aria-label="自动化运行历史">
                          <caption>自动化运行历史</caption>
                          <thead>
                            <tr>
                              <th>运行 ID</th>
                              <th>状态 / 原动作</th>
                              <th>受理操作</th>
                              <th>到期 / 失败</th>
                              <th>查看</th>
                            </tr>
                          </thead>
                          <tbody>
                            {runs.data.items.map((item) => (
                              <tr key={item.id}>
                                <td className="mono">{item.id}</td>
                                <td>
                                  <Badge value={item.status} />
                                  {item.operation_kind}
                                </td>
                                <td className="mono">
                                  {item.operation_id ?? "尚未受理"}
                                </td>
                                <td>
                                  {date(item.deadline)}
                                  <small>{item.failure_code ?? "—"}</small>
                                </td>
                                <td>
                                  <button
                                    onClick={() => {
                                      setRunId(item.id);
                                      setRunLookup(item.id);
                                    }}
                                  >
                                    查看原运行
                                  </button>
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                      {!runs.data.items.length && (
                        <p>
                          当前页暂无运行；没有运行不代表 worker 已正常运行。
                        </p>
                      )}
                      <button
                        disabled={runs.loading || !runs.data.next_cursor}
                        onClick={() => setRunCursor(runs.data!.next_cursor)}
                      >
                        运行下一页
                      </button>
                    </>
                  )}
                </Remote>
                <form
                  className="row"
                  onSubmit={(e) => {
                    e.preventDefault();
                    if (UUID.test(runLookup)) setRunId(runLookup);
                    else setError(new ApiFailure("INVALID_AUTOMATION_RUN_ID"));
                  }}
                >
                  <Field label="原运行 ID">
                    <input
                      required
                      pattern={UUID.source}
                      value={runLookup}
                      onChange={(e) => setRunLookup(e.target.value.trim())}
                    />
                  </Field>
                  <button>查询原运行</button>
                </form>
                <Remote state={exactRun}>
                  {exactRun.data && (
                    <section
                      data-testid="automation-run-detail"
                      data-run-id={exactRun.data.id}
                    >
                      <h4>原运行 {exactRun.data.id}</h4>
                      <Badge value={exactRun.data.status} />
                      <dl>
                        <dt>原规则版本 / 资源版本 / 运行代次</dt>
                        <dd>
                          {exactRun.data.automation_version} /{" "}
                          {exactRun.data.expected_resource_version} /{" "}
                          {exactRun.data.expected_generation}
                        </dd>
                        <dt>原操作 ID</dt>
                        <dd className="mono">
                          {exactRun.data.operation_id ?? "尚未受理"}
                        </dd>
                        <dt>计划 / 跳过范围（UTC）</dt>
                        <dd>
                          {exactRun.data.scheduled_for ?? "事件"} /{" "}
                          {exactRun.data.skipped_through ?? "无"}
                        </dd>
                        <dt>来源事件 ID / 序号</dt>
                        <dd>
                          {exactRun.data.source_event_id ?? "—"} /{" "}
                          {exactRun.data.source_event_sequence ?? "—"}
                        </dd>
                        <dt>期限（UTC）/ 失败分类</dt>
                        <dd>
                          {exactRun.data.deadline} /{" "}
                          {exactRun.data.failure_code ?? "—"}
                        </dd>
                        <dt>最近观测</dt>
                        <dd>{date(exactRun.data.updated_at)}</dd>
                      </dl>
                    </section>
                  )}
                </Remote>
              </section>
            )}
          </Remote>
          {!detailOnly && contract && (
            <form
              key={draftVersion}
              data-testid="automation-create"
              className="form-grid"
              onChange={() => setProposal(null)}
              onSubmit={(e) => {
                e.preventDefault();
                setError(null);
                try {
                  if (!creatable.current || pending)
                    throw new ApiFailure("AUTOMATION_WRITE_DISABLED");
                  const form = new FormData(e.currentTarget);
                  if (form.get("authorize") !== "on")
                    throw new ApiFailure("AUTOMATION_CONSENT_REQUIRED");
                  const body = buildCreateAutomation(
                    form,
                    contract,
                    features.maxTtl,
                  );
                  if (
                    body.trigger.kind === "EVENT"
                      ? !features.event
                      : !features.scheduled
                  )
                    throw new ApiFailure("AUTOMATION_TRIGGER_UNAVAILABLE");
                  proposalContract.current = contractKey;
                  setProposal(body);
                } catch (failure) {
                  setError(failure);
                }
              }}
            >
              <fieldset disabled={pending} style={{ display: "contents" }}>
                <h4 className="wide">创建有限自动化策略</h4>
                <Field label="策略名称">
                  <input
                    name="name"
                    required
                    maxLength={contract.limits.name_bytes_max}
                    autoComplete="off"
                  />
                </Field>
                <Field label="未来动作">
                  <select
                    name="action_kind"
                    aria-label="未来动作"
                    value={action}
                    onChange={(e) => setAction(e.target.value as typeof action)}
                  >
                    {AUTOMATION_ACTIONS.filter(([kind]) =>
                      contract.supported_actions.includes(kind),
                    ).map(([kind, label]) => (
                      <option key={kind} value={kind}>
                        {kind} · {label}
                      </option>
                    ))}
                  </select>
                </Field>
                <Field label="触发方式">
                  <select
                    name="trigger_kind"
                    aria-label="触发方式"
                    value={trigger}
                    onChange={(e) =>
                      setTrigger(e.target.value as typeof trigger)
                    }
                  >
                    {features.scheduled &&
                      contract.supported_triggers.includes("ONCE") && (
                        <>
                          <option value="ONCE">ONCE · 单次 UTC 时间</option>
                          <option value="CRON_UTC">
                            CRON_UTC · UTC 定时规则
                          </option>
                        </>
                      )}
                    {features.event &&
                      contract.supported_triggers.includes("EVENT") && (
                        <option value="EVENT">EVENT · 精确事件</option>
                      )}
                  </select>
                </Field>
                {trigger === "ONCE" && (
                  <Field
                    label="单次执行时间（UTC）"
                    hint="完整 UTC 时间，例如 2026-10-10T08:00:00Z。"
                  >
                    <input
                      name="once_at"
                      aria-label="单次执行时间（UTC）"
                      required
                      placeholder="YYYY-MM-DDTHH:mm:ssZ"
                    />
                  </Field>
                )}
                {trigger === "CRON_UTC" && (
                  <Field
                    label="UTC cron 表达式"
                    hint="秒/分/时/日/月/周/年七字段；秒必须 0，年必须 *，日与周同时约束，无 DST。"
                  >
                    <input
                      name="cron_expression"
                      required
                      maxLength={contract.limits.cron_expression_bytes_max}
                      defaultValue="0 */15 * * * * *"
                    />
                  </Field>
                )}
                {trigger === "EVENT" && (
                  <>
                    <Field label="精确事件类型">
                      <input
                        name="event_type"
                        required
                        maxLength={contract.limits.event_type_bytes_max}
                      />
                    </Field>
                    <Field label="事件聚合 ID">
                      <input
                        name="aggregate_id"
                        required
                        pattern={UUID.source}
                      />
                    </Field>
                  </>
                )}
                <Field
                  label="委派到期时间（UTC）"
                  hint={`必须有限：超过 ${contract.limits.delegation_lifetime_seconds.exclusive_minimum} 秒、最多 ${contract.limits.delegation_lifetime_seconds.maximum} 秒，且不超过每个真实授权的期限。`}
                >
                  <input
                    name="delegation_expires_at"
                    aria-label="委派到期时间（UTC）"
                    required
                    placeholder="YYYY-MM-DDTHH:mm:ssZ"
                  />
                </Field>
                <Field label="运行次数上限">
                  <input
                    name="run_budget"
                    type="number"
                    min={contract.limits.run_budget.minimum}
                    max={contract.limits.run_budget.maximum}
                    step={1}
                    defaultValue={1}
                    required
                  />
                </Field>
                <Field label="最小间隔（秒）">
                  <input
                    name="minimum_interval_seconds"
                    type="number"
                    min={contract.limits.minimum_interval_seconds.minimum}
                    max={contract.limits.minimum_interval_seconds.maximum}
                    step={1}
                    defaultValue={60}
                    required
                  />
                </Field>
                <Field label="允许延迟（秒）">
                  <input
                    name="grace_seconds"
                    type="number"
                    min={contract.limits.grace_seconds.minimum}
                    max={contract.limits.grace_seconds.maximum}
                    step={1}
                    defaultValue={300}
                    required
                  />
                </Field>
                {["START", "RENEW"].includes(action) && (
                  <Field label="计算租期（秒）">
                    <input
                      name="ttl_seconds"
                      type="number"
                      min={60}
                      max={features.maxTtl}
                      step={1}
                      defaultValue={Math.min(features.maxTtl, 3600)}
                      required
                    />
                  </Field>
                )}
                {action === "EXECUTE" && (
                  <>
                    <Field label="非敏感 argv JSON">
                      <textarea
                        name="argv"
                        required
                        rows={3}
                        placeholder='["可执行程序", "非敏感参数"]'
                        autoComplete="off"
                      />
                    </Field>
                    <Field label="非敏感 public_env JSON">
                      <textarea
                        name="public_env"
                        rows={3}
                        defaultValue="{}"
                        required
                        autoComplete="off"
                      />
                    </Field>
                    <Field label="工作目录">
                      <input name="cwd" defaultValue="/workspace" required />
                    </Field>
                    <Field label="执行超时（秒）">
                      <input
                        name="timeout_seconds"
                        type="number"
                        min={1}
                        max={3600}
                        step={1}
                        defaultValue={60}
                        required
                      />
                    </Field>
                    <Field label="输出上限（字节）">
                      <input
                        name="output_limit_bytes"
                        type="number"
                        min={0}
                        max={16777216}
                        step={1}
                        defaultValue={1048576}
                        required
                      />
                    </Field>
                    <Field label="非敏感客户关联标记">
                      <input
                        name="client_reference"
                        maxLength={128}
                        autoComplete="off"
                      />
                    </Field>
                    <label className="wide check">
                      <input type="checkbox" name="non_sensitive" required />
                      argv 和 public_env
                      不含秘密；参数仅在当前页面内存中保留，服务端将保存私有请求。
                    </label>
                    <label className="wide check">
                      <input
                        type="checkbox"
                        name="hard_stop_instance"
                        required
                      />
                      我授权超时或取消时申请停止整个实例。
                    </label>
                  </>
                )}
                {action === "BACKUP" && (
                  <>
                    <Field label="已批准备份配置 ID">
                      <input
                        name="backup_profile_id"
                        required
                        pattern={UUID.source}
                      />
                    </Field>
                    <Field label="备份保留天数">
                      <input
                        name="retention_days"
                        type="number"
                        min={31}
                        max={3650}
                        step={1}
                        defaultValue={31}
                        required
                      />
                    </Field>
                  </>
                )}
                <label className="wide check">
                  <input type="checkbox" name="authorize" required />
                  我明确授权在期限内按规则提交所选动作
                </label>
                <p className="wide fine">
                  每次发生前服务端重新校验授权、版本、代次与业务条件。STOP/RESTART/DELETE
                  和 EXECUTE 可能需要 instances:hard_stop；EVENT 另需
                  events:read。冷备份仍要求停止、可信关闭及有效配置。原创建参数不进入浏览器持久存储；重载后未知请求必须重新输入完全相同的原
                  JSON，验证摘要后才能重放原键。
                </p>
                <button
                  className="primary"
                  disabled={blocked || pending || unresolved}
                >
                  预览自动化授权
                </button>
              </fieldset>
            </form>
          )}
          {proposal &&
            contract &&
            proposalContract.current === contractKey &&
            !detailOnly && (
              <section data-testid="automation-consent">
                <p>
                  授权 {proposal.name} · {proposal.action.kind} /{" "}
                  {proposal.trigger.kind} · 最多 {proposal.run_budget} 次 · 到期{" "}
                  {proposal.delegation_expires_at}。确认后使用实际新读实例
                  ETag；只受理规则，不证明动作已完成。
                </p>
                <dl>
                  <dt>实际触发规则（UTC）</dt>
                  <dd>
                    {proposal.trigger.kind === "ONCE"
                      ? proposal.trigger.at
                      : proposal.trigger.kind === "CRON_UTC"
                        ? proposal.trigger.expression
                        : `${proposal.trigger.event_type} / ${proposal.trigger.aggregate_id}`}
                  </dd>
                  <dt>最小间隔 / 允许延迟</dt>
                  <dd>
                    {proposal.minimum_interval_seconds} /{" "}
                    {proposal.grace_seconds} 秒
                  </dd>
                  {"ttl_seconds" in proposal.action && (
                    <>
                      <dt>计算租期</dt>
                      <dd>{proposal.action.ttl_seconds} 秒</dd>
                    </>
                  )}
                  {proposal.action.kind === "BACKUP" && (
                    <>
                      <dt>备份配置 / 保留</dt>
                      <dd>
                        {proposal.action.request.profile_id} /{" "}
                        {proposal.action.request.retention_days} 天
                      </dd>
                    </>
                  )}
                  {proposal.action.kind === "EXECUTE" && (
                    <>
                      <dt>执行范围 / 超时 / 输出</dt>
                      <dd>
                        {proposal.action.request.argv.length} 个 argv ·{" "}
                        {proposal.action.request.cwd} ·{" "}
                        {proposal.action.request.timeout_seconds} 秒 ·{" "}
                        {proposal.action.request.output_limit_bytes} 字节 ·
                        超时申请停止实例
                      </dd>
                    </>
                  )}
                </dl>
                <Confirm
                  label="创建自动化策略"
                  target={id}
                  disabled={blocked || pending || unresolved}
                  run={create}
                >
                  <p>
                    确认你授权此实例在有限期限内执行上述未来动作；可能消耗资源、停止计算或删除计算。计算删除保留工作区。命令参数不会在元数据报告中回显。
                  </p>
                </Confirm>
                <button disabled={pending} onClick={() => setProposal(null)}>
                  放弃当前授权草稿
                </button>
              </section>
            )}
        </>
      )}
    </section>
  );
}
function RestoreAutomationPayload({
  context,
  row,
  restored,
  disabled,
}: {
  context: Context;
  row: Intent;
  restored: () => void;
  disabled: boolean;
}) {
  const [value, setValue] = useState(""),
    [pending, setPending] = useState(false),
    [error, setError] = useState<unknown>(null);
  const alive = useRef(true);
  useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
    };
  }, []);
  return (
    <form
      onSubmit={async (e) => {
        e.preventDefault();
        if (disabled || pending) return;
        setPending(true);
        setError(null);
        try {
          if (new TextEncoder().encode(value).length > 65536)
            throw new ApiFailure("INVALID_INTENT_BODY");
          await context.journal.rehydrate(
            context.session,
            row.key,
            JSON.parse(value),
          );
          if (alive.current) {
            setValue("");
            restored();
          }
        } catch (failure) {
          if (alive.current) setError(failure);
        } finally {
          if (alive.current) setPending(false);
        }
      }}
    >
      <Field
        label="完全相同的原自动化创建 JSON"
        hint="仅在内存中输入；摘要不一致不能恢复，不会生成新键或自动提交。"
      >
        <textarea
          aria-label="完全相同的原自动化创建 JSON"
          disabled={disabled || pending}
          required
          value={value}
          onChange={(e) => setValue(e.target.value)}
          autoComplete="off"
          rows={3}
        />
      </Field>
      <button disabled={disabled || pending}>恢复原请求参数</button>
      <ErrorView error={error} />
    </form>
  );
}

function Requests({
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
  const lifetime = useRef<AbortController | null>(null);
  useEffect(() => {
    const controller = new AbortController();
    lifetime.current = controller;
    return () => {
      controller.abort();
      lifetime.current = null;
    };
  }, []);
  const automationFeatures = useAutomationFeatures(
    caps,
    capsLoading,
    capsError,
    project,
  );
  const [automation, setAutomation] = useState<{
    id: string;
    instanceId: string;
  } | null>(null);
  useEffect(() => {
    const features = checkedAutomationFeatures(caps, project);
    if (
      (caps && !features.scheduled && !features.event) ||
      (!capsLoading && !capsError && !caps) ||
      (capsError instanceof ApiFailure &&
        [401, 403, 404].includes(capsError.status ?? 0))
    )
      setAutomation(null);
  }, [caps, capsError, capsLoading, project]);
  const [lookup, setLookup] = useState(""),
    [diagnosis, setDiagnosis] = useState<{
      id: string;
      instanceId: string;
    } | null>(null),
    [operationId, setOperationId] = useState(""),
    [error, setError] = useState<unknown>(null),
    [pending, setPending] = useState(false);
  const rows = useMemo(
    () => context.journal.list(context.session),
    [context.journal, context.session, revision],
  );
  const operation = useRemote(`${operationId}:${revision}`, async (signal) =>
    operationId
      ? unwrap(
          await context.api.client.GET("/v1/operations/{id}", {
            params: {
              header: headers(context.session),
              path: { id: operationId },
            },
            signal,
          }),
        )
      : null,
  );
  async function retry(row: Intent) {
    const controller = lifetime.current;
    if (!controller || controller.signal.aborted) return;
    setPending(true);
    setError(null);
    try {
      const notificationId = notificationAckId(row.path);
      let validateReceipt: ReceiptValidator<unknown> | undefined;
      if (notificationId) {
        if (capsLoading || capsError || !notificationsEnabled(caps, project))
          throw new ApiFailure("AUTOMATION_NOTIFICATIONS_UNAVAILABLE");
        if (row.method !== "POST" || row.etag !== '"1"')
          throw new ApiFailure("INVALID_AUTOMATION_NOTIFICATION");
        // Re-read the immutable notification under the current actor/project.
        // This never replaces the saved ACK key, empty body or original ETag.
        const result = await context.api.client.GET(
          "/v1/automation-notifications/{id}",
          {
            params: {
              header: headers(context.session),
              path: { id: notificationId },
            },
            signal: controller.signal,
          },
        );
        const current = scopedNotification(
          unwrap(result),
          context.session,
          project,
          undefined,
          notificationId,
        );
        notificationEtag(result.response, current.version);
        if (controller.signal.aborted)
          throw new ApiFailure("REQUEST_INTERRUPTED");
        const original = {
          ...current,
          version: 1,
          acknowledged_at: null,
          acknowledged_by: null,
        };
        validateReceipt = (data, response) => {
          const receipt = notificationReceipt(
            data,
            context.session,
            project,
            original,
          );
          if (
            current.version === 2 &&
            (receipt.resource.acknowledged_at !== current.acknowledged_at ||
              receipt.resource.acknowledged_by !== current.acknowledged_by)
          )
            throw new ApiFailure("INVALID_AUTOMATION_NOTIFICATION");
          notificationEtag(response.etag, receipt.resource.version);
        };
      }
      await context.journal.execute(
        context.api,
        context.session,
        row.key,
        validateReceipt,
      );
    } catch (error) {
      if (!controller.signal.aborted) setError(error);
    } finally {
      if (!controller.signal.aborted) {
        setPending(false);
        context.changed();
      }
    }
  }
  return (
    <section className="card">
      <h2>可核对的请求</h2>
      <p className="notice">
        UNKNOWN
        表示当前浏览器无法确认是否受理。显式重试会发送相同请求内容、版本和幂等键。记录保存在同源浏览器本地；自动化创建仅持久保存摘要，原参数只在当前页面内存中保留。重载后必须恢复完全相同的原
        JSON
        才能重放原键；不得生成新请求替代未知结果。其他未核对请求保留原参数；清除记录后须联系管理员核对。已受理仅保留查询依据；会话变化后只展示相同租户与主体的记录。
      </p>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>请求 / 时间</th>
              <th>目标</th>
              <th>状态</th>
              <th>操作 ID</th>
              <th>核对</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr key={row.key}>
                <td>
                  <span className="mono">{row.key}</span>
                  <small>{date(row.createdAt)}</small>
                </td>
                <td className="mono">
                  {row.method} {row.path}
                </td>
                <td>
                  <Badge value={row.state} />
                  {row.error && <small>{row.error}</small>}
                </td>
                <td>
                  {row.operationId ? (
                    <button
                      className="link mono"
                      onClick={() => {
                        setOperationId(row.operationId!);
                        setLookup(row.operationId!);
                      }}
                    >
                      {row.operationId}
                    </button>
                  ) : (
                    "—"
                  )}
                </td>
                <td>
                  {row.state === "ACCEPTED" &&
                    row.method === "POST" &&
                    row.resourceId &&
                    UUID.test(row.resourceId) &&
                    /^\/v1\/instances\/[^/]+\/diagnoses$/.test(row.path) &&
                    UUID.test(row.path.split("/")[3] ?? "") && (
                      <button
                        disabled={!project}
                        onClick={() =>
                          setDiagnosis({
                            id: row.resourceId!,
                            instanceId: row.path.split("/")[3]!,
                          })
                        }
                      >
                        打开报告
                      </button>
                    )}
                  {row.state === "ACCEPTED" &&
                    row.method === "POST" &&
                    row.resourceId &&
                    isAutomationId(row.resourceId) &&
                    /^\/v1\/instances\/[^/]+\/automations$/.test(row.path) &&
                    isAutomationId(row.path.split("/")[3] ?? "") && (
                      <button
                        disabled={
                          !project ||
                          automationFeatures.blocked ||
                          !(
                            automationFeatures.features.scheduled ||
                            automationFeatures.features.event
                          )
                        }
                        onClick={() =>
                          setAutomation({
                            id: row.resourceId!,
                            instanceId: row.path.split("/")[3]!,
                          })
                        }
                      >
                        打开自动化策略
                      </button>
                    )}
                  {["READY", "UNKNOWN"].includes(row.state) &&
                  row.bodySha256 &&
                  !context.journal.hasPayload(context.session, row.key) ? (
                    <RestoreAutomationPayload
                      key={row.key}
                      context={context}
                      row={row}
                      restored={context.changed}
                      disabled={
                        !project ||
                        automationFeatures.blocked ||
                        !(
                          automationFeatures.features.scheduled ||
                          automationFeatures.features.event
                        )
                      }
                    />
                  ) : ["READY", "UNKNOWN"].includes(row.state) ? (
                    <Confirm
                      label={
                        row.state === "READY"
                          ? "发送已记录请求"
                          : "显式重试原请求"
                      }
                      target={row.key}
                      disabled={
                        row.path.includes("/automations") &&
                        (!project ||
                          automationFeatures.blocked ||
                          !(
                            automationFeatures.features.scheduled ||
                            automationFeatures.features.event
                          ))
                      }
                      run={() => retry(row)}
                    >
                      <p>
                        只重放同一个幂等请求，不替换键。若保留期限已过，应联系管理员核对已有资源与操作。
                      </p>
                    </Confirm>
                  ) : null}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {!rows.length && <p className="empty">当前浏览器暂无请求记录。</p>}
      {!project && <p className="muted">选择报告所属项目后可打开诊断报告。</p>}
      {automation && (
        <AutomationPanel
          key={`${automation.id}:${automation.instanceId}:${automationFeatures.features.scheduled}:${automationFeatures.features.event}`}
          context={context}
          id={automation.instanceId}
          project={project}
          features={automationFeatures.features}
          blocked={automationFeatures.blocked}
          initialId={automation.id}
          detailOnly
        />
      )}
      {diagnosis && (
        <DiagnosisPanel
          key={`${diagnosis.id}:${diagnosis.instanceId}`}
          context={context}
          id={diagnosis.instanceId}
          project={project}
          revision={revision}
          enabled={false}
          initialId={diagnosis.id}
          readOnly
        />
      )}
      <form
        className="row"
        onSubmit={(e) => {
          e.preventDefault();
          if (UUID.test(lookup)) setOperationId(lookup);
          else setError(new ApiFailure("INVALID_OPERATION_ID"));
        }}
      >
        <Field label="操作 ID">
          <input
            value={lookup}
            onChange={(e) => setLookup(e.target.value.trim())}
            required
          />
        </Field>
        <button disabled={pending}>查询操作</button>
        <button type="button" onClick={context.changed}>
          刷新状态
        </button>
      </form>
      <ErrorView error={error} />
      <Remote state={operation}>
        {operation.data && (
          <>
            <Badge value={operation.data.status} />
            <p>
              阶段 {operation.data.stage} · 最后更新{" "}
              {date(operation.data.updated_at)}
            </p>
            <Json value={operation.data} />
          </>
        )}
      </Remote>
    </section>
  );
}
