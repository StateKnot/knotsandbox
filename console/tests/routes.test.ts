import test from "node:test";
import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import { BrowserApi, instanceActionPath } from "../src/api.ts";
import type { Session } from "../src/api.ts";

const id = "00000000-0000-4000-8000-000000000001";
for (const action of ["start", "stop", "restart", "renew"] as const) {
  test(`lifecycle ${action} dispatches the exact server action route with concurrency and CSRF headers`, async () => {
    let request: Request | undefined;
    const api = new BrowserApi(
      "https://console.example",
      () => {},
      async (r) => {
        request = r as Request;
        return new Response("{}", {
          status: 202,
          headers: { "content-type": "application/json" },
        });
      },
    );
    const session: Session = {
      tenant_id: id,
      principal_id: id,
      csrf_token: "a".repeat(43),
      absolute_expires_at: new Date().toISOString(),
      idle_expires_at: new Date().toISOString(),
    };
    api.setSession(session);
    await api.raw(
      instanceActionPath(id, action),
      "POST",
      action === "renew" ? { expires_at: new Date().toISOString() } : {},
      { "if-match": '"7"', "idempotency-key": id },
    );
    assert.equal(
      request?.url,
      `https://console.example/v1/instances/${id}/actions/${action}`,
    );
    assert.equal(request?.method, "POST");
    assert.equal(request?.headers.get("x-csrf-token"), session.csrf_token);
    assert.equal(request?.headers.get("if-match"), '"7"');
    assert.equal(request?.headers.get("idempotency-key"), id);
  });
}

test("every console source API path exists in both OpenAPI and actual Rust routes", async () => {
  const read = (path: string) =>
    readFile(new URL(path, import.meta.url), "utf8");
  const contract = await read("../../openapi/sandbox-api.yaml");
  const rust =
    (await read("../../src/api.rs")) +
    (await read("../../src/file_api.rs")) +
    (await read("../../src/automation_api.rs"));
  const defined = new Set(
    [...contract.matchAll(/^  ["']?(\/v1\/[^"':\n]+)["']?:/gm)].map(
      (m) => m[1],
    ),
  );
  const actual = new Set(
    [...rust.matchAll(/"(\/v1\/[^"\n]+)"/g)].map((m) => m[1]),
  );
  const shape = (path: string) => path.replace(/\{[^}]+\}/g, "{}");
  const definedShapes = new Set([...defined].map(shape));
  const actualShapes = new Set([...actual].map(shape));
  let checked = 0;
  for (const filename of await readdir(new URL("../src/", import.meta.url))) {
    if (!/\.tsx?$/.test(filename)) continue;
    const source = await read(`../src/${filename}`);
    for (const match of source.matchAll(/["`](\/v1\/[^"`\n]+)["`]/g)) {
      const path = match[1]!.replace(/\$\{[^}]+\}/g, "{}");
      assert.ok(
        definedShapes.has(shape(path)),
        `${filename}: OpenAPI is missing ${path}`,
      );
      assert.ok(
        actualShapes.has(shape(path)),
        `${filename}: server is missing ${path}`,
      );
      checked++;
    }
  }
  assert.ok(checked >= 20);
});

test("offered project actions are delegable under the latest formal SQL contract", async () => {
  const directory = new URL("../../migrations/", import.meta.url);
  let allowed: string[] = [];
  for (const filename of (await readdir(directory))
    .filter((name) => name.endsWith(".sql"))
    .sort()) {
    const sql = await readFile(new URL(filename, directory), "utf8");
    for (const match of sql.matchAll(
      /delegated_action NOT IN\s*\(([^)]+)\)/g,
    )) {
      allowed = [...match[1]!.matchAll(/'([^']+)'/g)].map((value) => value[1]!);
    }
  }
  assert.ok(allowed.includes("grants:write"));
  const source = await readFile(
    new URL("../src/Accounts.tsx", import.meta.url),
    "utf8",
  );
  const list = source.match(/const actions:[\s\S]*?=\s*\[([\s\S]*?)\];/);
  assert.ok(list, "account action choices must be explicit");
  const offered = [...list[1]!.matchAll(/"([^"]+)"/g)].map(
    (value) => value[1]!,
  );
  assert.ok(offered.length >= 20);
  for (const action of offered)
    assert.ok(allowed.includes(action), `formal SQL cannot delegate ${action}`);
});
