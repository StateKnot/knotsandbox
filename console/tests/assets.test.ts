import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  mkdtempSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
function fixture() {
  const root = mkdtempSync(join(tmpdir(), "sandbox-console-assets-"));
  const current = join(root, "current"),
    previous = join(root, "previous");
  for (const p of [current, previous])
    mkdirSync(join(p, "assets"), { recursive: true });
  return { root, current, previous };
}
function run(current: string, previous: string, first: boolean) {
  return spawnSync(
    process.execPath,
    [resolve("scripts/prepare-assets.mjs"), current, previous, String(first)],
    { encoding: "utf8" },
  );
}
test("first build manifest is explicit and later builds retain verified old assets", () => {
  const f = fixture();
  try {
    writeFileSync(join(f.current, "assets", "index-new.js"), "new");
    writeFileSync(
      join(f.previous, "bundle-manifest.json"),
      JSON.stringify({ schema: 1, assets: {} }),
    );
    assert.notEqual(run(f.current, f.previous, false).status, 0);
    assert.equal(run(f.current, f.previous, true).status, 0);
    writeFileSync(join(f.previous, "assets", "index-old.js"), "old");
    writeFileSync(
      join(f.previous, "bundle-manifest.json"),
      JSON.stringify({
        schema: 1,
        assets: {
          "index-old.js": createHash("sha256").update("old").digest("hex"),
        },
      }),
    );
    assert.equal(run(f.current, f.previous, false).status, 0);
    assert.equal(
      readFileSync(join(f.current, "assets", "index-old.js"), "utf8"),
      "old",
    );
    assert.equal(
      Object.keys(
        JSON.parse(
          readFileSync(join(f.current, "bundle-manifest.json"), "utf8"),
        ).assets,
      ).length,
      2,
    );
  } finally {
    rmSync(f.root, { recursive: true });
  }
});
test("digest mismatch and asset path escape fail the release build", () => {
  const f = fixture();
  try {
    writeFileSync(join(f.current, "assets", "index-new.js"), "new");
    writeFileSync(join(f.previous, "assets", "index-old.js"), "tampered");
    for (const entry of [
      { "index-old.js": "a".repeat(64) },
      { "../secret.js": "a".repeat(64) },
    ]) {
      writeFileSync(
        join(f.previous, "bundle-manifest.json"),
        JSON.stringify({ schema: 1, assets: entry }),
      );
      assert.notEqual(run(f.current, f.previous, false).status, 0);
    }
  } finally {
    rmSync(f.root, { recursive: true });
  }
});
