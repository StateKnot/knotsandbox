import test from "node:test";
import assert from "node:assert/strict";
import { localDate, expiry } from "../src/account-expiry.ts";
import { ApiFailure } from "../src/api.ts";

test("grant expiry retains the original microseconds after native datetime-local normalization in UTC, Shanghai and the DST fold", () => {
  const previous = process.env.TZ;
  try {
    for (const [zone, displayed] of [
      ["UTC", "2026-11-01T06:30:00.123"],
      ["Asia/Shanghai", "2026-11-01T14:30:00.123"],
      ["America/New_York", "2026-11-01T01:30:00.123"],
    ]) {
      process.env.TZ = zone;
      const original = "2026-11-01T06:30:00.123456Z";
      assert.equal(localDate(original), displayed);
      const form = new FormData();
      form.set("expires_at", displayed!);
      assert.equal(expiry(form, "permanent", "expires_at", original), original);
      const submillisecond = "2026-11-01T06:30:00.000987Z";
      form.set("expires_at", localDate(submillisecond).slice(0, 16));
      assert.equal(
        expiry(form, "permanent", "expires_at", submillisecond),
        submillisecond,
      );
      const trailingZero = "2026-11-01T06:30:00.120987Z";
      form.set("expires_at", localDate(trailingZero).replace(/0$/, ""));
      assert.equal(
        expiry(form, "permanent", "expires_at", trailingZero),
        trailingZero,
      );
      if (zone === "America/New_York") {
        assert.notEqual(new Date(displayed!).getTime(), Date.parse(original));
      }
      form.set("expires_at", "2026-11-02T12:00");
      assert.equal(
        expiry(form, "permanent", "expires_at", original),
        new Date("2026-11-02T12:00").toISOString(),
      );
      assert.equal(
        expiry(form, "permanent", "expires_at"),
        new Date("2026-11-02T12:00").toISOString(),
      );
    }
  } finally {
    if (previous === undefined) delete process.env.TZ;
    else process.env.TZ = previous;
  }
});

test("no expiry is an explicit choice, including when a prior finite grant is edited", () => {
  const form = new FormData();
  form.set("permanent", "on");
  assert.equal(expiry(form, "permanent", "expires_at"), null);
  assert.equal(
    expiry(form, "permanent", "expires_at", "2026-11-01T06:30:00.123456Z"),
    null,
  );
  assert.equal(localDate(null), "");
});

test("missing, empty and invalid finite expiry fails before any mutation", () => {
  for (const value of [null, "", "not-a-date"]) {
    const form = new FormData();
    if (value !== null) form.set("expires_at", value);
    assert.throws(
      () => expiry(form, "permanent", "expires_at"),
      (error) =>
        error instanceof ApiFailure && error.code === "INVALID_GRANT_EXPIRY",
    );
  }
});
