/** Merge only SHA-256 verified content-hash assets from a reviewed prior image. */
import { createHash } from "node:crypto";
import {
  lstatSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  writeFileSync,
} from "node:fs";
import { join, resolve } from "node:path";
const [currentArg, previousArg, firstRelease] = process.argv.slice(2);
if (!currentArg || !previousArg || !["true", "false"].includes(firstRelease))
  throw Error(
    "Use prepare-assets CURRENT_DIST PREVIOUS_DIST FIRST_RELEASE_BOOLEAN",
  );
const current = resolve(currentArg),
  previous = resolve(previousArg);
for (const dir of [current, previous]) {
  const stat = lstatSync(dir);
  if (!stat.isDirectory() || stat.isSymbolicLink())
    throw Error("Asset roots must be real directories");
}
const name = /^[A-Za-z0-9_-]+\.(?:js|css)$/;
function read(path, maximum) {
  const s = lstatSync(path);
  if (!s.isFile() || s.isSymbolicLink() || s.size > maximum)
    throw Error("Asset source must be a bounded regular file");
  return readFileSync(path);
}
const prior = JSON.parse(
  read(join(previous, "bundle-manifest.json"), 1024 * 1024).toString("utf8"),
);
if (
  prior.schema !== 1 ||
  !prior.assets ||
  typeof prior.assets !== "object" ||
  Array.isArray(prior.assets) ||
  Object.keys(prior).length !== 2
)
  throw Error("Invalid prior asset manifest");
const priorNames = Object.keys(prior.assets);
if (
  priorNames.length > 200 ||
  (firstRelease === "true" && priorNames.length) ||
  (firstRelease === "false" && !priorNames.length)
)
  throw Error(
    "First release requires empty prior assets; later release requires a reviewed prior bundle",
  );
if (priorNames.length) {
  const stat = lstatSync(join(previous, "assets"));
  if (!stat.isDirectory() || stat.isSymbolicLink())
    throw Error("Prior asset directory must be real");
}
const merged = {};
let bytes = 0;
function digest(data) {
  return createHash("sha256").update(data).digest("hex");
}
mkdirSync(join(current, "assets"), { recursive: true });
for (const file of readdirSync(join(current, "assets"))) {
  if (!name.test(file)) throw Error("Unexpected generated asset");
  const data = read(join(current, "assets", file), 8 * 1024 * 1024);
  merged[file] = digest(data);
  bytes += data.length;
}
for (const file of priorNames) {
  if (!name.test(file) || !/^[a-f0-9]{64}$/.test(prior.assets[file]))
    throw Error("Invalid prior asset identity");
  const source = join(previous, "assets", file),
    data = read(source, 8 * 1024 * 1024),
    sha = digest(data);
  if (sha !== prior.assets[file]) throw Error("Prior asset digest mismatch");
  if (merged[file] && merged[file] !== sha)
    throw Error("Content-hash filename collision");
  if (!merged[file]) {
    writeFileSync(join(current, "assets", file), data);
    merged[file] = sha;
    bytes += data.length;
  }
}
if (Object.keys(merged).length > 200 || bytes > 40 * 1024 * 1024)
  throw Error("Asset retention exceeds reviewed build limit");
writeFileSync(
  join(current, "bundle-manifest.json"),
  JSON.stringify({ schema: 1, assets: merged }, null, 2) + "\n",
);
process.stdout.write(
  JSON.stringify({
    verified_assets: Object.keys(merged).length,
    bytes,
    first_release: firstRelease === "true",
  }) + "\n",
);
