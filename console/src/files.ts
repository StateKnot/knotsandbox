import { ApiFailure, ETAG, fileData, UUID } from "./api.ts";
import type { BrowserApi, Schema, Session } from "./api.ts";
const PART = 1024 * 1024;
export const MAX_FILE_BYTES = 100 * PART;
export async function sha(bytes: Uint8Array<ArrayBuffer>): Promise<string> {
  return Array.from(
    new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)),
    (v) => v.toString(16).padStart(2, "0"),
  ).join("");
}
export function workspacePath(value: string): string {
  if (
    !value ||
    new TextEncoder().encode(value).length > 4096 ||
    value.split("/").some((c) => !c || c === "." || c === "..") ||
    /[\\\x00-\x1f\x7f]/.test(value)
  )
    throw new ApiFailure("INVALID_WORKSPACE_PATH");
  return value;
}
/** Sends every staged part exactly once. A failure retains the transfer ID for reconciliation. */
export async function stageFile(
  api: BrowserApi,
  session: Session,
  transfer: Schema["FileTransfer"],
  file: File,
  signal: AbortSignal,
  onPart: (index: number) => void,
): Promise<void> {
  if (
    !UUID.test(transfer.id) ||
    transfer.direction !== "UPLOAD" ||
    transfer.status !== "WAITING_UPLOAD" ||
    file.size !== transfer.byte_limit ||
    file.size > MAX_FILE_BYTES
  )
    throw new ApiFailure("INVALID_FILE_TRANSFER");
  const etag = `"${transfer.version}"`;
  if (!ETAG.test(etag)) throw new ApiFailure("INVALID_TRANSFER_VERSION");
  for (let offset = 0, index = 0; offset < file.size; offset += PART, index++) {
    signal.throwIfAborted();
    const bytes = new Uint8Array(
      await file.slice(offset, offset + PART).arrayBuffer(),
    );
    const digest = await sha(bytes);
    const headers = new Headers({
      "content-type": "application/octet-stream",
      "x-content-sha256": digest,
      "if-match": etag,
    });
    // Browsers own Content-Length; a Uint8Array body provides a known byte length.
    const result = await fileData(
      api,
      session,
      `/v1/file-transfers/${transfer.id}/content/${index}`,
      "PUT",
      headers,
      bytes,
      65536,
      signal,
    );
    if (
      result.headers.get("content-type")?.split(";", 1)[0]?.trim() !==
        "application/json" ||
      result.headers.get("etag") !== etag
    )
      throw new ApiFailure("INVALID_FILE_ACKNOWLEDGEMENT");
    const v: unknown = JSON.parse(new TextDecoder().decode(result.bytes));
    if (
      typeof v !== "object" ||
      v === null ||
      !("index" in v) ||
      v.index !== index ||
      !("sha256" in v) ||
      v.sha256 !== digest ||
      !("byte_length" in v) ||
      v.byte_length !== bytes.length ||
      !("transfer_version" in v) ||
      v.transfer_version !== transfer.version
    )
      throw new ApiFailure("INVALID_FILE_ACKNOWLEDGEMENT");
    onPart(index);
  }
}
/** No unverified or partial content is returned to the UI. */
export async function verifiedDownload(
  api: BrowserApi,
  session: Session,
  transfer: Schema["FileTransfer"],
  signal: AbortSignal,
): Promise<Blob> {
  if (
    transfer.direction !== "DOWNLOAD" ||
    transfer.status !== "SUCCEEDED" ||
    !UUID.test(transfer.id) ||
    transfer.content_status !== "FROZEN" ||
    transfer.observed_bytes === null ||
    transfer.observed_bytes < 0 ||
    transfer.observed_bytes > MAX_FILE_BYTES ||
    transfer.observed_sha256 === null ||
    !/^[a-f0-9]{64}$/.test(transfer.observed_sha256)
  )
    throw new ApiFailure("DOWNLOAD_NOT_READY");
  const { bytes, headers } = await fileData(
    api,
    session,
    `/v1/file-transfers/${transfer.id}/content`,
    "GET",
    new Headers({ accept: "application/octet-stream" }),
    undefined,
    transfer.observed_bytes,
    signal,
  );
  if (
    headers.get("content-type")?.split(";", 1)[0]?.trim() !==
      "application/octet-stream" ||
    (headers.get("content-encoding") &&
      headers.get("content-encoding") !== "identity") ||
    headers.get("content-length") !== String(transfer.observed_bytes) ||
    headers.get("x-content-sha256") !== transfer.observed_sha256 ||
    headers.get("etag") !== `"${transfer.version}"` ||
    bytes.length !== transfer.observed_bytes ||
    (await sha(bytes)) !== transfer.observed_sha256
  )
    throw new ApiFailure("FILE_INTEGRITY_FAILED");
  return new Blob([bytes], { type: "application/octet-stream" });
}
