import { ApiFailure } from "./api.ts";

export function localDate(value: string | null) {
  if (!value) return "";
  const date = new Date(value);
  return new Date(date.getTime() - date.getTimezoneOffset() * 60000)
    .toISOString()
    .slice(0, -1);
}
export function expiry(
  form: FormData,
  permanent: string,
  timestamp: string,
  original?: string | null,
) {
  if (form.has(permanent)) return null;
  const value = String(form.get(timestamp));
  const date = new Date(value);
  if (!value || !Number.isFinite(date.getTime()))
    throw new ApiFailure("INVALID_GRANT_EXPIRY");
  if (original && date.getTime() === new Date(localDate(original)).getTime())
    return original;
  return date.toISOString();
}
