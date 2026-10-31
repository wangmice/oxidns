import { ApiResponseError } from "@/lib/oxidns-api";
import { WEBUI } from "@/lib/i18n/keys";

export function normalizeCacheFilters(qname: string, ip: string) {
  return { qname: qname.trim(), ip: ip.trim() };
}

export function cacheEntryError(error: unknown, t: (key: string) => string) {
  if (error instanceof ApiResponseError && error.code === "invalid_cache_ip") {
    return t(WEBUI.cache.invalidIp);
  }
  return error instanceof Error ? error.message : t(WEBUI.cache.readEntriesFailed);
}
