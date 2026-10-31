import { describe, expect, it } from "vitest";
import { cacheEntryError, normalizeCacheFilters } from "./cache-filters";
import { ApiResponseError } from "@/lib/oxidns-api";
import { WEBUI } from "@/lib/i18n/keys";

describe("cache filter state", () => {
  it("applies both inputs together without rewriting IP syntax", () => {
    expect(normalizeCacheFilters(" example.com ", " 2001:0DB8::1 ")).toEqual({ qname: "example.com", ip: "2001:0DB8::1" });
  });
  it("clears both filters with empty inputs", () => {
    expect(normalizeCacheFilters("", "")).toEqual({ qname: "", ip: "" });
    expect(normalizeCacheFilters(" ", " ")).toEqual({ qname: "", ip: "" });
  });
  it("allows an IP-only filter", () => {
    expect(normalizeCacheFilters("", "192.0.2.1")).toEqual({ qname: "", ip: "192.0.2.1" });
  });
  it("maps invalid_cache_ip to localized copy and preserves other errors", () => {
    const t = (key: string) => `localized:${key}`;
    expect(cacheEntryError(new ApiResponseError("raw", 400, "invalid_cache_ip"), t)).toBe(`localized:${WEBUI.cache.invalidIp}`);
    expect(cacheEntryError(new Error("other"), t)).toBe("other");
    expect(cacheEntryError(null, t)).toBe(`localized:${WEBUI.cache.readEntriesFailed}`);
  });
});
