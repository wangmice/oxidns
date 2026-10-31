import { afterEach, describe, expect, it, vi } from "vitest";
import { fetchCacheEntries } from "./oxidns-api";

const fetchMock = vi.fn();
vi.stubGlobal("fetch", fetchMock);
afterEach(() => fetchMock.mockReset());

const payload = { entries: [], total_entries: 0 };

describe("cache entries API filters", () => {
  it("encodes IPv6 while preserving the domain filter and pagination cursor", async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify(payload)));
    const options = {
      limit: 100,
      cursor: "snapshot+/=",
      qname: "example.com",
      ip: "2001:db8::1",
    };
    expect(await fetchCacheEntries("cache primary", options)).toEqual(payload);
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/plugins/cache%20primary/entries?limit=100&cursor=snapshot%2B%2F%3D&qname=example.com&ip=2001%3Adb8%3A%3A1",
      expect.objectContaining({ method: "GET" }),
    );
  });

  it.each([undefined, ""])("omits an empty IP filter (%s)", async (ip) => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify(payload)));
    await fetchCacheEntries("cache", { qname: "example.com", ip });
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/plugins/cache/entries?qname=example.com",
      expect.any(Object),
    );
  });

  it("sends an IPv4-only filter without requiring a domain", async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify(payload)));
    await fetchCacheEntries("cache", { ip: "192.0.2.1" });
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/plugins/cache/entries?ip=192.0.2.1",
      expect.any(Object),
    );
  });

  it("preserves the invalid_cache_ip error code for localized feedback", async () => {
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify({ message: "Invalid IP", code: "invalid_cache_ip" }), { status: 400 }),
    );
    await expect(fetchCacheEntries("cache", { ip: "not-an-ip" })).rejects.toMatchObject({
      name: "ApiResponseError", status: 400, code: "invalid_cache_ip",
    });
  });
});
