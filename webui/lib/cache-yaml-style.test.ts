import { describe, expect, it } from "vitest";
import { parseOxiDnsYaml } from "./oxidns-config";
import { patchPluginsYaml } from "./oxidns-config-patch";

describe("cache single-field source style", () => {
  it("preserves an unterminated whitespace-only last line", () => {
    for (const spaces of [" ", "  ", "      "]) {
      const source =
        "plugins:\n  - tag: cache\n    type: cache\n    args:\n      lazy_cache_ttl: 86400\n      dump_interval: 7200\n" +
        spaces;
      const before = parseOxiDnsYaml(source).config!;
      const after = structuredClone(before);
      (after.plugins[0].args as Record<string, unknown>).lazy_cache_ttl =
        864090;
      expect(patchPluginsYaml(source, before, after)).toEqual({
        status: "patched",
        content: source.replace("86400", "864090"),
      });
    }
  });
  it.each(["\n", "\r\n"])(
    "preserves whitespace-only separators after args (%j)",
    (eol) => {
      for (const separator of ["", "  ", "      "]) {
        for (const next of [
          "",
          "  - tag: other\n    type: debug_print\n",
          "log: {level: info}\n",
        ]) {
          const source = (
            "plugins:\n  - tag: cache\n    type: cache\n    args:\n      size: 81920\n      lazy_cache_ttl: 86400\n      dump_file: /var/lib/oxidns/cache.dump\n      dump_interval: 7200\n" +
            separator +
            "\n" +
            next
          ).replaceAll("\n", eol);
          const before = parseOxiDnsYaml(source).config!;
          const after = structuredClone(before);
          (after.plugins[0].args as Record<string, unknown>).lazy_cache_ttl =
            864090;
          expect(patchPluginsYaml(source, before, after)).toEqual({
            status: "patched",
            content: source.replace(
              "lazy_cache_ttl: 86400",
              "lazy_cache_ttl: 864090",
            ),
          });
        }
      }
    },
  );
  it("separates added form fields at EOF without introducing a final newline", () => {
    const source =
      "plugins:\n- tag: cache\n  type: cache\n  args:\n    lazy_cache_ttl: 1";
    const before = parseOxiDnsYaml(source).config!;
    const after = structuredClone(before);
    after.plugins[0].args = { lazy_cache_ttl: 2, size: 81920 };
    const result = patchPluginsYaml(source, before, after);
    expect(result).toEqual({
      status: "patched",
      content: source.replace(
        "lazy_cache_ttl: 1",
        "lazy_cache_ttl: 2\n    size: 81920",
      ),
    });
  });

  it("does not rebuild unchanged empty YAML values", () => {
    const source =
      "plugins:\n- tag: cache\n  type: cache\n  args:\n    size: # unchanged empty\n    lazy_cache_ttl: 1\n";
    const before = parseOxiDnsYaml(source).config!;
    const after = structuredClone(before);
    (after.plugins[0].args as Record<string, unknown>).lazy_cache_ttl = 2;
    expect(patchPluginsYaml(source, before, after)).toEqual({
      status: "patched",
      content: source.replace("lazy_cache_ttl: 1", "lazy_cache_ttl: 2"),
    });
  });
  it("retains block args style when an explicit rebuild is needed", () => {
    const source =
      "plugins:\n  - tag: cache\n    type: cache\n    args:\n      size: 81920\n      lazy_cache_ttl: { old: 1 }\n      dump_interval: 7200\n";
    const before = parseOxiDnsYaml(source).config!;
    const after = structuredClone(before);
    (after.plugins[0].args as Record<string, unknown>).lazy_cache_ttl = 864000;
    (after.plugins[0].args as Record<string, unknown>).size = 81921;
    const result = patchPluginsYaml(source, before, after);
    expect(result.status).toBe("needs_confirmation");
    if (result.status !== "needs_confirmation") return;
    expect(result.candidate?.content).toContain("args:\n      size: 81921\n");
    expect(result.candidate?.content).not.toContain("args:\n      {");
  });
  for (const indent of [2, 4]) {
    for (const value of [86400, "86400"]) {
      it(`patches lazy_cache_ttl only, indent=${indent}, type=${typeof value}`, () => {
        const pad = " ".repeat(indent);
        const source = `plugins:\n${pad}- tag: cache\n${pad}  type: cache\n${pad}  args:\n${pad}    size: 81920\n${pad}    lazy_cache_ttl: 86400 # retain\n${pad}    dump_file: /var/lib/oxidns/cache.dump\n${pad}    dump_interval: 7200\n`;
        const before = parseOxiDnsYaml(source).config!;
        const after = structuredClone(before);
        (after.plugins[0].args as Record<string, unknown>).lazy_cache_ttl =
          typeof value === "number" ? 864000 : "864000";
        const result = patchPluginsYaml(source, before, after);
        expect(result.status).toBe("patched");
        if (result.status !== "patched") throw new Error(result.reason);
        expect(result.content).toBe(
          source.replace(
            "86400 #",
            typeof value === "number" ? "864000 #" : '"864000" #',
          ),
        );
      });
    }
  }
});
