import { describe, expect, it } from "vitest";
import { parseDocument } from "yaml";
import { parseOxiDnsYaml, type OxiDnsConfig } from "./oxidns-config";
import { patchConfigYaml, patchPluginsYaml } from "./oxidns-config-patch";

function check(
  source: string,
  expected: string,
  change: (c: OxiDnsConfig) => void,
  plugins = false,
) {
  const before = parseOxiDnsYaml(source).config!;
  expect(before).toBeDefined();
  const after = structuredClone(before);
  change(after);
  const result = (plugins ? patchPluginsYaml : patchConfigYaml)(
    source,
    before,
    after,
  );
  expect(result).toEqual({ status: "patched", content: expected });
  if (result.status === "patched") {
    expect(parseOxiDnsYaml(result.content).config).toEqual(after);
    const raw = parseDocument(result.content).toJSON();
    if (raw.plugins?.length) expect(raw.plugins[0].future).toBe("keep");
  }
}

const selections = [[0], [1], [2], [0, 1, 2]];
describe("authorized source-range deletions", () => {
  for (const eol of ["\n", "\r\n"])
    for (const eof of [true, false]) {
      const style = (s: string) =>
        "\uFEFF---" +
        eol +
        (eof ? s : s.replace(/\n$/, "")).replaceAll("\n", eol);
      for (const remove of selections) {
        it(`root ${remove} ${JSON.stringify(eol)} eof=${eof}`, () => {
          const lines = [
            "a: 1 # inline\n",
            "b:\n  # subtree\n  value: |-\n    # literal\n    text\n  # subtree tail\n",
            "c: 3 # inline\n",
          ];
          const assemble = (deleted: number[]) =>
            style(
              lines
                .map(
                  (line, i) =>
                    `# before ${i}\n  \n` +
                    (deleted.includes(i) ? "" : line) +
                    `# after ${i}\n`,
                )
                .join("") + "plugins: []\n# footer\n",
            );
          check(assemble([]), assemble(remove), (c) => {
            for (const i of remove) delete c[["a", "b", "c"][i]];
          });
        });
        for (const kind of ["nested", "scalar", "plugin"] as const) {
          it(`${kind} ${remove} ${JSON.stringify(eol)} eof=${eof}`, () => {
            const indent = kind === "plugin" ? "  " : "    ";
            const entries = [0, 1, 2].map((i) =>
              kind === "plugin"
                ? `  - tag: p${i} # inline\n    type: reject\n    future: keep\n    args:\n      # subtree\n      rcode: REFUSED\n    # subtree tail\n`
                : kind === "scalar"
                  ? `    - ${i} # inline\n`
                  : `    k${i}:\n      # subtree\n      text: |-\n        # literal\n        body\n      # subtree tail\n`,
            );
            const assemble = (deleted: number[]) =>
              style(
                (kind === "plugin"
                  ? "plugins:\n"
                  : "plugins: []\ncustom:\n  values:\n") +
                  entries
                    .map(
                      (line, i) =>
                        `${indent}# before ${i}\n${indent} \n` +
                        (deleted.includes(i)
                          ? deleted.length === 3 && i === 0
                            ? `${indent}${kind === "nested" ? "{}" : "[]"}\n`
                            : ""
                          : line) +
                        `${indent}# after ${i}\n`,
                    )
                    .join("") +
                  "# footer\nlog: {level: info}\n",
              );
            check(
              assemble([]),
              assemble(remove),
              (c) => {
                if (kind === "plugin")
                  c.plugins = c.plugins.filter((_, i) => !remove.includes(i));
                else {
                  const custom = c.custom as {
                    values: Record<string, unknown> | number[];
                  };
                  if (kind === "scalar")
                    custom.values = (custom.values as number[]).filter(
                      (_, i) => !remove.includes(i),
                    );
                  else
                    for (const i of remove)
                      delete (custom.values as Record<string, unknown>)[
                        `k${i}`
                      ];
                }
              },
              kind === "plugin",
            );
          });
        }
      }
    }
  it.each([false, true])(
    "deletes plugin args fields through both entry points (%s)",
    (plugins) => {
      const source =
        "plugins:\n  - tag: p\n    type: reject\n    future: keep\n    args:\n      # before\n       \n      gone:\n        # subtree\n        x: 1\n      # after\n      rcode: REFUSED\n";
      check(
        source,
        source.replace("      gone:\n        # subtree\n        x: 1\n", ""),
        (c) => {
          delete (c.plugins[0].args as Record<string, unknown>).gone;
        },
        plugins,
      );
    },
  );
  it("retains a BOM without a document marker and mixed line endings", () => {
    const source = "\uFEFFgone: 1 # inline\r\n  \r\n# sibling\nkeep: 2";
    check(source, "\uFEFF  \r\n# sibling\nkeep: 2", (c) => {
      delete c.gone;
    });
  });
  it("combines deletion with scalar edits without moving trivia", () => {
    const source = "gone: 1\n  \n# adjacent\nkeep: 2\n";
    check(source, "  \n# adjacent\nkeep: 3\n", (c) => {
      delete c.gone;
      c.keep = 3;
    });
  });
  it("deletes every root field without losing the BOM", () => {
    check("\uFEFFa: 1\n# tail\n", "\uFEFF{}\n# tail\n", (c) => {
      delete c.a;
    });
  });
  it.each(["\n", "\r\n"])(
    "deletes a complete plugin through the full-config entry point (%j)",
    (eol) => {
      const source =
        "plugins:\n  # before\n   \n  - tag: p\n    type: reject\n    args:\n      # inside\n      rcode: REFUSED\n  # after\nlog: {level: info}\n".replaceAll(
          "\n",
          eol,
        );
      check(
        source,
        "plugins:\n  # before\n   \n  []\n  # after\nlog: {level: info}\n".replaceAll(
          "\n",
          eol,
        ),
        (c) => {
          c.plugins = [];
        },
      );
    },
  );
  it("retains # literal text in an untouched block scalar", () => {
    const source =
      "custom:\n  message: |-\n    # literal\n    body\n  gone: 1 # inline\n  # sibling\n  stay: 2\n";
    check(source, source.replace("  gone: 1 # inline\n", ""), (c) => {
      delete (c.custom as Record<string, unknown>).gone;
    });
  });
  it("does not accept loss of standalone comments in flow deletions", () => {
    const source = "custom: {\n  # before\n  a: 1,\n  # between\n  b: 2\n}\n";
    const before = parseOxiDnsYaml(source).config!;
    const after = structuredClone(before);
    delete (after.custom as Record<string, unknown>).a;
    const result = patchConfigYaml(source, before, after);
    if (result.status === "patched") {
      expect(result.content).toContain("  # before\n");
      expect(result.content).toContain("  # between\n");
      expect(parseOxiDnsYaml(result.content).config).toEqual(after);
    } else expect(result).not.toHaveProperty("candidate");
  });
  it.each(selections)("validates flow deletion %j", (...remove) => {
    const source = "custom: {a: 1, b: 2, c: 3}\nnetwork: {values: [1, 2, 3]}\n";
    const before = parseOxiDnsYaml(source).config!;
    const after = structuredClone(before);
    for (const i of remove)
      delete (after.custom as Record<string, unknown>)[["a", "b", "c"][i]];
    after.network!.values = [1, 2, 3].filter((_, i) => !remove.includes(i));
    const result = patchConfigYaml(source, before, after);
    expect(result.status).toBe("patched");
    if (result.status === "patched")
      expect(parseOxiDnsYaml(result.content).config).toEqual(after);
  });
});
