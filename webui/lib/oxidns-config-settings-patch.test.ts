import { describe, expect, it } from "vitest";
import { parseOxiDnsYaml, type OxiDnsConfig } from "./oxidns-config";
import { patchConfigYaml } from "./oxidns-config-patch";

function config(source: string): OxiDnsConfig {
  const parsed = parseOxiDnsYaml(source);
  expect(parsed.config, parsed.diagnostics.join("\n")).toBeDefined();
  return parsed.config!;
}

function patched(source: string, change: (after: OxiDnsConfig) => void) {
  const before = config(source);
  const after = structuredClone(before);
  change(after);
  const result = patchConfigYaml(source, before, after);
  expect(result).toMatchObject({ status: "patched" });
  if (result.status !== "patched") throw new Error(result.reason);
  expect(config(result.content)).toEqual(after);
  return result.content;
}

function refused(source: string, change: (after: OxiDnsConfig) => void) {
  const before = config(source);
  const after = structuredClone(before);
  change(after);
  const result = patchConfigYaml(source, before, after);
  expect(result).toMatchObject({ status: "needs_confirmation" });
  expect(result).not.toHaveProperty("candidate");
}

describe("patchConfigYaml settings", () => {
  it.each([
    "runtime: {worker_threads: 2}\n\n # keep indent\nlog: {level: info}\n",
    "runtime: {worker_threads: 2}\n  \nlog: {level: info}\n",
  ])(
    "does not silently discard inter-field trivia on removal: %s",
    (source) => {
      const before = config(source);
      const after = structuredClone(before);
      delete after.runtime;
      const result = patchConfigYaml(source, before, after);
      if (result.status === "patched") {
        expect(result.content).toBe(
          source.replace("runtime: {worker_threads: 2}\n", ""),
        );
      } else {
        expect(result).not.toHaveProperty("candidate");
      }
    },
  );
  it("adds and removes root settings without materializing default plugins", () => {
    const source =
      "# keep header\nlog: {level: info} # untouched\nobsolete: true\n";
    const content = patched(source, (after) => {
      delete after.obsolete;
      after.runtime = { worker_threads: 4 };
      after.api = { listen: "127.0.0.1:9080" };
    });
    expect(content).toContain(
      "# keep header\nlog: {level: info} # untouched\n",
    );
    expect(content).not.toContain("plugins:");
  });

  it("adds a root field after a scalar with no final newline", () => {
    expect(
      patched("log: {level: info}", (after) => {
        after.runtime = { worker_threads: 2 };
      }),
    ).toBe("log: {level: info}\nruntime:\n  worker_threads: 2");
  });

  it("patches runtime, network and api nested flow and block sequences", () => {
    const source =
      "runtime:\n  worker_threads: 2 # threads\nnetwork:\n  upstreams:\n    - {addr: '1.1.1.1', ports: [53, 54]} # first\n    - addr: '8.8.8.8' # stable\n      ports:\n        - 53 # dns\napi: {listen: 'localhost:80', enabled: false}\nplugins: [] # do not touch\n";
    const content = patched(source, (after) => {
      after.runtime!.worker_threads = 8;
      const upstreams = after.network!.upstreams as Array<{
        addr: string;
        ports: number[];
      }>;
      upstreams[0].ports = [53, 853, 443];
      upstreams[1].ports.push(853);
      after.api!.enabled = true;
    });
    expect(content).toContain("worker_threads: 8 # threads");
    expect(content).toContain("addr: '8.8.8.8' # stable");
    expect(content).toContain("- 53 # dns");
    expect(content).toContain("api: {listen: 'localhost:80', enabled: true}");
    expect(content).toContain("plugins: [] # do not touch\n");
  });

  it("preserves block scalar style and unrelated comments", () => {
    const source =
      'log:\n  message: |- # message\n    old\n    text\n  level: "info" # level\n# footer\n';
    const content = patched(source, (after) => {
      after.log!.message = "new\ntext";
    });
    expect(content).toContain("message: |- # message\n    new\n    text\n");
    expect(content).toContain('  level: "info" # level\n# footer\n');
  });

  it("patches flow roots and removes or empties nested collections", () => {
    patched(
      "{ log: {level: info, color: true}, runtime: {workers: [1, 2]}, plugins: [] }",
      (after) => {
        delete after.log!.color;
        after.runtime!.workers = [];
        after.api = { enabled: false };
      },
    );
    patched(
      "log:\n  level: info\nnetwork:\n  servers:\n    - one\n    - two\n",
      (after) => {
        after.log = {};
        after.network!.servers = [];
      },
    );
  });

  it("retains CRLF, BOM, markers and trailing comments on root insertion", () => {
    const source = "\uFEFF---\r\nlog: {level: info}\r\n# tail\r\n...\r\n";
    const content = patched(source, (after) => {
      after.runtime = { workers: 4 };
    });
    expect(content.startsWith("\uFEFF---\r\nlog: {level: info}\r\n")).toBe(
      true,
    );
    expect(content).toContain("# tail\r\n");
    expect(content.endsWith("...\r\n")).toBe(true);
    expect(content.replaceAll("\r\n", "")).not.toContain("\n");
  });

  it("uses tag-aware plugin reorder and rename before settings reconciliation", () => {
    const source =
      "log: {level: info}\nplugins:\n  - tag: one # first\n    type: reject\n    future: keep\n  - tag: two # second\n    type: reject\n";
    const before = config(source);
    const after = structuredClone(before);
    after.plugins.reverse();
    after.plugins[1].tag = "renamed";
    after.log!.level = "debug";
    const result = patchConfigYaml(source, before, after, {
      renamedTags: new Map([["one", "renamed"]]),
    });
    expect(result).toMatchObject({ status: "patched" });
    if (result.status !== "patched") throw new Error(result.reason);
    expect(config(result.content)).toEqual(after);
    expect(result.content).toContain(
      "tag: renamed # first\n    type: reject\n    future: keep",
    );
    expect(result.content.indexOf("# second")).toBeLessThan(
      result.content.indexOf("# first"),
    );
  });

  it("preserves unchanged anchors and aliases in unrelated settings", () => {
    const source =
      "shared: &defaults {level: info}\nlog: *defaults\nnetwork: {servers: [&server 'one', *server]}\napi: {enabled: false}\n";
    expect(
      patched(source, (after) => {
        after.api!.enabled = true;
      }),
    ).toBe(source.replace("false", "true"));
  });

  it("refuses anchor edits affecting unedited aliases and direct alias edits", () => {
    const source =
      "shared: &defaults {level: info}\nlog: *defaults\napi: {enabled: false}\n";
    refused(source, (after) => {
      (after.shared as Record<string, unknown>).level = "debug";
    });
    refused(source, (after) => {
      after.log!.level = "debug";
    });
    refused(source, (after) => {
      delete after.shared;
    });
    refused(source, (after) => {
      delete after.log;
    });
    refused(source, (after) => {
      (after.shared as Record<string, unknown>).level = "debug";
      after.log!.level = "debug";
    });
  });

  it("refuses dangerous plugin aliases without offering a localized candidate", () => {
    refused(
      "args: &args {rcode: REFUSED}\nplugins:\n  - tag: reject\n    type: reject\n    args: *args\n",
      (after) => {
        (after.plugins[0].args as Record<string, unknown>).rcode = "NXDOMAIN";
      },
    );
  });

  it("rejects stale before models even on no-op and plugin-only patches", () => {
    const source = "log: {level: info}\nplugins: []\n";
    const before = config(source);
    before.log!.level = "debug";
    for (const after of [
      structuredClone(before),
      { ...before, plugins: [{ tag: "x", type: "reject" }] },
    ]) {
      const result = patchConfigYaml(source, before, after);
      expect(result).toMatchObject({ status: "needs_confirmation" });
      expect(result).not.toHaveProperty("candidate");
    }
  });
  it("keeps CRLF when editing multiline block scalars", () => {
    const source =
      "log:\r\n  message: |-\r\n    old\r\n    text\r\napi: {enabled: true}\r\n";
    const content = patched(source, (after) => {
      after.log!.message = "new\nlines";
    });
    expect(content).toBe(source.replace("old\r\n    text", "new\r\n    lines"));
  });

  it("handles plugin insertion and deletion alongside root changes without EOF newline", () => {
    const source = "---\nlog: {level: info}\n...";
    const added = patched(source, (after) => {
      after.plugins = [
        { tag: "reject", type: "reject", args: { rcode: "REFUSED" } },
      ];
      after.api = { enabled: true };
    });
    expect(added.endsWith("...")).toBe(true);
    const removed = patched(added, (after) => {
      after.plugins = [];
      delete after.log;
    });
    expect(config(removed).plugins).toEqual([]);
    expect(removed.endsWith("...")).toBe(true);
  });

  it("refuses invalid YAML and structurally unsafe replacements without candidates", () => {
    const result = patchConfigYaml("log: [", { plugins: [] }, { plugins: [] });
    expect(result.status).toBe("needs_confirmation");
    expect(result).not.toHaveProperty("candidate");
    refused("log: {level: info}\n", (after) => {
      after.log!.level = { unexpected: true };
    });
  });

  it("preserves unchanged bytes and only changes the requested scalar", () => {
    const source =
      "\uFEFF---\r\n# header\r\nlog: { level: 'info', color: false } # keep\r\nplugins: []\r\n...";
    const before = config(source);
    expect(patchConfigYaml(source, before, structuredClone(before))).toEqual({
      status: "patched",
      content: source,
    });
    const after = structuredClone(before);
    after.log!.level = "debug";
    expect(patchConfigYaml(source, before, after)).toEqual({
      status: "patched",
      content: source.replace("'info'", "'debug'"),
    });
  });
});
