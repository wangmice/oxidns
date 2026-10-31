import { describe, expect, it } from "vitest";
import {
  getOxiDnsConfigSubKeys,
  getOxiDnsConfigValueSuggestions,
  sortOxiDnsConfigForSerialize,
} from "./oxidns-config-schema";

describe("OxiDNS config schema runtime settings", () => {
  it("exposes provider_file_auto_reload under runtime", () => {
    expect(getOxiDnsConfigSubKeys(["runtime"])).toEqual([
      "worker_threads",
      "provider_file_auto_reload",
    ]);
    expect(
      getOxiDnsConfigValueSuggestions(
        ["runtime"],
        "provider_file_auto_reload",
      ).map((entry) => entry.label),
    ).toEqual(["true", "false"]);
  });

  it("serializes the runtime auto-reload switch in stable schema order", () => {
    expect(
      sortOxiDnsConfigForSerialize({
        runtime: {
          provider_file_auto_reload: true,
          worker_threads: 4,
        },
      }),
    ).toEqual({
      runtime: { worker_threads: 4, provider_file_auto_reload: true },
    });
  });
});
