import { afterEach, describe, expect, it } from "vitest";
import { parseOxiDnsYaml, pluginsFromConfig } from "./oxidns-config";
import { useAppStore } from "./store";

function load(source: string) {
  const parsed = parseOxiDnsYaml(source);
  if (!parsed.config) throw new Error(parsed.diagnostics.join("\n"));
  useAppStore.setState({
    configModel: parsed.config,
    configText: source,
    yamlConfig: source,
    plugins: pluginsFromConfig(parsed.config),
    configError: null,
    configDiagnostics: [],
    configPatchConfirmation: null,
  });
  return structuredClone(parsed.config);
}

afterEach(() => useAppStore.getState().resolveConfigPatchConfirmation("cancel"));

describe("source-preserving deletion through configuration state", () => {
  it("keeps independent comments around a removed plugin field", async () => {
    const source = "plugins:\n  - tag: cache\n    type: cache\n    args:\n      size: 81920\n      # TTL documentation\n      lazy_cache_ttl: 86400 # remove with field\n      # persistence documentation\n      dump_interval: 7200\n";
    const config = load(source);
    const args = { ...(config.plugins[0].args as Record<string, unknown>) };
    delete args.lazy_cache_ttl;
    const pending = useAppStore.getState().updatePluginConfig("cache", args);
    const confirmation = useAppStore.getState().configPatchConfirmation;
    if (confirmation) useAppStore.getState().resolveConfigPatchConfirmation("cancel");
    const result = await pending;
    expect(result).toBe("patched");
    expect(useAppStore.getState().configText).toBe(source.replace("      lazy_cache_ttl: 86400 # remove with field\n", ""));
  });

  it("keeps root-level independent comments when a setting is removed", async () => {
    const source = "# runtime documentation\nruntime:\n  worker_threads: 2 # remove subtree\n\n# logging documentation\nlog: {level: info}\nplugins: []\n";
    const config = load(source);
    delete config.runtime;
    const pending = useAppStore.getState().stageSettingsConfig(config);
    const confirmation = useAppStore.getState().configPatchConfirmation;
    if (confirmation) useAppStore.getState().resolveConfigPatchConfirmation("cancel");
    const result = await pending;
    expect(result).toBe("patched");
    expect(useAppStore.getState().configText).toBe(source.replace("runtime:\n  worker_threads: 2 # remove subtree\n", ""));
  });
});
