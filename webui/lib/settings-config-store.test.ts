import { afterEach, describe, expect, it, vi } from "vitest";
import { readFileSync } from "node:fs";
import { parseOxiDnsYaml, pluginsFromConfig } from "./oxidns-config";
import { shouldPersistPluginMutation, useAppStore } from "./store";

const apiMocks = vi.hoisted(() => ({
  validateConfigText: vi.fn(),
  saveConfigFile: vi.fn(),
}));

vi.mock("./oxidns-api", async (importOriginal) => ({
  ...(await importOriginal<typeof import("./oxidns-api")>()),
  ...apiMocks,
}));

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
    configEditorBaseline: null,
    configPatchConfirmation: null,
    editorMode: false,
  });
  return structuredClone(parsed.config);
}

afterEach(() => {
  useAppStore.getState().resolveConfigPatchConfirmation("cancel");
  vi.restoreAllMocks();
});

describe("settings source-backed configuration staging", () => {
  it("sends the source-preserving content to the save API", async () => {
    const source = '# header\nlog: { level: "info" } # log\nplugins: []\n';
    const config = load(source);
    useAppStore.setState({ configVersion: "original-version" });
    config.log!.level = "debug";
    apiMocks.validateConfigText.mockResolvedValue({ dependency_graph: {} });
    apiMocks.saveConfigFile.mockResolvedValue({
      path: "config.yaml",
      version: "saved-version",
    });
    vi.spyOn(useAppStore.getState(), "refreshRuntimeState").mockResolvedValue();
    await useAppStore.getState().stageSettingsConfig(config);
    await useAppStore.getState().saveConfig();
    expect(apiMocks.saveConfigFile).toHaveBeenCalledWith({
      content: source.replace('"info"', '"debug"'),
      baseVersion: "original-version",
      validate: true,
      reload: false,
    });
  });
  it("preserves comments and formatting in the staged save payload", async () => {
    const source =
      '# header\r\nlog: { level: "info" } # log\r\nplugins: [] # plugins\r\n';
    const config = load(source);
    config.log!.level = "debug";
    const resolution = await useAppStore.getState().stageSettingsConfig(config);
    expect(shouldPersistPluginMutation(resolution)).toBe(true);
    expect(useAppStore.getState().configText).toBe(
      source.replace('"info"', '"debug"'),
    );
    expect(useAppStore.getState().yamlConfig).toBe(
      useAppStore.getState().configText,
    );
    expect(useAppStore.getState().configModel.log!.level).toBe("debug");
  });

  it("does not save or stage an unsafe alias edit on cancel or review", async () => {
    const source =
      "shared: &logging { level: info }\nlog: *logging # retain\nplugins: []\n";
    for (const choice of ["cancel", "review"] as const) {
      const config = load(source);
      config.log!.level = "debug";
      const pending = useAppStore.getState().stageSettingsConfig(config);
      expect(useAppStore.getState().configPatchConfirmation).toMatchObject({
        canForce: false,
      });
      useAppStore.getState().resolveConfigPatchConfirmation(choice);
      const resolution = await pending;
      expect(shouldPersistPluginMutation(resolution)).toBe(false);
      expect(useAppStore.getState().configText).toBe(source);
      expect(useAppStore.getState().configModel.log!.level).toBe("info");
      expect(useAppStore.getState().editorMode).toBe(choice === "review");
    }
  });

  it("patches outbound plugin references and settings in the same mutation", async () => {
    const source =
      "# header\nnetwork: { outbound: { default: old } } # network\nplugins:\n  - tag: main\n    type: forward\n    args: { outbound: old } # args\n";
    const config = load(source);
    (config.network!.outbound as Record<string, unknown>).default = "new";
    (config.plugins[0].args as Record<string, unknown>).outbound = "new";
    await expect(
      useAppStore.getState().stageSettingsConfig(config),
    ).resolves.toBe("patched");
    expect(useAppStore.getState().configText).toBe(
      source.replaceAll(": old", ": new"),
    );
  });

  it("routes save, restart and authentication through patch staging", () => {
    const source = readFileSync(
      new URL("../app/(console)/settings/page.tsx", import.meta.url),
      "utf8",
    );
    expect(source).not.toContain("stringifyOxiDnsConfig");
    expect(source.match(/await stageSettingsConfig\(/g)).toHaveLength(3);
    expect(source).toContain(
      "if (!shouldPersistPluginMutation(resolution)) return;",
    );
  });
});
