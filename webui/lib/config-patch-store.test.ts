import { beforeEach, describe, expect, it } from "vitest";
import { parseOxiDnsYaml, pluginsFromConfig } from "./oxidns-config";
import { useAppStore } from "./store";

function loadStoreConfig(source: string) {
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
    configEditorBaseline: null,
    editorMode: false,
  });
}

describe("config patch confirmation state", () => {
  it("cancels reviewed candidates and returns to the source before review", async () => {
    const source =
      "shared: &shared { timeout: 2s }\nplugins:\n  - tag: main\n    type: forward\n    args: *shared\n";
    loadStoreConfig(source);
    const pending = useAppStore
      .getState()
      .updatePluginConfig("main", { timeout: "3s" });
    useAppStore.getState().resolveConfigPatchConfirmation("review");
    await expect(pending).resolves.toBe("review");
    useAppStore.getState().setYamlConfig("invalid: [");
    useAppStore.getState().cancelConfigEditing("wrong baseline");
    expect(useAppStore.getState().configText).toBe(source);
    expect(useAppStore.getState().configError).toBeNull();
    expect(useAppStore.getState().editorMode).toBe(false);
    expect(useAppStore.getState().configEditorBaseline).toBeNull();
  });

  it("cancels ordinary YAML edits without saving", () => {
    const source = "plugins: []\n";
    loadStoreConfig(source);
    useAppStore.getState().setYamlConfig("plugins: []\nlog: {level: debug}\n");
    useAppStore.getState().cancelConfigEditing(source);
    expect(useAppStore.getState().configText).toBe(source);
    expect(useAppStore.getState().editorMode).toBe(false);
  });
  it("offers force for a multi-field edit requiring a local rebuild", async () => {
    const source =
      "log: {level: info} # keep\nplugins:\n  - tag: main\n    type: forward\n    args: { upstream: old, timeout: 2s } # args\n";
    loadStoreConfig(source);
    const pending = useAppStore.getState().updatePluginConfig("main", {
      upstream: ["new"],
      timeout: "3s",
    });
    expect(useAppStore.getState().configPatchConfirmation).toMatchObject({
      canForce: true,
    });
    useAppStore.getState().resolveConfigPatchConfirmation("force");
    await expect(pending).resolves.toBe("forced");
    expect(useAppStore.getState().configModel.plugins[0].args).toEqual({
      upstream: ["new"],
      timeout: "3s",
    });
    expect(useAppStore.getState().configText).toContain(
      "log: {level: info} # keep\n",
    );
  });

  it("does not overwrite newer source when an old confirmation is accepted", async () => {
    const source =
      "shared: &shared { timeout: 2s }\nplugins:\n  - tag: main\n    type: forward\n    args: *shared\n";
    loadStoreConfig(source);
    const pending = useAppStore
      .getState()
      .updatePluginConfig("main", { timeout: "3s" });
    useAppStore.getState().setYamlConfig(source + "log: {level: debug}\n");
    useAppStore.getState().resolveConfigPatchConfirmation("force");
    await expect(pending).resolves.toBe("cancelled");
    expect(useAppStore.getState().configText).toBe(
      source + "log: {level: debug}\n",
    );
  });
  beforeEach(() => {
    useAppStore.getState().resolveConfigPatchConfirmation("cancel");
  });

  it("applies a safe edit immediately", async () => {
    const source = `plugins: # keep
  - tag: main
    type: forward
    args:
      upstream: "udp://1.1.1.1" # keep
`;
    loadStoreConfig(source);

    const resolution = await useAppStore
      .getState()
      .updatePluginConfig("main", { upstream: "udp://8.8.8.8" });

    expect(resolution).toBe("patched");
    expect(useAppStore.getState().configText).toBe(
      source.replace("udp://1.1.1.1", "udp://8.8.8.8"),
    );
    expect(useAppStore.getState().configPatchConfirmation).toBeNull();
  });

  it("keeps state unchanged on cancel and stages a local candidate for review", async () => {
    const source = `shared: &shared { timeout: 2s }
plugins:
  - tag: main
    type: forward
    args: *shared # keep alias
`;
    loadStoreConfig(source);

    const cancelled = useAppStore
      .getState()
      .updatePluginConfig("main", { timeout: "3s" });
    expect(useAppStore.getState().configPatchConfirmation).toMatchObject({
      affectedPath: "plugins.main.args",
      canForce: true,
    });
    useAppStore.getState().resolveConfigPatchConfirmation("cancel");
    await expect(cancelled).resolves.toBe("cancelled");
    expect(useAppStore.getState().configText).toBe(source);

    const reviewed = useAppStore
      .getState()
      .updatePluginConfig("main", { timeout: "3s" });
    useAppStore.getState().resolveConfigPatchConfirmation("review");
    await expect(reviewed).resolves.toBe("review");
    expect(useAppStore.getState().editorMode).toBe(true);
    expect(useAppStore.getState().configEditorBaseline).toBe(source);
    expect(useAppStore.getState().configText).toContain(
      "args: { timeout: 3s } # keep alias",
    );
  });

  it("applies the reviewed local candidate after explicit force", async () => {
    const source = `shared: &shared { timeout: 2s }
plugins:
  - tag: main
    type: forward
    args: *shared
`;
    loadStoreConfig(source);

    const forced = useAppStore
      .getState()
      .updatePluginConfig("main", { timeout: "3s" });
    useAppStore.getState().resolveConfigPatchConfirmation("force");

    await expect(forced).resolves.toBe("forced");
    expect(useAppStore.getState().configText).toContain(
      "args: { timeout: 3s }",
    );
  });
});
