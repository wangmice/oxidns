import { describe, expect, it } from "vitest";
import { applyProviderFileAutoReloadSetting } from "./runtime-settings";

describe("provider file auto reload runtime setting", () => {
  it("preserves an environment placeholder when the switch is untouched", () => {
    const runtime = {
      worker_threads: 4,
      provider_file_auto_reload: "${PROVIDER_FILE_AUTO_RELOAD:-true}",
    };

    expect(
      applyProviderFileAutoReloadSetting(runtime, false, false),
    ).toEqual(runtime);
  });

  it("preserves an explicit false value when the switch is untouched", () => {
    const runtime = {
      provider_file_auto_reload: false,
    };

    expect(
      applyProviderFileAutoReloadSetting(runtime, false, false),
    ).toEqual(runtime);
  });

  it("writes true after the user explicitly enables the switch", () => {
    expect(
      applyProviderFileAutoReloadSetting(
        {
          provider_file_auto_reload: "${PROVIDER_FILE_AUTO_RELOAD:-false}",
        },
        true,
        true,
      ),
    ).toEqual({
      provider_file_auto_reload: true,
    });
  });

  it("removes the field after the user explicitly disables the switch", () => {
    expect(
      applyProviderFileAutoReloadSetting(
        { provider_file_auto_reload: true, worker_threads: 2 },
        false,
        true,
      ),
    ).toEqual({ worker_threads: 2 });
  });
});
