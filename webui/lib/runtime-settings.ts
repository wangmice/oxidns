export function applyProviderFileAutoReloadSetting(
  runtime: Record<string, unknown>,
  enabled: boolean,
  touched: boolean,
): Record<string, unknown> {
  const next = { ...runtime };
  if (!touched) {
    return next;
  }

  if (enabled) {
    next.provider_file_auto_reload = true;
  } else {
    delete next.provider_file_auto_reload;
  }

  return next;
}
