/*
 * SPDX-FileCopyrightText: 2026 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
// @vitest-environment happy-dom

import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  within,
} from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { PluginDetailTemplateProps } from "../types";
import type { CacheEntryRow } from "@/lib/oxidns-api";
import { WEBUI } from "@/lib/i18n/keys";
import { cachePlugin } from "./cache";

const api = vi.hoisted(() => ({
  fetchCacheEntries: vi.fn(),
  deleteCacheEntry: vi.fn(),
  deleteCacheEntries: vi.fn(),
  flushCache: vi.fn(),
}));
const i18n = vi.hoisted(() => ({ locale: "en-US", t: (key: string) => key }));
vi.mock("@/lib/oxidns-api", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/lib/oxidns-api")>()),
  ...api,
}));
vi.mock("@/lib/i18n/provider", () => ({ useI18n: () => i18n }));
vi.mock("@/hooks/use-plugin-applied", () => ({
  usePluginAppliedStatus: () => "applied",
}));
vi.mock("@/components/ui/toast", () => ({
  useToast: () => ({ toast: vi.fn() }),
}));
vi.mock("../plugin-detail-template", () => ({
  PluginDetailTemplate: ({ metricsContent }: PluginDetailTemplateProps) =>
    metricsContent,
}));
vi.mock("../dns-record-detail-dialog", () => ({
  DnsRecordDetailDialog: () => null,
}));

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

function row(domain: string): CacheEntryRow {
  return {
    id: domain,
    domain,
    record_type: "A",
    fresh: true,
    rcode: "No Error",
  } as CacheEntryRow;
}

async function settle() {
  await act(async () => {
    await vi.runAllTimersAsync();
  });
}

async function filter(qname: string) {
  fireEvent.change(screen.getByPlaceholderText("example.com"), {
    target: { value: qname },
  });
  fireEvent.submit(screen.getByPlaceholderText("example.com").closest("form")!);
  await settle();
}

async function mount() {
  const Detail = cachePlugin.Detail!;
  const view = render(
    <Detail
      plugin={
        { name: "cache", config: {} } as PluginDetailTemplateProps["plugin"]
      }
      chartData={[]}
      onClose={() => {}}
    />,
  );
  await settle();
  await filter("a.example");
  return view;
}

beforeEach(() => {
  vi.useFakeTimers();
  vi.clearAllMocks();
  api.fetchCacheEntries.mockImplementation(async (_tag, options) => ({
    entries: [row(options.qname || "initial.example")],
    total_entries: 1,
  }));
  api.deleteCacheEntries.mockResolvedValue({ deleted_entries: 1 });
});
afterEach(() => {
  cleanup();
  vi.useRealTimers();
});

describe("cache mutation continuations", () => {
  it.each(["single", "bulk"])(
    "does not restart reads after unmounting a pending %s delete",
    async (kind) => {
      const deletion = deferred<{ deleted_entries: number }>();
      api.deleteCacheEntry.mockReturnValue(deletion.promise);
      api.deleteCacheEntries.mockReturnValue(deletion.promise);
      const view = await mount();
      if (kind === "single") {
        fireEvent.click(
          screen.getByRole("button", { name: WEBUI.cache.deleteEntryAria }),
        );
      } else {
        fireEvent.click(
          screen.getByRole("button", { name: WEBUI.cache.selectAllMatching }),
        );
        fireEvent.click(
          screen.getByRole("button", { name: WEBUI.cache.deleteSelected }),
        );
      }
      fireEvent.click(
        within(screen.getByRole("alertdialog")).getByRole("button", {
          name: WEBUI.common.delete,
        }),
      );
      const calls = api.fetchCacheEntries.mock.calls.length;
      view.unmount();
      await act(async () => {
        deletion.resolve({ deleted_entries: 1 });
      });
      await settle();
      expect(api.fetchCacheEntries).toHaveBeenCalledTimes(calls);
    },
  );

  it("blocks filter submissions while flush is pending and cancels older reads", async () => {
    const flush = deferred<{ cleared_entries: number }>();
    api.flushCache.mockReturnValue(flush.promise);
    await mount();
    fireEvent.click(screen.getByRole("button", { name: WEBUI.common.clear }));
    fireEvent.click(
      within(screen.getByRole("alertdialog")).getByRole("button", {
        name: WEBUI.common.clear,
      }),
    );
    expect(api.flushCache).toHaveBeenCalledWith("cache");
    expect(
      (screen.getByPlaceholderText("example.com") as HTMLInputElement).disabled,
    ).toBe(true);
    expect(
      (
        screen.getByRole("button", {
          name: WEBUI.cache.filterButton,
        }) as HTMLButtonElement
      ).disabled,
    ).toBe(true);
    const calls = api.fetchCacheEntries.mock.calls.length;
    // Form submission can bypass a disabled submit button (e.g. Enter/script).
    await filter("b.example");
    expect(api.fetchCacheEntries).toHaveBeenCalledTimes(calls);
    await act(async () => {
      flush.resolve({ cleared_entries: 1 });
    });
    await settle();
    expect(screen.queryByText("a.example")).toBeNull();
    expect(screen.queryByText("b.example")).toBeNull();
    expect(api.fetchCacheEntries.mock.calls.at(-1)![1].signal.aborted).toBe(
      true,
    );
  });

  it.each([false, true])(
    "keeps the new filter's rows and bulk scope after a delayed single delete (new read pending: %s)",
    async (pending) => {
      const deletion = deferred<void>();
      api.deleteCacheEntry.mockReturnValue(deletion.promise);
      await mount();
      fireEvent.click(
        screen.getByRole("button", { name: WEBUI.cache.deleteEntryAria }),
      );
      fireEvent.click(
        within(screen.getByRole("alertdialog")).getByRole("button", {
          name: WEBUI.common.delete,
        }),
      );
      expect(api.deleteCacheEntry).toHaveBeenCalledWith("cache", "a.example");
      const newRead = deferred<{
        entries: CacheEntryRow[];
        total_entries: number;
      }>();
      if (pending) api.fetchCacheEntries.mockReturnValueOnce(newRead.promise);
      await filter("b.example");
      if (!pending) expect(screen.getByText("b.example")).toBeTruthy();
      const callsBeforeCompletion = api.fetchCacheEntries.mock.calls.length;
      await act(async () => {
        deletion.resolve();
      });
      await settle();
      // Even a transport that ignores abort must not publish its late response.
      await act(async () => {
        newRead.resolve({ entries: [row("late.example")], total_entries: 1 });
      });
      expect(screen.queryByText("late.example")).toBeNull();
      expect(
        api.fetchCacheEntries.mock.calls
          .slice(callsBeforeCompletion)
          .map(([, options]) => options.qname),
      ).not.toContain("a.example");
      expect(screen.queryByText("a.example")).toBeNull();
      expect(screen.getByText("b.example")).toBeTruthy();
      fireEvent.click(
        screen.getByRole("button", { name: WEBUI.cache.selectAllMatching }),
      );
      fireEvent.click(
        screen.getByRole("button", { name: WEBUI.cache.deleteSelected }),
      );
      fireEvent.click(
        within(screen.getByRole("alertdialog")).getByRole("button", {
          name: WEBUI.common.delete,
        }),
      );
      await settle();
      expect(api.deleteCacheEntries).toHaveBeenCalledWith("cache", {
        filter: { qname: "b.example", answer_ip: undefined },
      });
    },
  );
});
