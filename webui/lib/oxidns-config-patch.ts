"use client";

import {
  CST,
  Scalar,
  isAlias,
  isMap,
  isScalar,
  isSeq,
  parseDocument,
  stringify,
  type Pair,
  type ParsedNode,
  type YAMLMap,
  type YAMLSeq,
} from "yaml";
import {
  parseOxiDnsYaml,
  type OxiDnsConfig,
  type OxiDnsPluginConfig,
} from "@/lib/oxidns-config";

export interface PluginYamlPatchOptions {
  renamedTags?: ReadonlyMap<string, string>;
}

export interface PluginYamlPatchCandidate {
  content: string;
  affectedPath: string;
}

export type PluginYamlPatchResult =
  | { status: "patched"; content: string }
  | {
      status: "needs_confirmation";
      reason: string;
      affectedPath: string;
      candidate?: PluginYamlPatchCandidate;
    };

type CstNodeToken = NonNullable<ParsedNode["srcToken"]>;
type CstCollectionItem = NonNullable<Pair<ParsedNode, ParsedNode>["srcToken"]>;

interface PatchContext {
  eol: "\n" | "\r\n";
  path: string;
  preserveUnknownPluginKeys?: boolean;
}

class UnsafePluginYamlPatch extends Error {
  constructor(
    message: string,
    readonly path: string,
    readonly node?: ParsedNode,
    readonly desired?: unknown,
  ) {
    super(message);
    this.name = "UnsafePluginYamlPatch";
  }
}

/**
 * Apply structured plugin changes without stringifying the whole YAML file.
 *
 * Parsed nodes retain their concrete source tokens. We only mutate tokens
 * below `plugins`, then splice that token range back into the original text.
 * Source outside the changed range is therefore byte-for-byte identical.
 */
export function patchPluginsYaml(
  source: string,
  before: OxiDnsConfig,
  after: OxiDnsConfig,
  options: PluginYamlPatchOptions = {},
): PluginYamlPatchResult {
  const loaded = parseOxiDnsYaml(source);
  if (!loaded.config || !deepEqual(loaded.config, before)) {
    return confirmationResult(
      "The YAML source no longer matches the loaded configuration; edit it manually",
      "$",
    );
  }
  if (deepEqual(before, after)) {
    return { status: "patched", content: source };
  }
  if (!deepEqual({ ...before, plugins: after.plugins }, after)) {
    return confirmationResult(
      "Plugin edits cannot change non-plugin configuration",
      "$",
    );
  }
  if (!source.endsWith("\n")) {
    const eol = detectEol(source);
    const result = patchPluginsYaml(source + eol, before, after, options);
    const restoreEof = (content: string) =>
      content.endsWith(eol) ? content.slice(0, -eol.length) : content;
    if (result.status === "patched") {
      const content = restoreEof(result.content);
      return patchedConfigMatches(content, after)
        ? { status: "patched", content }
        : confirmationResult(
            "Restoring the YAML EOF requires manual editing",
            "plugins",
          );
    }
    if (result.candidate) {
      const content = restoreEof(result.candidate.content);
      if (patchedConfigMatches(content, after)) {
        return { ...result, candidate: { ...result.candidate, content } };
      }
      return confirmationResult(result.reason, result.affectedPath);
    }
    return result;
  }
  const eol = detectEol(source);
  let document;
  try {
    document = parseDocument(source, {
      keepSourceTokens: true,
      prettyErrors: true,
    });
  } catch (error) {
    return confirmationResult(
      error instanceof Error ? error.message : "Unable to parse YAML source",
      "plugins",
    );
  }

  if (document.errors.length > 0) {
    return confirmationResult(document.errors[0].message, "plugins");
  }

  try {
    if (!isMap(document.contents) || !document.contents.srcToken) {
      throw new UnsafePluginYamlPatch(
        "The YAML root is not a source-backed mapping",
        "plugins",
      );
    }

    const deletionPatch = patchDeletedValues(
      source,
      document.contents,
      before,
      after,
    );
    if (
      deletionPatch !== undefined &&
      unmanagedPluginKeysMatch(source, deletionPatch, before, after, options)
    )
      return { status: "patched", content: deletionPatch };

    const pluginsNode = document.get("plugins", true);
    const scalarPatch = deepEqual(
      before.plugins.map((plugin) => plugin.tag),
      after.plugins.map((plugin) => plugin.tag),
    )
      ? patchScalarValues(source, document.contents, before, after)
      : undefined;
    if (
      scalarPatch !== undefined &&
      unmanagedPluginKeysMatch(source, scalarPatch, before, after, options)
    ) {
      return { status: "patched", content: scalarPatch };
    }
    let content: string;
    if (pluginsNode === undefined) {
      if (after.plugins.length === 0)
        return { status: "patched", content: source };
      content = appendPluginsToRoot(
        source,
        document.contents,
        after.plugins,
        eol,
      );
    } else if (
      isSeq(pluginsNode) &&
      pluginsNode.srcToken &&
      pluginsNode.range
    ) {
      const parsedPluginsNode = pluginsNode as YAMLSeq.Parsed;
      const originalSequenceSource = source.slice(
        parsedPluginsNode.range[0],
        parsedPluginsNode.range[2],
      );
      reconcilePluginSequence(
        parsedPluginsNode,
        before.plugins,
        after.plugins,
        options.renamedTags,
        eol,
      );
      const replacement =
        parsedPluginsNode.srcToken!.items.length > 0 ||
        parsedPluginsNode.srcToken?.type === "flow-collection"
          ? CST.stringify(parsedPluginsNode.srcToken!)
          : `[]${originalSequenceSource.endsWith(eol) ? eol : ""}`;
      content = spliceNodeSource(source, parsedPluginsNode, replacement);
    } else if (deepEqual(before.plugins, after.plugins)) {
      return { status: "patched", content: source };
    } else {
      throw new UnsafePluginYamlPatch(
        "The plugins value is not an editable YAML sequence",
        "plugins",
        isParsedNode(pluginsNode) ? pluginsNode : undefined,
        after.plugins,
      );
    }

    if (
      before.plugins.some(
        (plugin) =>
          !after.plugins.some(
            (next) =>
              next.tag === (options.renamedTags?.get(plugin.tag) ?? plugin.tag),
          ),
      ) &&
      !standaloneTriviaRetained(source, content)
    ) {
      return confirmationResult(
        "Preserving standalone comments and blank lines requires manual YAML editing",
        "plugins",
      );
    }
    if (
      !patchedConfigMatches(content, after) ||
      !unmanagedPluginKeysMatch(source, content, before, after, options)
    ) {
      throw new UnsafePluginYamlPatch(
        "The incremental YAML patch did not produce the requested plugin configuration",
        "plugins",
      );
    }

    return { status: "patched", content };
  } catch (error) {
    if (error instanceof UnsafePluginYamlPatch) {
      const candidate = createLocalizedCandidate(
        source,
        error,
        before,
        after,
        options,
      );
      return confirmationResult(error.message, error.path, candidate);
    }
    return confirmationResult(
      error instanceof Error ? error.message : "Unable to patch YAML source",
      "plugins",
    );
  }
}

/** Patch the complete model while retaining source-backed, untouched YAML. */
export function patchConfigYaml(
  source: string,
  before: OxiDnsConfig,
  after: OxiDnsConfig,
  options: PluginYamlPatchOptions = {},
): PluginYamlPatchResult {
  try {
    const loaded = parseOxiDnsYaml(source);
    if (!loaded.config || !deepEqual(loaded.config, before)) {
      return confirmationResult(
        "The YAML source no longer matches the loaded configuration; edit it manually",
        "$",
      );
    }
    if (deepEqual(before, after)) return { status: "patched", content: source };

    const original = parseDocument(source, { keepSourceTokens: true });
    if (!isMap(original.contents)) {
      return confirmationResult(
        "The YAML root is not an editable mapping",
        "$",
      );
    }
    assertSafeConfigChange(original.contents, before, after, "$");
    const deletionPatch = patchDeletedValues(
      source,
      original.contents,
      before,
      after,
    );
    if (
      deletionPatch !== undefined &&
      unmanagedPluginKeysMatch(source, deletionPatch, before, after, options)
    )
      return { status: "patched", content: deletionPatch };

    // Plugins require tag-aware alignment, not generic positional reconciliation.
    // A newly appended block item needs a separator after an EOF scalar.
    // Remove this temporary terminator again after all source splices.
    const terminatedSource = source.endsWith("\n")
      ? source
      : source + detectEol(source);
    const plugins = patchPluginsYaml(
      terminatedSource,
      before,
      { ...before, plugins: after.plugins },
      options,
    );
    if (plugins.status !== "patched") {
      return confirmationResult(plugins.reason, plugins.affectedPath);
    }
    const document = parseDocument(plugins.content, { keepSourceTokens: true });
    if (document.errors.length || !isMap(document.contents)) {
      return confirmationResult(
        "Unable to reparse the patched YAML mapping",
        "$",
      );
    }
    const root = document.contents;
    // The model defaults a missing plugins key to []. Keep its physical presence
    // (and its already patched tokens) identical on both sides of reconciliation.
    const physicalPlugins = document.toJSON().plugins;
    const rootBefore = { ...before, plugins: physicalPlugins };
    const rootAfter = { ...after, plugins: physicalPlugins };
    const token = reconcileMap(root, rootBefore, rootAfter, {
      eol: detectEol(source),
      path: "$",
    });
    let content = spliceNodeSource(plugins.content, root, CST.stringify(token));
    // CST.setScalarValue emits LF for regenerated multiline scalar bodies.
    // On a uniformly CRLF source these can only be newly generated bytes.
    if (detectEol(source) === "\r\n" && !/(?<!\r)\n/.test(source)) {
      content = content.replace(/(?<!\r)\n/g, "\r\n");
    }
    if (!source.endsWith("\n") && content.endsWith("\n")) {
      content = content.slice(0, -detectEol(content).length);
    }
    // Collection deletion/normalization can attach standalone trivia to a
    // removed item. Refuse instead of silently losing comments or whitespace.
    if (!standaloneTriviaRetained(source, content)) {
      return confirmationResult(
        "Preserving standalone comments and blank lines requires manual YAML editing",
        "$",
      );
    }
    const final = parseOxiDnsYaml(content);
    if (
      !final.config ||
      !deepEqual(final.config, after) ||
      !unmanagedPluginKeysMatch(source, content, before, after, options)
    ) {
      return confirmationResult(
        "The incremental YAML patch did not produce the requested complete configuration; edit it manually",
        "$",
      );
    }
    return { status: "patched", content };
  } catch (error) {
    return confirmationResult(
      error instanceof Error ? error.message : "Unable to patch YAML source",
      error instanceof UnsafePluginYamlPatch ? error.path : "$",
    );
  }
}

function assertSafeConfigChange(
  node: ParsedNode,
  before: unknown,
  after: unknown,
  path: string,
) {
  if (deepEqual(before, after)) return;
  if (isAlias(node) || ("anchor" in node && node.anchor)) {
    throw new UnsafePluginYamlPatch(
      "Changing a YAML alias or anchor requires manual editing",
      path,
    );
  }
  if (isMap(node)) {
    for (const pair of node.items) {
      const key = scalarMapKey(pair);
      if (key === null || !isParsedNode(pair.value)) continue;
      const previous = isPlainRecord(before) ? before[key] : undefined;
      const desired = isPlainRecord(after) ? after[key] : undefined;
      assertSafeConfigChange(pair.value, previous, desired, `${path}.${key}`);
    }
  } else if (isSeq(node)) {
    node.items.forEach((item, index) => {
      if (isParsedNode(item)) {
        assertSafeConfigChange(
          item,
          Array.isArray(before) ? before[index] : undefined,
          Array.isArray(after) ? after[index] : undefined,
          `${path}[${index}]`,
        );
      }
    });
  }
}

function reconcilePluginSequence(
  sequence: YAMLSeq.Parsed,
  before: OxiDnsPluginConfig[],
  after: OxiDnsPluginConfig[],
  renamedTags: ReadonlyMap<string, string> | undefined,
  eol: "\n" | "\r\n",
) {
  const sequenceToken = sequence.srcToken;
  if (!sequenceToken || !isSequenceToken(sequenceToken)) {
    throw new UnsafePluginYamlPatch(
      "The plugins sequence has no editable source tokens",
      "plugins",
      sequence,
      after,
    );
  }

  if (sequence.items.length !== before.length) {
    throw new UnsafePluginYamlPatch(
      "The parsed plugin list no longer matches the loaded configuration",
      "plugins",
      sequence,
      after,
    );
  }

  const oldByTag = new Map<
    string,
    {
      node: ParsedNode;
      item: CstCollectionItem;
      config: OxiDnsPluginConfig;
    }
  >();

  sequence.items.forEach((node, index) => {
    const config = before[index];
    const item = sequenceToken.items[index];
    if (!config || !item || !isParsedNode(node)) return;
    if (oldByTag.has(config.tag)) {
      throw new UnsafePluginYamlPatch(
        `Duplicate plugin tag '${config.tag}' cannot be patched safely`,
        `plugins.${config.tag}`,
        node,
        config,
      );
    }
    oldByTag.set(config.tag, { node, item, config });
  });

  const oldTagForNew = new Map<string, string>();
  renamedTags?.forEach((newTag, oldTag) => oldTagForNew.set(newTag, oldTag));
  const usedOldTags = new Set<string>();
  const nextItems: CstCollectionItem[] = [];

  after.forEach((plugin, index) => {
    const oldTag = oldTagForNew.get(plugin.tag) ?? plugin.tag;
    const existing = oldByTag.get(oldTag);
    if (existing && !usedOldTags.has(oldTag)) {
      usedOldTags.add(oldTag);
      const token = reconcileNode(existing.node, existing.config, plugin, {
        eol,
        path: `plugins.${oldTag}`,
        preserveUnknownPluginKeys: true,
      });
      const item = structuredClone(existing.item);
      item.value = token;
      nextItems.push(item);
      return;
    }

    nextItems.push(
      createSequenceItem(
        plugin,
        sequenceToken.type === "flow-collection",
        eol,
        sequenceToken.indent,
      ),
    );
    usedOldTags.add(`@new:${index}:${plugin.tag}`);
  });

  sequenceToken.items = nextItems;
  normalizeSequenceStarts(sequenceToken, eol);
}

/** Delete block entries by original ranges, not by CST trivia ownership.
 * The parser may store a sibling comment in the preceding subtree's last item.
 * Only CST comment tokens at the deleted entry's indentation (or less) survive;
 * hash-prefixed text inside a scalar is never classified as a comment.
 */
function patchDeletedValues(
  source: string,
  root: ParsedNode,
  before: OxiDnsConfig,
  after: OxiDnsConfig,
): string | undefined {
  let hasDeletion = false;
  const edits: Array<{ start: number; end: number; text: string }> = [];
  const remove = (item: CstCollectionItem, indent: number): boolean => {
    hasDeletion = true;
    const head = item.key ?? item.start.find((p) => p.type === "seq-item-ind");
    if (!head) return false;
    const physicalStart = source.lastIndexOf("\n", head.offset - 1) + 1;
    const start =
      physicalStart === 0 && source.startsWith("\uFEFF") ? 1 : physicalStart;
    // Compact mappings/sequences share a physical line with their parent.
    if (!/^[ \t]*$/.test(source.slice(start, head.offset))) return false;
    const comments = new Map<number, number>();
    const scalars: Array<[number, number]> = [];
    let end = head.offset;
    const visit = (value: unknown) => {
      if (!value || typeof value !== "object") return;
      if (Array.isArray(value)) {
        value.forEach(visit);
        return;
      }
      const token = value as {
        type?: string;
        offset?: number;
        source?: string;
        indent?: number;
      };
      if (
        token.offset !== undefined &&
        typeof token.source === "string" &&
        token.type !== "block-scalar"
      )
        end = Math.max(end, token.offset + token.source.length);
      if (token.type === "comment" && token.offset !== undefined)
        comments.set(token.offset, token.indent ?? 0);
      if (
        token.type === "block-scalar" ||
        token.type === "single-quoted-scalar" ||
        token.type === "double-quoted-scalar" ||
        token.type === "scalar"
      ) {
        const t = value as CstNodeToken;
        end = Math.max(end, t.offset + CST.stringify(t).length);
        scalars.push([t.offset, t.offset + CST.stringify(t).length]);
      }
      Object.values(value).forEach(visit);
    };
    visit(item);
    let cursor = start;
    while (cursor < end) {
      const newline = source.indexOf("\n", cursor);
      const lineEnd = newline < 0 ? source.length : newline + 1;
      const line = source.slice(cursor, lineEnd);
      const first = cursor + (line.match(/^[ \t]*/)?.[0].length ?? 0);
      if (first >= end) break;
      const literal = scalars.some(
        ([left, right]) => cursor >= left && cursor < right && first < right,
      );
      const blank = /^[ \t]*(?:\r?\n)?$/.test(line);
      const blockSubtree =
        item.value?.type === "block-map" || item.value?.type === "block-seq";
      const siblingComment =
        comments.has(first) &&
        (!blockSubtree || comments.get(first)! <= indent);
      if (literal || (!blank && !siblingComment))
        edits.push({ start: cursor, end: lineEnd, text: "" });
      cursor = lineEnd;
    }
    return true;
  };
  const collect = (
    node: ParsedNode,
    previous: unknown,
    desired: unknown,
  ): boolean => {
    if (deepEqual(previous, desired)) return true;
    if (isAlias(node) || ("anchor" in node && node.anchor)) return false;
    if (
      isScalar(node) &&
      isScalarValue(desired) &&
      node.srcToken &&
      node.range
    ) {
      const token = structuredClone(node.srcToken);
      CST.setScalarValue(token, scalarSourceValue(desired), {
        afterKey: true,
        type: preferredScalarType(node, desired),
      });
      let text = CST.stringify(token);
      if (detectEol(source) === "\r\n" && !/(?<!\r)\n/.test(source))
        text = text.replace(/(?<!\r)\n/g, "\r\n");
      edits.push({ start: node.range[0], end: node.range[2], text });
      return true;
    }
    if (
      isMap(node) &&
      isPlainRecord(previous) &&
      isPlainRecord(desired) &&
      node.srcToken?.type === "block-map"
    ) {
      if (
        Object.keys(desired).some(
          (key) => desired[key] !== undefined && previous[key] === undefined,
        )
      )
        return false;
      let kept = 0;
      for (let index = 0; index < node.items.length; index++) {
        const pair = node.items[index];
        const key = scalarMapKey(pair);
        const item = node.srcToken.items[index];
        if (key === null || !item) return false;
        // Unmanaged plugin keys are absent from both projected models.
        if (previous[key] === undefined && desired[key] === undefined) {
          kept++;
          continue;
        }
        if (desired[key] === undefined) {
          if (!remove(item, node.srcToken.indent)) return false;
        } else {
          kept++;
          if (
            !deepEqual(previous[key], desired[key]) &&
            (!isParsedNode(pair.value) ||
              !collect(pair.value, previous[key], desired[key]))
          )
            return false;
        }
      }
      if (kept === 0 && node.items.length) {
        const offset = node.range![0];
        const start = source.lastIndexOf("\n", offset - 1) + 1;
        edits.push({
          start,
          end: start,
          text: source.slice(start, offset) + "{}" + detectEol(source),
        });
      }
      return true;
    }
    if (
      isSeq(node) &&
      Array.isArray(previous) &&
      Array.isArray(desired) &&
      node.srcToken?.type === "block-seq"
    ) {
      if (previous.length === desired.length) {
        return node.items.every(
          (item, index) =>
            isParsedNode(item) &&
            collect(item, previous[index], desired[index]),
        );
      }
      // Deletion-only alignment is linear and retains the earliest equal duplicate.
      let next = 0;
      for (let index = 0; index < previous.length; index++) {
        if (
          next < desired.length &&
          deepEqual(previous[index], desired[next])
        ) {
          next++;
          continue;
        }
        const item = node.srcToken.items[index];
        if (!item || !remove(item, node.srcToken.indent)) return false;
      }
      if (next !== desired.length) return false;
      if (!desired.length && previous.length) {
        const offset = node.range![0];
        const start = source.lastIndexOf("\n", offset - 1) + 1;
        edits.push({
          start,
          end: start,
          text: source.slice(start, offset) + "[]" + detectEol(source),
        });
      }
      return true;
    }
    return false;
  };
  if (!collect(root, before, after) || !hasDeletion || !edits.length)
    return undefined;
  let content = source;
  // Apply removals before an insertion at the same original offset.
  for (const edit of edits.sort((a, b) => b.start - a.start || b.end - a.end)) {
    content =
      content.slice(0, edit.start) + edit.text + content.slice(edit.end);
  }
  if (!source.endsWith("\n") && content.endsWith("\n"))
    content = content.slice(0, -detectEol(content).length);
  return patchedConfigMatches(content, after) ? content : undefined;
}

// Value-only edits must never normalize their enclosing collections or trivia.
function patchScalarValues(
  source: string,
  root: ParsedNode,
  before: unknown,
  after: OxiDnsConfig,
): string | undefined {
  const edits: Array<{ start: number; end: number; text: string }> = [];
  const collect = (
    node: ParsedNode,
    previous: unknown,
    desired: unknown,
  ): boolean => {
    if (deepEqual(previous, desired)) return true;
    if (
      isScalar(node) &&
      isScalarValue(desired) &&
      node.srcToken &&
      node.range &&
      !node.anchor
    ) {
      const token = structuredClone(node.srcToken);
      CST.setScalarValue(token, scalarSourceValue(desired), {
        afterKey: true,
        type: preferredScalarType(node, desired),
      });
      edits.push({
        start: node.range[0],
        end: node.range[2],
        text: CST.stringify(token),
      });
      return true;
    }
    if (
      isMap(node) &&
      isPlainRecord(previous) &&
      isPlainRecord(desired) &&
      !node.anchor
    ) {
      const keys = Object.keys(previous).filter(
        (key) => previous[key] !== undefined,
      );
      if (
        !deepEqual(
          [...keys].sort(),
          Object.keys(desired)
            .filter((key) => desired[key] !== undefined)
            .sort(),
        )
      )
        return false;
      return node.items.every((pair) => {
        const key = scalarMapKey(pair);
        return (
          key !== null &&
          (deepEqual(previous[key], desired[key]) ||
            (isParsedNode(pair.value) &&
              collect(pair.value, previous[key], desired[key])))
        );
      });
    }
    if (
      isSeq(node) &&
      Array.isArray(previous) &&
      Array.isArray(desired) &&
      previous.length === desired.length &&
      !node.anchor
    ) {
      return node.items.every(
        (item, index) =>
          isParsedNode(item) && collect(item, previous[index], desired[index]),
      );
    }
    return false;
  };
  if (!collect(root, before, after) || edits.length === 0) return undefined;
  let content = source;
  for (const edit of edits.sort((a, b) => b.start - a.start)) {
    content =
      content.slice(0, edit.start) + edit.text + content.slice(edit.end);
  }
  return patchedConfigMatches(content, after) ? content : undefined;
}

function reconcileNode(
  node: ParsedNode,
  before: unknown,
  after: unknown,
  context: PatchContext,
): CstNodeToken {
  if (deepEqual(before, after)) {
    if (!node.srcToken) {
      throw new UnsafePluginYamlPatch(
        "An unchanged YAML node has no source token",
        context.path,
        node,
        after,
      );
    }
    return node.srcToken;
  }

  if (!node.srcToken) {
    throw new UnsafePluginYamlPatch(
      "The changed YAML node has no source token",
      context.path,
      node,
      after,
    );
  }

  if (isAlias(node)) {
    throw new UnsafePluginYamlPatch(
      "The changed value is provided through a YAML alias",
      context.path,
      node,
      after,
    );
  }

  if (isScalar(node) && isScalarValue(after)) {
    const token = structuredClone(node.srcToken);
    const scalarType = preferredScalarType(node, after);
    CST.setScalarValue(token, scalarSourceValue(after), {
      afterKey: true,
      type: scalarType,
    });
    return token;
  }

  if (isMap(node) && isPlainRecord(before) && isPlainRecord(after)) {
    return reconcileMap(node, before, after, context);
  }

  if (isSeq(node) && Array.isArray(before) && Array.isArray(after)) {
    return reconcileSequence(node, before, after, context);
  }

  throw new UnsafePluginYamlPatch(
    "The changed value requires replacing its YAML node type",
    context.path,
    node,
    after,
  );
}

function reconcileMap(
  map: YAMLMap.Parsed,
  before: Record<string, unknown>,
  after: Record<string, unknown>,
  context: PatchContext,
): CstNodeToken {
  const token = map.srcToken;
  if (!token || !isMapToken(token)) {
    throw new UnsafePluginYamlPatch(
      "The changed mapping has no editable source token",
      context.path,
      map,
      after,
    );
  }

  const desiredEntries = Object.entries(after).filter(
    ([, value]) => value !== undefined,
  );
  const desiredKeys = new Set(desiredEntries.map(([key]) => key));
  const seenKeys = new Set<string>();
  const nextItems: CstCollectionItem[] = [];

  map.items.forEach((pair, index) => {
    const item = token.items[index];
    const key = scalarMapKey(pair);
    if (!item || key === null) {
      throw new UnsafePluginYamlPatch(
        "Complex YAML mapping keys cannot be patched safely",
        context.path,
        map,
        after,
      );
    }

    const preserveUnknown =
      context.preserveUnknownPluginKeys &&
      key !== "tag" &&
      key !== "type" &&
      key !== "args";
    if (preserveUnknown) {
      nextItems.push(structuredClone(item));
      return;
    }

    if (!desiredKeys.has(key)) return;
    seenKeys.add(key);
    if (deepEqual(before[key], after[key])) {
      nextItems.push(structuredClone(item));
      return;
    }
    if (!pair.value || !isParsedNode(pair.value)) {
      throw new UnsafePluginYamlPatch(
        "An empty YAML mapping value cannot be changed safely",
        `${context.path}.${key}`,
        map,
        after[key],
      );
    }
    const nextItem = structuredClone(item);
    nextItem.value = reconcileNode(pair.value, before[key], after[key], {
      eol: context.eol,
      path: `${context.path}.${key}`,
    });
    nextItems.push(nextItem);
  });

  desiredEntries.forEach(([key, value]) => {
    if (seenKeys.has(key)) return;
    nextItems.push(
      createMapItem(
        key,
        value,
        token.type === "flow-collection",
        context.eol,
        token.indent,
      ),
    );
  });

  const keysUnchanged =
    map.items.length === nextItems.length &&
    map.items.every((pair) => {
      const key = scalarMapKey(pair);
      return key !== null && desiredKeys.has(key);
    });
  token.items = nextItems;
  if (nextItems.length === 0 && token.type === "block-map") {
    return createEmptyCollectionToken("map", context.eol);
  }
  if (!keysUnchanged) normalizeMapStarts(token, context.eol);
  return token;
}

function reconcileSequence(
  sequence: YAMLSeq.Parsed,
  before: unknown[],
  after: unknown[],
  context: PatchContext,
): CstNodeToken {
  const token = sequence.srcToken;
  if (!token || !isSequenceToken(token)) {
    throw new UnsafePluginYamlPatch(
      "The changed sequence has no editable source token",
      context.path,
      sequence,
      after,
    );
  }

  const nextItems: CstCollectionItem[] = [];
  if (before.length === after.length) {
    after.forEach((value, index) => {
      const node = sequence.items[index];
      const item = token.items[index];
      if (!item || !node || !isParsedNode(node)) {
        throw new UnsafePluginYamlPatch(
          "The YAML sequence cannot be aligned with its source tokens",
          `${context.path}[${index}]`,
          sequence,
          after,
        );
      }
      const nextItem = structuredClone(item);
      nextItem.value = reconcileNode(node, before[index], value, {
        eol: context.eol,
        path: `${context.path}[${index}]`,
      });
      nextItems.push(nextItem);
    });
  } else {
    const matches = longestCommonSubsequence(before, after);
    let oldCursor = 0;
    let newCursor = 0;
    for (const [matchedOld, matchedNew] of [
      ...matches,
      [before.length, after.length] as [number, number],
    ]) {
      while (oldCursor < matchedOld && newCursor < matchedNew) {
        const node = sequence.items[oldCursor];
        const item = token.items[oldCursor];
        if (!node || !item || !isParsedNode(node)) {
          throw new UnsafePluginYamlPatch(
            "The changed YAML sequence cannot be aligned safely",
            `${context.path}[${newCursor}]`,
            sequence,
            after,
          );
        }
        const nextItem = structuredClone(item);
        nextItem.value = reconcileNode(
          node,
          before[oldCursor],
          after[newCursor],
          {
            eol: context.eol,
            path: `${context.path}[${newCursor}]`,
          },
        );
        nextItems.push(nextItem);
        oldCursor += 1;
        newCursor += 1;
      }
      while (newCursor < matchedNew) {
        nextItems.push(
          createSequenceItem(
            after[newCursor],
            token.type === "flow-collection",
            context.eol,
            token.indent,
          ),
        );
        newCursor += 1;
      }
      oldCursor = matchedOld;
      if (matchedOld < before.length && matchedNew < after.length) {
        const item = token.items[matchedOld];
        if (!item) {
          throw new UnsafePluginYamlPatch(
            "The unchanged YAML sequence item has no source token",
            `${context.path}[${matchedNew}]`,
            sequence,
            after,
          );
        }
        nextItems.push(structuredClone(item));
        oldCursor += 1;
        newCursor = matchedNew + 1;
      }
    }
  }

  token.items = nextItems;
  if (nextItems.length === 0 && token.type === "block-seq") {
    return createEmptyCollectionToken("sequence", context.eol);
  }
  normalizeSequenceStarts(token, context.eol);
  return token;
}

function appendPluginsToRoot(
  source: string,
  root: YAMLMap.Parsed,
  plugins: OxiDnsPluginConfig[],
  eol: "\n" | "\r\n",
) {
  const token = root.srcToken;
  if (!token || !isMapToken(token)) {
    throw new UnsafePluginYamlPatch(
      "A plugins key cannot be appended safely to this YAML root",
      "plugins",
      root,
      plugins,
    );
  }
  const nextToken = structuredClone(token);
  const flow = nextToken.type === "flow-collection";
  (nextToken.items as CstCollectionItem[]).push(
    createMapItem("plugins", plugins, flow, eol, nextToken.indent),
  );
  normalizeMapStarts(nextToken, eol);
  return spliceNodeSource(source, root, CST.stringify(nextToken));
}

function createMapItem(
  key: string,
  value: unknown,
  flow: boolean,
  eol: "\n" | "\r\n",
  indent = 2,
): CstCollectionItem {
  const data = { __before__: 0, [key]: cleanUndefined(value) };
  const text = flow
    ? stringify({ root: data }, yamlStringifyOptions(true)).replaceAll(
        "\n",
        eol,
      )
    : blockCollectionWrapper(data, indent, eol);
  const document = parseDocument(text, { keepSourceTokens: true });
  const map =
    indent === 0 && !flow ? document.contents : document.get("root", true);
  const parsedMap = isMap(map) ? (map as YAMLMap.Parsed) : null;
  if (!parsedMap?.srcToken || !isMapToken(parsedMap.srcToken as CstNodeToken)) {
    throw new Error("Unable to create YAML mapping item");
  }
  const item = parsedMap.srcToken.items[1];
  if (!item) throw new Error(`Unable to create YAML mapping item '${key}'`);
  return structuredClone(item);
}

function createSequenceItem(
  value: unknown,
  flow: boolean,
  eol: "\n" | "\r\n",
  indent = 2,
): CstCollectionItem {
  const data = ["__before__", cleanUndefined(value)];
  const text = flow
    ? stringify({ root: data }, yamlStringifyOptions(true)).replaceAll(
        "\n",
        eol,
      )
    : blockCollectionWrapper(data, indent, eol);
  const document = parseDocument(text, { keepSourceTokens: true });
  const sequence = document.get("root", true);
  const parsedSequence = isSeq(sequence) ? (sequence as YAMLSeq.Parsed) : null;
  if (
    !parsedSequence?.srcToken ||
    !isSequenceToken(parsedSequence.srcToken as CstNodeToken)
  ) {
    throw new Error("Unable to create YAML sequence item");
  }
  const item = parsedSequence.srcToken.items[1];
  if (!item) throw new Error("Unable to create YAML sequence item");
  return structuredClone(item);
}

function createLocalizedCandidate(
  source: string,
  error: UnsafePluginYamlPatch,
  before: OxiDnsConfig,
  after: OxiDnsConfig,
  options: PluginYamlPatchOptions,
): PluginYamlPatchCandidate | undefined {
  // Reparse pristine source: reconciliation may have mutated earlier CST nodes
  // before failing. Never grow the replacement beyond a single plugin.
  try {
    const document = parseDocument(source, { keepSourceTokens: true });
    const plugins = document.get("plugins", true);
    if (!isSeq(plugins) || plugins.items.length !== before.plugins.length) {
      return undefined;
    }
    const replacements: Array<{
      node: ParsedNode;
      desired: unknown;
      path: string;
    }> = [];
    const rawPlugins = document.toJSON().plugins;
    before.plugins.forEach((plugin, index) => {
      const node = plugins.items[index];
      const tag = options.renamedTags?.get(plugin.tag) ?? plugin.tag;
      const desired = after.plugins.find((entry) => entry.tag === tag);
      if (!desired || deepEqual(plugin, desired) || !isMap(node)) return;
      // The original failure may point at a parent collection (e.g. an empty
      // value). Only trust its range if it is inside this changed plugin.
      if (
        error.node?.range &&
        node.range &&
        error.desired !== undefined &&
        error.node.range[0] >= node.range[0] &&
        error.node.range[1] <= node.range[1]
      ) {
        replacements.push({
          node: error.node,
          desired: error.desired,
          path: error.path,
        });
      }
      const args = node.get("args", true);
      if (isParsedNode(args) && desired.args !== undefined) {
        replacements.push({
          node: args,
          desired: desired.args,
          path: `plugins.${plugin.tag}.args`,
        });
      }
      // Preserve schema-unknown plugin keys, which the loaded model projects
      // away. Complete raw validation below protects them as well.
      const raw = rawPlugins[index];
      const rest = { ...raw };
      delete rest.args;
      replacements.push({
        node: node as YAMLMap.Parsed,
        desired: { ...rest, ...(projectManagedPlugin(desired) as object) },
        path: `plugins.${plugin.tag}`,
      });
    });
    for (const { node, desired, path } of replacements) {
      if (!node.range) continue;
      const block =
        node.srcToken?.type === "block-map" ||
        node.srcToken?.type === "block-seq";
      let replacement = stringify(
        cleanUndefined(desired),
        yamlStringifyOptions(!block),
      ).trimEnd();
      if (block) {
        const lineStart = source.lastIndexOf("\n", node.range[0] - 1) + 1;
        const column = node.range[0] - lineStart;
        replacement = replacement.replaceAll(
          "\n",
          detectEol(source) + " ".repeat(column),
        );
      }
      const content =
        source.slice(0, node.range[0]) +
        replacement +
        source.slice(node.range[1]);
      if (
        patchedConfigMatches(content, after) &&
        unmanagedPluginKeysMatch(source, content, before, after, options)
      ) {
        return { content, affectedPath: path };
      }
    }
  } catch {
    // Unresolvable aliases, unsupported source ranges, or malformed candidates
    // must remain manual-only rather than bypassing semantic verification.
  }
  return undefined;
}

function createEmptyCollectionToken(
  kind: "map" | "sequence",
  eol: "\n" | "\r\n",
): CstNodeToken {
  const text = `root: ${kind === "map" ? "{}" : "[]"}${eol}`;
  const document = parseDocument(text, { keepSourceTokens: true });
  const node = document.get("root", true);
  if (!isParsedNode(node) || !node.srcToken) {
    throw new Error("Unable to create an empty YAML collection");
  }
  return structuredClone(node.srcToken);
}

function standaloneTriviaRetained(source: string, content: string) {
  const lines = (text: string) =>
    text.match(/^[\t ]*(?:#[^\r\n]*)?(?:\r?\n|$)/gm)?.filter(Boolean) ?? [];
  const original = lines(source);
  let index = 0;
  for (const line of lines(content)) if (line === original[index]) index++;
  return index === original.length;
}

function patchedConfigMatches(content: string, expected: OxiDnsConfig) {
  const parsed = parseOxiDnsYaml(content);
  return Boolean(parsed.config && deepEqual(parsed.config, expected));
}

function unmanagedPluginKeysMatch(
  source: string,
  content: string,
  before: OxiDnsConfig,
  after: OxiDnsConfig,
  options: PluginYamlPatchOptions,
) {
  const original = parseDocument(source).toJSON().plugins ?? [];
  const candidate = parseDocument(content).toJSON().plugins ?? [];
  const unmanaged = (plugin: Record<string, unknown>) =>
    Object.fromEntries(
      Object.entries(plugin).filter(
        ([key]) => !["tag", "type", "args"].includes(key),
      ),
    );
  return before.plugins.every((plugin, index) => {
    const tag = options.renamedTags?.get(plugin.tag) ?? plugin.tag;
    const next = after.plugins.findIndex((entry) => entry.tag === tag);
    return (
      next < 0 ||
      deepEqual(unmanaged(original[index]), unmanaged(candidate[next]))
    );
  });
}

function projectManagedPlugin(plugin: OxiDnsPluginConfig) {
  return cleanUndefined({
    tag: plugin.tag,
    type: plugin.type,
    ...(plugin.args === undefined ? {} : { args: plugin.args }),
  });
}

function preferredScalarType(
  node: import("yaml").Scalar,
  value: string | number | boolean | null,
) {
  if (typeof value !== "string") return Scalar.PLAIN;
  if (typeof node.value === "string") {
    if (
      node.type === Scalar.BLOCK_FOLDED ||
      node.type === Scalar.BLOCK_LITERAL
    ) {
      return value.includes("\n") ? node.type : Scalar.QUOTE_DOUBLE;
    }
    if (
      node.type === Scalar.QUOTE_DOUBLE ||
      node.type === Scalar.QUOTE_SINGLE
    ) {
      return node.type;
    }
    if (node.type === Scalar.PLAIN && isSafePlainString(value)) {
      return Scalar.PLAIN;
    }
  }
  return Scalar.QUOTE_DOUBLE;
}

function isSafePlainString(value: string) {
  if (!value || value.includes("\n") || value.includes("\r")) return false;
  try {
    const parsed = parseDocument(`value: ${value}\n`).get("value");
    return typeof parsed === "string" && parsed === value;
  } catch {
    return false;
  }
}

function scalarSourceValue(value: string | number | boolean | null) {
  if (value === null) return "null";
  return String(value);
}

function normalizeMapStarts(
  token: Extract<CstNodeToken, { type: "block-map" | "flow-collection" }>,
  eol: "\n" | "\r\n",
) {
  if (token.type === "flow-collection") {
    normalizeFlowStarts(token.items);
    return;
  }
  normalizeBlockStarts(token.items, token.indent, eol, false);
}

function normalizeSequenceStarts(
  token: Extract<CstNodeToken, { type: "block-seq" | "flow-collection" }>,
  eol: "\n" | "\r\n",
) {
  if (token.type === "flow-collection") {
    normalizeFlowStarts(token.items);
    return;
  }
  normalizeBlockStarts(token.items, token.indent, eol, true);
}

function normalizeFlowStarts(items: CstCollectionItem[]) {
  items.forEach((item, index) => {
    const commaIndex = item.start.findIndex((part) => part.type === "comma");
    if (index === 0) {
      if (commaIndex >= 0) item.start.splice(commaIndex, 1);
      return;
    }
    if (commaIndex >= 0) return;
    const template = createSequenceItem("value", true, "\n").start;
    const comma = template.find((part) => part.type === "comma");
    if (comma) item.start.unshift(structuredClone(comma));
  });
}

function normalizeBlockStarts(
  items: CstCollectionItem[],
  indent: number,
  eol: "\n" | "\r\n",
  sequence: boolean,
) {
  items.forEach((item, index) => {
    const markerType = sequence ? "seq-item-ind" : null;
    const markerIndex = markerType
      ? item.start.findIndex((part) => part.type === markerType)
      : -1;
    const prefixEnd = markerIndex >= 0 ? markerIndex : item.start.length;
    const hasIndent = item.start
      .slice(0, prefixEnd)
      .some((part) => part.type === "space" && part.source.length >= indent);

    if (index === 0) {
      const firstIndent = item.start.findIndex(
        (part, partIndex) =>
          partIndex < prefixEnd &&
          part.type === "space" &&
          part.source.length >= indent,
      );
      if (firstIndent >= 0) item.start.splice(firstIndent, 1);
      return;
    }

    if (hasIndent) return;
    const generated = sequence
      ? createSequenceItem("value", false, eol, indent)
      : createMapItem("value", 1, false, eol, indent);
    const indentToken = generated.start.find(
      (part) => part.type === "space" && part.source.length > 0,
    );
    if (indentToken) {
      const copy = structuredClone(indentToken);
      copy.source = " ".repeat(indent);
      item.start.unshift(copy);
    }
  });
}

function longestCommonSubsequence(before: unknown[], after: unknown[]) {
  // A full LCS matrix is useful for retaining comments on moved array items,
  // but configuration arrays may contain thousands of rules. Bound the
  // quadratic path and retain the common edges for large arrays instead.
  const maxLcsCells = 100_000;
  if (
    before.length > 0 &&
    after.length > Math.floor(maxLcsCells / before.length)
  ) {
    return commonEdgeMatches(before, after);
  }

  const lengths = Array.from({ length: before.length + 1 }, () =>
    Array<number>(after.length + 1).fill(0),
  );
  for (let left = before.length - 1; left >= 0; left -= 1) {
    for (let right = after.length - 1; right >= 0; right -= 1) {
      lengths[left][right] = deepEqual(before[left], after[right])
        ? lengths[left + 1][right + 1] + 1
        : Math.max(lengths[left + 1][right], lengths[left][right + 1]);
    }
  }

  const matches: Array<[number, number]> = [];
  let left = 0;
  let right = 0;
  while (left < before.length && right < after.length) {
    if (deepEqual(before[left], after[right])) {
      matches.push([left, right]);
      left += 1;
      right += 1;
    } else if (lengths[left + 1][right] >= lengths[left][right + 1]) {
      left += 1;
    } else {
      right += 1;
    }
  }
  return matches;
}

function commonEdgeMatches(before: unknown[], after: unknown[]) {
  const matches: Array<[number, number]> = [];
  let prefix = 0;
  while (
    prefix < before.length &&
    prefix < after.length &&
    deepEqual(before[prefix], after[prefix])
  ) {
    matches.push([prefix, prefix]);
    prefix += 1;
  }

  const suffix: Array<[number, number]> = [];
  let oldIndex = before.length - 1;
  let newIndex = after.length - 1;
  while (
    oldIndex >= prefix &&
    newIndex >= prefix &&
    deepEqual(before[oldIndex], after[newIndex])
  ) {
    suffix.push([oldIndex, newIndex]);
    oldIndex -= 1;
    newIndex -= 1;
  }
  suffix.reverse();
  return matches.concat(suffix);
}

function yamlStringifyOptions(flow: boolean) {
  return {
    collectionStyle: flow ? ("flow" as const) : ("block" as const),
    indent: 2,
    lineWidth: 0,
    nullStr: "null",
  };
}

function blockCollectionWrapper(
  value: unknown,
  indent: number,
  eol: "\n" | "\r\n",
) {
  const body = stringify(value, yamlStringifyOptions(false)).trimEnd();
  if (indent === 0) return `${body.replaceAll("\n", eol)}${eol}`;
  const prefix = " ".repeat(indent);
  const indented = body
    .split("\n")
    .map((line) => `${prefix}${line}`)
    .join(eol);
  return `root:${eol}${indented}${eol}`;
}

function spliceNodeSource(
  source: string,
  node: ParsedNode,
  replacement: string,
) {
  if (!node.range) throw new Error("YAML node has no source range");
  return (
    source.slice(0, node.range[0]) + replacement + source.slice(node.range[2])
  );
}

function confirmationResult(
  reason: string,
  affectedPath: string,
  candidate?: PluginYamlPatchCandidate,
): PluginYamlPatchResult {
  return {
    status: "needs_confirmation",
    reason,
    affectedPath,
    ...(candidate ? { candidate } : {}),
  };
}

function scalarMapKey(pair: Pair<ParsedNode, ParsedNode | null>) {
  return isScalar(pair.key) && typeof pair.key.value === "string"
    ? pair.key.value
    : null;
}

function detectEol(source: string): "\n" | "\r\n" {
  return source.includes("\r\n") ? "\r\n" : "\n";
}

function isScalarValue(
  value: unknown,
): value is string | number | boolean | null {
  return (
    value === null ||
    typeof value === "string" ||
    typeof value === "number" ||
    typeof value === "boolean"
  );
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value && typeof value === "object" && !Array.isArray(value));
}

function cleanUndefined(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(cleanUndefined);
  if (!isPlainRecord(value)) return value;
  return Object.fromEntries(
    Object.entries(value)
      .filter(([, entry]) => entry !== undefined)
      .map(([key, entry]) => [key, cleanUndefined(entry)]),
  );
}

function deepEqual(left: unknown, right: unknown): boolean {
  if (Object.is(left, right)) return true;
  if (Array.isArray(left) || Array.isArray(right)) {
    if (!Array.isArray(left) || !Array.isArray(right)) return false;
    return (
      left.length === right.length &&
      left.every((entry, index) => deepEqual(entry, right[index]))
    );
  }
  if (!isPlainRecord(left) || !isPlainRecord(right)) return false;

  const leftEntries = Object.entries(left).filter(
    ([, value]) => value !== undefined,
  );
  const rightKeys = Object.keys(right).filter(
    (key) => right[key] !== undefined,
  );
  if (leftEntries.length !== rightKeys.length) return false;
  return leftEntries.every(
    ([key, value]) =>
      Object.prototype.hasOwnProperty.call(right, key) &&
      right[key] !== undefined &&
      deepEqual(value, right[key]),
  );
}

function isParsedNode(value: unknown): value is ParsedNode {
  return Boolean(value && typeof value === "object" && "toJSON" in value);
}

function isMapToken(
  token: CstNodeToken,
): token is Extract<CstNodeToken, { type: "block-map" | "flow-collection" }> {
  return token.type === "block-map" || token.type === "flow-collection";
}

function isSequenceToken(
  token: CstNodeToken,
): token is Extract<CstNodeToken, { type: "block-seq" | "flow-collection" }> {
  return token.type === "block-seq" || token.type === "flow-collection";
}
