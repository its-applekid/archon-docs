import { StoreError, assertDocId, docState, editKey, mutate, read, upgrade } from "./store.mjs";
import { appendEvent } from "../functions/events.mjs";
import { scanBlocks } from "./anchor-core.mjs";
import { toHtml, toMd } from "./inline-md.mjs";
import { createHash } from "node:crypto";
import { closeSync, constants, fstatSync, lstatSync, openSync, readSync, readdirSync } from "node:fs";
import { isAbsolute } from "node:path";

// The one apply path (P4-N).
//
// Every direct edit and every accepted suggestion reaches durable state
// through exactly one operation in this module. It owns the mode decision,
// the manifest, the effective base, the repository source and pull request,
// and the P3-E receipt compare-and-swap. It owns no authority: the caller has
// already proven who the actor is and what that actor may do, and this module
// refuses to re-derive either from a request, from public HTML, or from a
// document file.
//
// It is deliberately context-free. It never imports a Functions context, a
// provider SDK, an identity or access helper, or the notification fan-out, and
// it emits no log line. `edit.mjs` owns the single `notify()` call site.

/* ------------------------------------------------------------------ tables */

const REPOSITORY = "repository";
const STANDALONE = "standalone";

const API_ORIGIN = "https://api.github.com";
const BODY_MARKER = "<!-- body -->";
const COMMITTER_NAME = "Architecture Docs";
const PULL_BODY =
  "Edits proposed from the hosted document. Each commit changes one build-approved block.";
const SUGGESTION_PULL_BODY =
  `${PULL_BODY} Accepted suggestions retain their authorship in their commits and receipts.`;
const TRAILER_NAME = "X-Suggestion-Id";

const ENV_NAMES = Object.freeze([
  "DOCS_REPO", "DOCS_BASE_BRANCH", "DOCS_GITHUB_TOKEN", "DOCS_BOT_EMAIL",
]);

const DATA_FUNCTION_KEYS = Object.freeze([
  "storeFn", "readFn", "mutateFn", "fetchFn", "appendEventFn", "nowFn", "sha256Fn",
  "closeSyncFn", "fstatSyncFn", "lstatSyncFn", "openSyncFn", "readSyncFn", "readdirSyncFn",
  "scanBlocksFn", "toMdFn", "toHtmlFn",
]);
const SCALAR_KEYS = Object.freeze(["manifestRoot", "env"]);
const DEPENDENCY_KEYS = Object.freeze([...DATA_FUNCTION_KEYS, ...SCALAR_KEYS]);
const MANIFEST_KEYS = Object.freeze(["docId", "instance", "commit", "blocks"]);
const ROW_KEYS = Object.freeze(["file", "section", "tag", "hash"]);
const ACTOR_KEYS = Object.freeze(["sub", "name", "email"]);
const RECEIPT_KEYS = Object.freeze(["v", "aid", "text", "by", "at", "baseHash", "pr"]);
const DIRECT_KEYS = Object.freeze([...RECEIPT_KEYS, "via"]);
const SUGGESTION_KEYS = Object.freeze([...DIRECT_KEYS, "sugId", "acceptedBy", "acceptedAt"]);
const INPUT_KEYS = Object.freeze([
  "docId", "aid", "text", "author", "acceptedBy", "sugId", "via", "expectBase",
]);
const ENVELOPE_KEYS = Object.freeze(["value", "etag"]);
const RESULT_KEYS = Object.freeze(["value", "etag", "changed"]);
const ANCHOR_SECTION_KEYS = Object.freeze(["ids", "texts"]);
const TAGS = Object.freeze(["p", "h2", "h3", "h4"]);
const SKIPPED_DIRECTORIES = new Set([".git", "_site", "node_modules", "netlify"]);

const DOC_ID_PATTERN = /^[0-9a-f]{6}$/;
const AID_PATTERN = /^a[0-9a-f]{8}$/;
const INSTANCE_PATTERN = /^[A-Za-z0-9]+(?:[._-][A-Za-z0-9]+)*$/;
const FILE_PATTERN = /^sections\/[a-z0-9]+(?:[._-][a-z0-9]+)*\.html$/;
const MODE_SECTION_PATTERN = /^[a-z0-9][a-z0-9._-]*$/;
const HASH_PATTERN = /^[0-9a-f]{64}$/;
const COMMIT_PATTERN = /^(?:[0-9a-f]{7,64})?$/;
const MODE_COMMIT_PATTERN = /^(?:[0-9a-f]{7})?$/;
const BLOB_SHA_PATTERN = /^[0-9a-f]{40}$/;
const SUBJECT_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._~-]{0,127}$/;
const EMAIL_LOCAL_PATTERN =
  /^[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*$/;
const DNS_LABEL_PATTERN = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const EMAIL_EDGE_WHITESPACE = /^[ \t\n\r\f]+|[ \t\n\r\f]+$/g;
const NON_ASCII_PATTERN = /[^\x00-\x7f]/;
const TIMESTAMP_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const SUGGESTION_ID_PATTERN = /^s_[a-z0-9]{1,48}_[0-9a-f]{8}$/;
const LONE_SURROGATE_PATTERN =
  /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;
const REPO_PATTERN = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;
const BRANCH_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$/;
const BASE64_PATTERN = /^[A-Za-z0-9+/]*={0,2}$/;

const MAX_TEXT_UNITS = 4_000;
const MAX_NAME_UNITS = 200;
const MAX_EMAIL_UNITS = 254;
const MAX_RESPONSE_BYTES = 2_097_152;
const MAX_CONTENT_BYTES = 1_048_576;
const REQUEST_TIMEOUT_MS = 10_000;

const MAX_DEPTH = 12;
const MAX_ENTRIES = 4_096;
const MAX_CANDIDATES = 64;
const MAX_FILE_BYTES = 2_097_152;
const MAX_TOTAL_BYTES = 8_388_608;
const MAX_MANIFEST_BLOCKS = 5_000;
const MAX_MODE_BLOCKS = 1_000;
const MAX_TOTAL_BLOCKS = 10_000;
const READ_CHUNK = 65_536;

/** The complete public error table: code -> [status, message]. */
const PUBLIC_ERRORS = Object.freeze({
  "invalid-body": [400, "Invalid request body"],
  "not-found": [404, "Document or block not found"],
  conflict: [409, "The block changed since this document was built"],
  "invalid-state": [500, "Invalid edit state"],
  "repository-unavailable": [502, "Repository write unavailable"],
  unavailable: [503, "Edit state unavailable"],
});

/**
 * The one public apply failure. It carries a status, a stable code, a safe
 * message, and — for a base or source conflict only — the current hash and the
 * bounded current text. It never carries a cause, a provider body, a path, a
 * ref, a token, a store key, or an actor.
 */
export class ApplyError extends Error {
  /**
   * @param {string} code
   * @param {{currentHash?: string, current?: string | null}} [details]
   */
  constructor(code, details = {}) {
    // Own-property only: a forged code such as `toString` or `constructor`
    // would otherwise resolve through the prototype chain and yield a row that
    // is not a row, producing an `undefined` status and message.
    const known = hasOwn(PUBLIC_ERRORS, code) ? code : "invalid-state";
    const row = PUBLIC_ERRORS[known];
    super(row[1]);
    const fixed = (key, value, enumerable) => {
      Object.defineProperty(this, key, {
        value, writable: false, enumerable, configurable: false,
      });
    };
    fixed("message", row[1], false);
    fixed("status", row[0], true);
    fixed("code", known, true);
    fixed("currentHash", details.currentHash, true);
    fixed("current", details.current, true);
  }
}

const applyFail = (code) => new ApplyError(code);

/** A base or source conflict: both bounded current fields are always present. */
function applyConflict(currentHash, current) {
  return new ApplyError("conflict", {
    currentHash: typeof currentHash === "string" && HASH_PATTERN.test(currentHash)
      ? currentHash
      : undefined,
    current: typeof current === "string" ? current : null,
  });
}

/** The private sentinel thrown out of a pure `mutate()` callback. It never
 * escapes this module: the caller converts it into a public conflict after the
 * callback has returned, because no hash may be computed inside the callback. */
class ReceiptConflict extends Error {
  constructor(observed) {
    super("receipt");
    this.observed = observed;
  }
}

/* ------------------------------------------------------------- shape checks */

const rawCompare = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
const hasOwn = (value, key) => Object.prototype.hasOwnProperty.call(value, key);

function sameSet(actual, expected) {
  if (actual.length !== expected.length) return false;
  const sorted = [...actual].sort(rawCompare);
  const wanted = [...expected].sort(rawCompare);
  return wanted.every((key, index) => sorted[index] === key);
}

function isDataDescriptor(object, key) {
  const descriptor = Object.getOwnPropertyDescriptor(object, key);
  return descriptor !== undefined &&
    hasOwn(descriptor, "value") &&
    descriptor.enumerable === true;
}

/** Plain JSON-style object: `Object.prototype` or null prototype, no symbol
 * keys, every own property an enumerable data property. */
function isPlainRecord(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null) return false;
  if (Object.getOwnPropertySymbols(value).length !== 0) return false;
  return Object.getOwnPropertyNames(value).every((key) => isDataDescriptor(value, key));
}

function isExactRecord(value, keys) {
  return isPlainRecord(value) && sameSet(Object.getOwnPropertyNames(value), keys);
}

/** Ordinary object whose own keys are exactly `keys` in exactly that order. */
function isExactOrderedObject(value, keys) {
  if (value === null || typeof value !== "object" || Array.isArray(value) ||
      Object.getPrototypeOf(value) !== Object.prototype) {
    return false;
  }
  const own = Reflect.ownKeys(value);
  if (own.length !== keys.length || !keys.every((key, index) => own[index] === key)) return false;
  return keys.every((key) => isDataDescriptor(value, key));
}

function isDenseArray(value) {
  if (!Array.isArray(value) || Object.getOwnPropertySymbols(value).length !== 0) return false;
  const names = Object.getOwnPropertyNames(value);
  if (names.length !== value.length + 1 || names[names.length - 1] !== "length") return false;
  for (let index = 0; index < value.length; index += 1) {
    if (names[index] !== String(index) || !isDataDescriptor(value, String(index))) return false;
  }
  return true;
}

function isTimestamp(value) {
  if (typeof value !== "string" || !TIMESTAMP_PATTERN.test(value)) return false;
  try {
    return new Date(value).toISOString() === value;
  } catch {
    return false;
  }
}

/** P2-G's canonical mailbox grammar. It is duplicated here on purpose: this
 * module may not import an identity or access helper, and the value must
 * already be normalized rather than normalized here. */
function isNormalizedEmail(value) {
  if (typeof value !== "string" || value.length === 0 || value.length > MAX_EMAIL_UNITS) {
    return false;
  }
  if (value.replace(EMAIL_EDGE_WHITESPACE, "") !== value) return false;
  if (NON_ASCII_PATTERN.test(value)) return false;
  if (value.toLowerCase() !== value) return false;
  const at = value.indexOf("@");
  if (at === -1 || value.indexOf("@", at + 1) !== -1) return false;
  if (!EMAIL_LOCAL_PATTERN.test(value.slice(0, at))) return false;
  const labels = value.slice(at + 1).split(".");
  return labels.length >= 2 && labels.every((label) => DNS_LABEL_PATTERN.test(label));
}

function isActor(value) {
  if (!isExactOrderedObject(value, ACTOR_KEYS)) return false;
  const { sub, name, email } = value;
  if (typeof sub !== "string" || !SUBJECT_PATTERN.test(sub)) return false;
  if (typeof name !== "string" || name.length > MAX_NAME_UNITS) return false;
  if (typeof email !== "string") return false;
  return email.length === 0 || isNormalizedEmail(email);
}

const cloneActor = (actor) => ({ sub: actor.sub, name: actor.name, email: actor.email });

const sameActor = (a, b) => a.sub === b.sub && a.name === b.name && a.email === b.email;

/** Structural equality over the finite, JSON-only receipt shape. */
function sameReceipt(a, b) {
  if (!isPlainRecord(a) || !isPlainRecord(b)) return false;
  const left = Reflect.ownKeys(a);
  const right = Reflect.ownKeys(b);
  if (left.length !== right.length || !left.every((key, index) => right[index] === key)) {
    return false;
  }
  return left.every((key) => {
    const one = a[key];
    const two = b[key];
    if (isPlainRecord(one) || isPlainRecord(two)) return sameReceipt(one, two);
    return Object.is(one, two);
  });
}

/* ------------------------------------------------------------- the manifest */

/**
 * Validate and freshly clone one exact P2-D manifest.
 *
 * The result is the canonical `{docId, instance, commit, blocks}` object in
 * that order, with each row's four fields in their declared order. It performs
 * no I/O, reads no configuration, and confers no authority: an authority field
 * anywhere in the document is a rejection, not an input.
 *
 * @param {unknown} value
 * @param {string} expectedDocId
 * @returns {{docId: string, instance: string, commit: string, blocks: object}}
 */
export function assertApplyManifest(value, expectedDocId) {
  if (typeof expectedDocId !== "string" || !DOC_ID_PATTERN.test(expectedDocId)) {
    throw applyFail("invalid-state");
  }
  if (!isExactOrderedObject(value, MANIFEST_KEYS)) throw applyFail("invalid-state");
  const { docId, instance, commit, blocks } = value;
  if (typeof docId !== "string" || docId !== expectedDocId) throw applyFail("invalid-state");
  if (typeof instance !== "string" || !INSTANCE_PATTERN.test(instance)) {
    throw applyFail("invalid-state");
  }
  if (typeof commit !== "string" || !COMMIT_PATTERN.test(commit)) throw applyFail("invalid-state");
  if (!isPlainRecord(blocks) || Object.getPrototypeOf(blocks) !== Object.prototype) {
    throw applyFail("invalid-state");
  }
  const aids = Reflect.ownKeys(blocks);
  // An oversized manifest is a corrupt document, not a transient outage: it is
  // invalid state (500), never a 503 that invites a retry.
  if (aids.length > MAX_MANIFEST_BLOCKS) throw applyFail("invalid-state");
  const rows = {};
  for (const aid of aids) {
    if (typeof aid !== "string" || !AID_PATTERN.test(aid)) throw applyFail("invalid-state");
    const row = blocks[aid];
    if (!isExactOrderedObject(row, ROW_KEYS)) throw applyFail("invalid-state");
    if (typeof row.file !== "string" || !FILE_PATTERN.test(row.file) ||
        typeof row.section !== "string" || row.section.length === 0 ||
        typeof row.tag !== "string" || !TAGS.includes(row.tag) ||
        typeof row.hash !== "string" || !HASH_PATTERN.test(row.hash)) {
      throw applyFail("invalid-state");
    }
    rows[aid] = Object.freeze({
      file: row.file, section: row.section, tag: row.tag, hash: row.hash,
    });
  }
  return Object.freeze({ docId, instance, commit, blocks: Object.freeze(rows) });
}

/**
 * The additional P4-S publication subset a Mode A manifest must satisfy. The
 * generic P2-D validator admits an eight-character commit and five thousand
 * rows; the private standalone sidecar admits neither, and this narrowing is
 * never widened back to the generic bounds.
 *
 * @param {{commit: string, blocks: object}} manifest
 */
function assertModeSubset(manifest) {
  if (!MODE_COMMIT_PATTERN.test(manifest.commit)) throw applyFail("invalid-state");
  const aids = Object.getOwnPropertyNames(manifest.blocks);
  if (aids.length > MAX_MODE_BLOCKS) throw applyFail("invalid-state");
  for (const aid of aids) {
    if (!MODE_SECTION_PATTERN.test(manifest.blocks[aid].section)) throw applyFail("invalid-state");
  }
}

/* -------------------------------------------------------------- the receipt */

/**
 * Validate and freshly clone exactly one P3-E receipt.
 *
 * `expectedAid` is mandatory. The three accepted shapes are the initial
 * seven-field receipt, the eight-field `via: "edit"` receipt, and the
 * eleven-field `via: "suggestion"` receipt, each in its exact declared field
 * order. This is the sole exported server receipt validator; P3-E's private
 * validator stays behaviorally identical to it.
 *
 * @param {unknown} value
 * @param {string} expectedAid
 * @returns {object} A fresh receipt.
 */
export function assertApplyReceipt(value, expectedAid) {
  if (typeof expectedAid !== "string" || !AID_PATTERN.test(expectedAid)) {
    throw applyFail("invalid-state");
  }
  let record;
  try {
    record = upgrade(value);
  } catch {
    throw applyFail("invalid-state");
  }
  if (!isPlainRecord(record)) throw applyFail("invalid-state");
  const via = hasOwn(record, "via") ? record.via : undefined;
  let keys;
  if (via === undefined) keys = RECEIPT_KEYS;
  else if (via === "edit") keys = DIRECT_KEYS;
  else if (via === "suggestion") keys = SUGGESTION_KEYS;
  else throw applyFail("invalid-state");
  if (!isExactOrderedObject(record, keys)) throw applyFail("invalid-state");
  const { v, aid, text, by, at, baseHash, pr } = record;
  if (v !== 1 ||
      typeof aid !== "string" || !AID_PATTERN.test(aid) || aid !== expectedAid ||
      typeof text !== "string" || text.length > MAX_TEXT_UNITS ||
      !isActor(by) ||
      !isTimestamp(at) ||
      typeof baseHash !== "string" || !HASH_PATTERN.test(baseHash) ||
      !(pr === null || (Number.isSafeInteger(pr) && pr > 0))) {
    throw applyFail("invalid-state");
  }
  const receipt = { v: 1, aid, text, by: cloneActor(by), at, baseHash, pr };
  if (via === undefined) return receipt;
  receipt.via = via;
  if (via === "edit") return receipt;
  const { sugId, acceptedBy, acceptedAt } = record;
  if (typeof sugId !== "string" || !SUGGESTION_ID_PATTERN.test(sugId) ||
      !isActor(acceptedBy) || !isTimestamp(acceptedAt)) {
    throw applyFail("invalid-state");
  }
  receipt.sugId = sugId;
  receipt.acceptedBy = cloneActor(acceptedBy);
  receipt.acceptedAt = acceptedAt;
  return receipt;
}

/* --------------------------------------------------------------- the seam */

const badDependencies = () => new TypeError("Invalid git edit dependencies");

/** One narrow, one-time snapshot of exactly the four configuration names.
 * `process.env` is never enumerated. */
function snapshotEnvironment() {
  const captured = {};
  for (const name of ENV_NAMES) {
    const value = process.env[name];
    if (typeof value === "string") captured[name] = value;
  }
  return Object.freeze(captured);
}

function captureEnvironment(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value) ||
      Object.getPrototypeOf(value) !== Object.prototype ||
      Object.getOwnPropertySymbols(value).length !== 0) {
    throw badDependencies();
  }
  const captured = {};
  for (const name of Object.getOwnPropertyNames(value)) {
    if (!ENV_NAMES.includes(name) || !isDataDescriptor(value, name)) throw badDependencies();
    if (typeof value[name] !== "string") throw badDependencies();
    captured[name] = value[name];
  }
  return Object.freeze(captured);
}

function captureManifestRoot(value) {
  if (typeof value !== "string" || value.length === 0 || value.includes("\0") ||
      !isAbsolute(value)) {
    throw badDependencies();
  }
  let normalized = value;
  while (normalized.length > 1 && normalized.endsWith("/")) normalized = normalized.slice(0, -1);
  return normalized;
}

/**
 * Create one git-edit service from one closed ordinary dependency object.
 *
 * Every member is optional and every omitted member falls back to the
 * canonical production import. An unknown key, a symbol, an accessor, an
 * array, `null`, a custom prototype, a wrong type, or an explicit `undefined`
 * throws `TypeError("Invalid git edit dependencies")` synchronously, so no
 * request field can ever select a dependency.
 *
 * @param {object} [dependencies]
 * @returns {{readApplyManifest: Function, readApplyReceipt: Function,
 *            readEffectiveBase: Function, applyText: Function}}
 */
export function createGitEditService(dependencies = {}) {
  if (dependencies === null || typeof dependencies !== "object" ||
      Array.isArray(dependencies) ||
      Object.getPrototypeOf(dependencies) !== Object.prototype ||
      Object.getOwnPropertySymbols(dependencies).length !== 0) {
    throw badDependencies();
  }
  const supplied = Object.getOwnPropertyNames(dependencies);
  for (const key of supplied) {
    if (!DEPENDENCY_KEYS.includes(key) || !isDataDescriptor(dependencies, key)) {
      throw badDependencies();
    }
  }
  for (const key of DATA_FUNCTION_KEYS) {
    if (supplied.includes(key) && typeof dependencies[key] !== "function") throw badDependencies();
  }

  const deps = Object.freeze({
    storeFn: dependencies.storeFn ?? docState,
    readFn: dependencies.readFn ?? read,
    mutateFn: dependencies.mutateFn ?? mutate,
    fetchFn: dependencies.fetchFn ?? ((input, init) => globalThis.fetch(input, init)),
    appendEventFn: dependencies.appendEventFn ?? appendEvent,
    nowFn: dependencies.nowFn ?? Date.now,
    sha256Fn: dependencies.sha256Fn ??
      ((value) => createHash("sha256").update(value, "utf8").digest("hex")),
    closeSyncFn: dependencies.closeSyncFn ?? closeSync,
    fstatSyncFn: dependencies.fstatSyncFn ?? fstatSync,
    lstatSyncFn: dependencies.lstatSyncFn ?? lstatSync,
    openSyncFn: dependencies.openSyncFn ?? openSync,
    readSyncFn: dependencies.readSyncFn ?? readSync,
    readdirSyncFn: dependencies.readdirSyncFn ?? readdirSync,
    scanBlocksFn: dependencies.scanBlocksFn ?? scanBlocks,
    toMdFn: dependencies.toMdFn ?? toMd,
    toHtmlFn: dependencies.toHtmlFn ?? toHtml,
    manifestRoot: supplied.includes("manifestRoot")
      ? captureManifestRoot(dependencies.manifestRoot)
      : null,
    env: supplied.includes("env") ? captureEnvironment(dependencies.env) : null,
  });

  let environment = deps.env;
  let index = null;

  /* ------------------------------------------------------------- helpers */

  const sha256 = (value) => {
    let digest;
    try {
      digest = deps.sha256Fn(value);
    } catch {
      throw applyFail("invalid-state");
    }
    if (typeof digest !== "string" || !HASH_PATTERN.test(digest)) {
      throw applyFail("invalid-state");
    }
    return digest;
  };

  const toHtmlOf = (text) => {
    let html;
    try {
      html = deps.toHtmlFn(text);
    } catch {
      throw applyFail("invalid-state");
    }
    if (typeof html !== "string") throw applyFail("invalid-state");
    return html;
  };

  /** The round-trip admission gate: text is storable only when both P2-D twins
   * reproduce it exactly. The original text is stored, never a normalised
   * copy. */
  const isEditableText = (value) => {
    if (typeof value !== "string" || value.length > MAX_TEXT_UNITS) return false;
    if (LONE_SURROGATE_PATTERN.test(value)) return false;
    try {
      const html = deps.toHtmlFn(value);
      if (typeof html !== "string" || deps.toMdFn(html) !== value) return false;
      return deps.toHtmlFn(deps.toMdFn(html)) === html;
    } catch {
      return false;
    }
  };

  /** The bounded 409 `current` projection: the block's text only when it is
   * safely representable in the editable vocabulary, otherwise null. */
  const representable = (inner) => {
    let text;
    try {
      text = deps.toMdFn(inner);
    } catch {
      return null;
    }
    if (typeof text !== "string" || text.length > MAX_TEXT_UNITS) return null;
    if (LONE_SURROGATE_PATTERN.test(text)) return null;
    try {
      if (deps.toHtmlFn(text) !== inner) return null;
      if (deps.toMdFn(deps.toHtmlFn(text)) !== text) return null;
    } catch {
      return null;
    }
    return text;
  };

  /** Storage faults carry a stable code: `unavailable` is the 503 edit-state
   * failure, and every other classified fault is an invalid state. */
  const storeCode = (error) => {
    if (error instanceof StoreError) {
      return error.code === "unavailable" ? "unavailable" : "invalid-state";
    }
    return "unavailable";
  };

  const openStore = () => {
    try {
      return deps.storeFn();
    } catch (error) {
      throw applyFail(storeCode(error));
    }
  };

  const slotKey = (docId, aid) => {
    try {
      return editKey(docId, aid);
    } catch {
      throw applyFail("invalid-state");
    }
  };

  /* --------------------------------------------------- the sidecar index */

  const joinPath = (directory, name) => (directory === "/" ? `/${name}` : `${directory}/${name}`);

  const walk = (directory, segments, depth, counters, candidates) => {
    let rows;
    try {
      rows = deps.readdirSyncFn(directory, { withFileTypes: true });
    } catch {
      throw applyFail("unavailable");
    }
    if (!Array.isArray(rows)) throw applyFail("unavailable");
    counters.entries += rows.length;
    if (counters.entries > MAX_ENTRIES) throw applyFail("unavailable");
    const sorted = [...rows].sort((a, b) => rawCompare(a.name, b.name));
    for (const row of sorted) {
      const name = row.name;
      if (typeof name !== "string") throw applyFail("unavailable");
      const path = joinPath(directory, name);
      if (row.isDirectory()) {
        if (SKIPPED_DIRECTORIES.has(name)) continue;
        if (depth + 1 > MAX_DEPTH) throw applyFail("unavailable");
        walk(path, [...segments, name], depth + 1, counters, candidates);
        continue;
      }
      const length = segments.length;
      if (length >= 2 && segments[length - 1] === "dist" &&
          name === `${segments[length - 2]}.edit.json`) {
        counters.candidates += 1;
        if (counters.candidates > MAX_CANDIDATES) throw applyFail("unavailable");
        candidates.push({
          path,
          relative: [...segments, name].join("/"),
          instance: segments[length - 2],
        });
      }
    }
  };

  const readCandidate = (path, counters) => {
    let info;
    try {
      info = deps.lstatSyncFn(path);
    } catch {
      throw applyFail("unavailable");
    }
    if (info.isSymbolicLink() || !info.isFile()) throw applyFail("invalid-state");
    const remaining = MAX_TOTAL_BYTES - counters.bytes;
    if (info.size > MAX_FILE_BYTES || info.size > remaining) throw applyFail("unavailable");
    if (typeof constants.O_RDONLY !== "number" || typeof constants.O_NOFOLLOW !== "number") {
      throw applyFail("unavailable");
    }
    let fd;
    try {
      fd = deps.openSyncFn(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    } catch {
      throw applyFail("unavailable");
    }
    try {
      let before;
      try {
        before = deps.fstatSyncFn(fd);
      } catch {
        throw applyFail("unavailable");
      }
      if (!before.isFile() || before.dev !== info.dev || before.ino !== info.ino) {
        throw applyFail("unavailable");
      }
      if (before.size > MAX_FILE_BYTES || before.size > remaining) throw applyFail("unavailable");
      const capacity = before.size + 1;
      const buffer = Buffer.alloc(capacity);
      let total = 0;
      while (total < capacity) {
        let count;
        try {
          count = deps.readSyncFn(fd, buffer, total, Math.min(READ_CHUNK, capacity - total), total);
        } catch {
          throw applyFail("unavailable");
        }
        if (count === 0) break;
        total += count;
      }
      if (total !== before.size) throw applyFail("unavailable");
      let after;
      try {
        after = deps.fstatSyncFn(fd);
      } catch {
        throw applyFail("unavailable");
      }
      if (after.dev !== before.dev || after.ino !== before.ino || after.size !== before.size ||
          after.mtimeMs !== before.mtimeMs || after.ctimeMs !== before.ctimeMs) {
        throw applyFail("unavailable");
      }
      counters.bytes += total;
      return buffer.subarray(0, total);
    } finally {
      try {
        deps.closeSyncFn(fd);
      } catch {
        throw applyFail("unavailable");
      }
    }
  };

  const parseSidecar = (bytes) => {
    try {
      const text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
      return JSON.parse(text);
    } catch {
      throw applyFail("invalid-state");
    }
  };

  /** The inventory root gets the same treatment as every file under it: a
   * symlinked or non-directory root is refused rather than traversed. */
  const validateRoot = (root) => {
    if (typeof root !== "string" || root.length === 0 || root.includes("\0")) {
      throw applyFail("invalid-state");
    }
    let normalized = root;
    while (normalized.length > 1 && normalized.endsWith("/")) normalized = normalized.slice(0, -1);
    let info;
    try {
      info = deps.lstatSyncFn(normalized);
    } catch {
      throw applyFail("unavailable");
    }
    if (info.isSymbolicLink() || !info.isDirectory()) throw applyFail("invalid-state");
    return normalized;
  };

  /** The complete lazy bounded immutable inventory. Only a fully valid
   * inventory is cached; a partial read is never memoized. */
  const buildIndex = () => {
    const root = deps.manifestRoot === null ? process.cwd() : deps.manifestRoot;
    const counters = { entries: 0, candidates: 0, bytes: 0, blocks: 0 };
    const candidates = [];
    walk(validateRoot(root), [], 0, counters, candidates);
    if (candidates.length === 0) throw applyFail("unavailable");
    candidates.sort((a, b) => rawCompare(a.relative, b.relative));
    const built = new Map();
    const seen = new Set();
    for (const candidate of candidates) {
      if (seen.has(candidate.relative)) throw applyFail("invalid-state");
      seen.add(candidate.relative);
      const raw = parseSidecar(readCandidate(candidate.path, counters));
      if (!isPlainRecord(raw) || typeof raw.docId !== "string" ||
          !DOC_ID_PATTERN.test(raw.docId)) {
        throw applyFail("invalid-state");
      }
      const manifest = assertApplyManifest(raw, raw.docId);
      if (manifest.instance !== candidate.instance) throw applyFail("invalid-state");
      counters.blocks += Object.getOwnPropertyNames(manifest.blocks).length;
      if (counters.blocks > MAX_TOTAL_BLOCKS) throw applyFail("unavailable");
      if (built.has(manifest.docId)) throw applyFail("invalid-state");
      built.set(manifest.docId, manifest);
    }
    return built;
  };

  const sidecarIndex = () => {
    if (index === null) index = buildIndex();
    return index;
  };

  /* ------------------------------------------------------- configuration */

  /** Mode is configuration-selected and never request-selected. Partial
   * repository configuration is a fatal invalid state in both directions:
   * a configured repository never falls back into standalone, and standalone
   * never borrows a repository value. */
  const selectMode = () => {
    if (environment === null) environment = snapshotEnvironment();
    const present = ENV_NAMES.filter((name) => hasOwn(environment, name));
    if (!present.includes(ENV_NAMES[0])) {
      if (present.length !== 0) throw applyFail("invalid-state");
      return { mode: STANDALONE, config: null };
    }
    const repo = environment.DOCS_REPO;
    const branch = hasOwn(environment, "DOCS_BASE_BRANCH")
      ? environment.DOCS_BASE_BRANCH
      : "main";
    const token = environment.DOCS_GITHUB_TOKEN;
    const botEmail = environment.DOCS_BOT_EMAIL;
    if (typeof repo !== "string" || !REPO_PATTERN.test(repo)) throw applyFail("invalid-state");
    if (typeof branch !== "string" || !BRANCH_PATTERN.test(branch) ||
        branch.includes("..") || branch.includes("//") || branch.includes("@{") ||
        branch.endsWith(".") || branch.startsWith("/") || branch.endsWith("/")) {
      throw applyFail("invalid-state");
    }
    if (typeof token !== "string" || token.length === 0) throw applyFail("invalid-state");
    if (!isNormalizedEmail(botEmail)) throw applyFail("invalid-state");
    return {
      mode: REPOSITORY,
      config: Object.freeze({
        repo,
        owner: repo.slice(0, repo.indexOf("/")),
        base: branch,
        token,
        botEmail,
      }),
    };
  };

  /* --------------------------------------------------- manifest selection */

  /** The one Mode A read: exactly one `docState()` and exactly one raw strong
   * `get()` of the private P4-S sidecar. P2-B `read()` is deliberately not used
   * because it requires the mutable `{v:1}` envelope this immutable manifest
   * intentionally does not have. */
  const readModeManifest = async (docId) => {
    const store = openStore();
    if (store === null || typeof store !== "object" || typeof store.get !== "function") {
      throw applyFail("invalid-state");
    }
    let raw;
    try {
      raw = await store.get(`mode/${docId}/manifest.json`, {
        type: "json",
        consistency: "strong",
      });
    } catch (error) {
      if (error instanceof SyntaxError) throw applyFail("invalid-state");
      throw applyFail("unavailable");
    }
    if (raw === null || raw === undefined) throw applyFail("not-found");
    if (!isPlainRecord(raw)) throw applyFail("invalid-state");
    const manifest = assertApplyManifest(raw, docId);
    assertModeSubset(manifest);
    return manifest;
  };

  async function readApplyManifest(docId) {
    if (typeof docId !== "string" || !DOC_ID_PATTERN.test(docId)) throw applyFail("invalid-state");
    try {
      assertDocId(docId);
    } catch {
      throw applyFail("invalid-state");
    }
    const selected = selectMode();
    if (selected.mode === STANDALONE) {
      return Object.freeze({ mode: STANDALONE, manifest: await readModeManifest(docId) });
    }
    const manifest = sidecarIndex().get(docId);
    if (manifest === undefined) throw applyFail("not-found");
    return Object.freeze({ mode: REPOSITORY, manifest });
  }

  /* ------------------------------------------------------ receipt reading */

  const strongReceipt = async (store, key, aid) => {
    let found;
    try {
      found = await deps.readFn(store, key, null);
    } catch (error) {
      throw applyFail(storeCode(error));
    }
    if (!isExactRecord(found, ENVELOPE_KEYS)) throw applyFail("invalid-state");
    const { value, etag } = found;
    if (value === null) {
      if (etag !== null) throw applyFail("invalid-state");
      return null;
    }
    if (typeof etag !== "string" || etag.length === 0) throw applyFail("invalid-state");
    return assertApplyReceipt(value, aid);
  };

  async function readApplyReceipt(docId, aid) {
    if (typeof docId !== "string" || !DOC_ID_PATTERN.test(docId)) throw applyFail("invalid-state");
    if (typeof aid !== "string" || !AID_PATTERN.test(aid)) throw applyFail("invalid-state");
    const store = openStore();
    return strongReceipt(store, slotKey(docId, aid), aid);
  }

  /* ------------------------------------------------------- effective base */

  /** The one effective-base definition. A receipt is authority only while its
   * stored `baseHash` still equals the manifest row hash; an absent or stale
   * receipt never becomes authority, and the canonical manifest deliberately
   * carries no source text. No GitHub or source read happens here, which is
   * what keeps suggestion list and create costs bounded. */
  const effectiveBaseOf = (mode, docId, aid, manifest, row, receipt) => {
    const current = receipt !== null && receipt.baseHash === row.hash;
    const hash = current ? sha256(toHtmlOf(receipt.text)) : row.hash;
    return Object.freeze({
      mode,
      docId,
      aid,
      section: row.section,
      tag: row.tag,
      docVersion: manifest.commit,
      manifestHash: row.hash,
      hash,
      text: current ? receipt.text : null,
      pending: current,
    });
  };

  async function readEffectiveBase(docId, aid) {
    if (typeof aid !== "string" || !AID_PATTERN.test(aid)) throw applyFail("invalid-state");
    const { mode, manifest } = await readApplyManifest(docId);
    const row = manifest.blocks[aid];
    if (row === undefined) throw applyFail("not-found");
    const store = openStore();
    const receipt = await strongReceipt(store, slotKey(docId, aid), aid);
    return effectiveBaseOf(mode, docId, aid, manifest, row, receipt);
  }

  /* ---------------------------------------------------- GitHub transport */

  const encodeSegments = (path) =>
    path.split("/").map((segment) => encodeURIComponent(segment)).join("/");

  /** Read at most two MiB from a provider response through exactly one
   * reader. */
  const readBoundedResponse = async (response) => {
    const body = response.body;
    if (body === null || body === undefined) {
      if (typeof response.arrayBuffer !== "function") throw applyFail("repository-unavailable");
      let buffer;
      try {
        buffer = await response.arrayBuffer();
      } catch {
        throw applyFail("repository-unavailable");
      }
      if (buffer.byteLength > MAX_RESPONSE_BYTES) throw applyFail("repository-unavailable");
      return new Uint8Array(buffer);
    }
    if (typeof body.getReader !== "function" || body.locked === true) {
      throw applyFail("repository-unavailable");
    }
    let reader;
    try {
      reader = body.getReader();
    } catch {
      throw applyFail("repository-unavailable");
    }
    const chunks = [];
    let total = 0;
    let broken = false;
    try {
      for (;;) {
        const result = await reader.read();
        if (result.done === true) break;
        const chunk = result.value;
        if (!(chunk instanceof Uint8Array) || total + chunk.byteLength > MAX_RESPONSE_BYTES) {
          broken = true;
          break;
        }
        chunks.push(chunk);
        total += chunk.byteLength;
      }
    } catch {
      broken = true;
    }
    if (broken) {
      try {
        await reader.cancel();
      } catch {
        // A rejected cancellation is tolerated; the lock is still released once.
      }
    }
    try {
      reader.releaseLock();
    } catch {
      // Best effort, never repeated.
    }
    if (broken) throw applyFail("repository-unavailable");
    const bytes = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.byteLength;
    }
    return bytes;
  };

  /** One bounded GitHub REST call: ten seconds, no redirect, at most two MiB of
   * response, and one fatal UTF-8 decode before a single JSON parse. */
  const callGitHub = async (config, method, path, payload) => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
    try {
      const headers = {
        Accept: "application/vnd.github+json",
        Authorization: `Bearer ${config.token}`,
        "User-Agent": "architecture-docs-edit",
        "X-GitHub-Api-Version": "2022-11-28",
      };
      const init = { method, headers, redirect: "error", signal: controller.signal };
      if (payload !== undefined) {
        headers["Content-Type"] = "application/json";
        init.body = JSON.stringify(payload);
      }
      let response;
      try {
        response = await deps.fetchFn(`${API_ORIGIN}${path}`, init);
      } catch {
        throw applyFail("repository-unavailable");
      }
      if (response === null || typeof response !== "object" ||
          !Number.isSafeInteger(response.status)) {
        throw applyFail("repository-unavailable");
      }
      const bytes = await readBoundedResponse(response);
      if (bytes.byteLength === 0) return { status: response.status, body: null };
      let text;
      try {
        text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
      } catch {
        throw applyFail("repository-unavailable");
      }
      try {
        return { status: response.status, body: JSON.parse(text) };
      } catch {
        return { status: response.status, body: null };
      }
    } finally {
      clearTimeout(timer);
    }
  };

  /* ------------------------------------------------------------ the branch */

  /** `docedit/<docId>/<first 16 lowercase hex of SHA-256(sub)>`: deterministic
   * per author and document, and it exposes neither the email nor the raw
   * subject. An accepted suggestion uses the suggester's subject, never the
   * accepter's. */
  const branchFor = (docId, sub) => `docedit/${docId}/${sha256(sub).slice(0, 16)}`;

  const refObjectSha = (body) => {
    if (!isPlainRecord(body)) return null;
    const object = body.object;
    if (!isPlainRecord(object)) return null;
    const sha = object.sha;
    return typeof sha === "string" && BLOB_SHA_PATTERN.test(sha) ? sha : null;
  };

  const readRef = async (config, ref) => {
    const result = await callGitHub(
      config, "GET", `/repos/${config.repo}/git/ref/${encodeSegments(ref)}`,
    );
    if (result.status === 404) return null;
    if (result.status !== 200) throw applyFail("repository-unavailable");
    const sha = refObjectSha(result.body);
    if (sha === null) throw applyFail("repository-unavailable");
    return sha;
  };

  /** Read the author branch, creating it from the configured base when absent.
   * A concurrent create returning 422 is accepted only after a fresh read
   * proves the exact ref now exists. The ref is never force-updated or
   * deleted. */
  const resolveBranch = async (config, branch) => {
    const existing = await readRef(config, `heads/${branch}`);
    if (existing !== null) return existing;
    const baseSha = await readRef(config, `heads/${config.base}`);
    if (baseSha === null) throw applyFail("repository-unavailable");
    const created = await callGitHub(config, "POST", `/repos/${config.repo}/git/refs`, {
      ref: `refs/heads/${branch}`,
      sha: baseSha,
    });
    if (created.status === 201) {
      const sha = refObjectSha(created.body);
      if (sha === null) throw applyFail("repository-unavailable");
      return sha;
    }
    if (created.status === 422) {
      const raced = await readRef(config, `heads/${branch}`);
      if (raced === null) throw applyFail("repository-unavailable");
      return raced;
    }
    throw applyFail("repository-unavailable");
  };

  /* --------------------------------------------------------- file contents */

  const decodeBase64Content = (value) => {
    if (typeof value !== "string") throw applyFail("repository-unavailable");
    const packed = value.split("\n").join("");
    if (packed.length % 4 !== 0 || !BASE64_PATTERN.test(packed)) {
      throw applyFail("repository-unavailable");
    }
    const bytes = Buffer.from(packed, "base64");
    if (bytes.toString("base64") !== packed) throw applyFail("repository-unavailable");
    if (bytes.byteLength > MAX_CONTENT_BYTES) throw applyFail("repository-unavailable");
    try {
      return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
    } catch {
      throw applyFail("repository-unavailable");
    }
  };

  /** Read one repository file at the author branch. A missing file, a
   * directory, a submodule, an unexpected encoding, or a non-canonical blob
   * SHA is a repository fault, never a guess. */
  const readRepositoryFile = async (config, branch, path) => {
    const result = await callGitHub(
      config, "GET",
      `/repos/${config.repo}/contents/${encodeSegments(path)}?ref=${encodeURIComponent(branch)}`,
    );
    if (result.status !== 200) throw applyFail("repository-unavailable");
    const body = result.body;
    if (!isPlainRecord(body)) throw applyFail("repository-unavailable");
    if (body.type !== "file" || body.encoding !== "base64") {
      throw applyFail("repository-unavailable");
    }
    const sha = body.sha;
    if (typeof sha !== "string" || !BLOB_SHA_PATTERN.test(sha)) {
      throw applyFail("repository-unavailable");
    }
    return { sha, text: decodeBase64Content(body.content) };
  };

  /* -------------------------------------------------------------- locator */

  /** P1-D's exact per-section `{ids, texts}` schema. Every section is
   * validated, not only the one this request selects, so a corrupt map is a
   * repository fault rather than a silently narrower search. */
  const anchorSectionIds = (text, section) => {
    let parsed;
    try {
      parsed = JSON.parse(text);
    } catch {
      throw applyFail("repository-unavailable");
    }
    if (!isPlainRecord(parsed)) throw applyFail("repository-unavailable");
    for (const name of Object.getOwnPropertyNames(parsed)) {
      const value = parsed[name];
      if (!isExactRecord(value, ANCHOR_SECTION_KEYS)) throw applyFail("repository-unavailable");
      const { ids, texts } = value;
      if (!isDenseArray(ids) || !isDenseArray(texts) || ids.length !== texts.length) {
        throw applyFail("repository-unavailable");
      }
      for (const id of ids) {
        if (typeof id !== "string" || !AID_PATTERN.test(id)) {
          throw applyFail("repository-unavailable");
        }
      }
      for (const entry of texts) {
        if (typeof entry !== "string") throw applyFail("repository-unavailable");
      }
    }
    if (!hasOwn(parsed, section)) throw applyConflict(undefined, null);
    return parsed[section].ids;
  };

  /** Split the source at its single exact body marker and scan only the bytes
   * after it, keeping every reported offset in whole-source coordinates. A
   * section that builds with zero or two markers is buildable but not
   * editable: the scan offset would be a guess, and this path may not guess. */
  const scanSourceBody = (source) => {
    const at = source.indexOf(BODY_MARKER);
    if (at === -1 || source.indexOf(BODY_MARKER, at + BODY_MARKER.length) !== -1) {
      throw applyFail("repository-unavailable");
    }
    const start = at + BODY_MARKER.length;
    let blocks;
    try {
      blocks = deps.scanBlocksFn(source.slice(start));
    } catch {
      throw applyFail("repository-unavailable");
    }
    if (!Array.isArray(blocks)) throw applyFail("repository-unavailable");
    return { start, blocks };
  };

  /**
   * Join the committed anchors map to the scanned source and prove the
   * selected block is exactly the tag the manifest recorded. The positional
   * join is used only after `anchors.json` names the aid. This returns the
   * located inner range and its bytes; the source hash gate is a separate,
   * later check, because an accepted suggestion may legitimately skip it.
   */
  const locateBlock = (row, aid, anchorsText, source) => {
    const ids = anchorSectionIds(anchorsText, row.section);
    let index = -1;
    for (let at = 0; at < ids.length; at += 1) {
      if (ids[at] !== aid) continue;
      if (index !== -1) throw applyFail("repository-unavailable");
      index = at;
    }
    if (index === -1) throw applyConflict(undefined, null);
    const { start, blocks } = scanSourceBody(source);
    // The join is positional, so it is sound only when the committed anchors
    // map and the scanned source describe the same block sequence. A length
    // mismatch means the two drifted apart since the document was built, so
    // the index no longer names the block the caller meant — including when
    // the source grew and the index still resolves to something. That is the
    // same drift a deleted block reports, and it is answered the same way:
    // a conflict that writes nothing and describes no repository state.
    if (blocks.length !== ids.length) throw applyConflict(undefined, null);
    const block = blocks[index];
    if (block === undefined) throw applyConflict(undefined, null);
    if (block === null || typeof block !== "object") throw applyFail("repository-unavailable");
    const innerStart = start + block.innerStart;
    const innerEnd = start + block.innerEnd;
    if (!Number.isSafeInteger(innerStart) || !Number.isSafeInteger(innerEnd) ||
        innerStart < start || innerEnd < innerStart || innerEnd > source.length) {
      throw applyFail("repository-unavailable");
    }
    const inner = source.slice(innerStart, innerEnd);
    if (block.tag !== row.tag) throw applyConflict(sha256(inner), representable(inner));
    return { innerStart, innerEnd, inner };
  };

  /* -------------------------------------------------------- pull requests */

  const pullNumber = (row, config, branch) => {
    if (!isPlainRecord(row)) throw applyFail("repository-unavailable");
    const number = row.number;
    if (!Number.isSafeInteger(number) || number <= 0) throw applyFail("repository-unavailable");
    const { head, base } = row;
    if (!isPlainRecord(head) || !isPlainRecord(base)) throw applyFail("repository-unavailable");
    if (head.ref !== branch || base.ref !== config.base) throw applyFail("repository-unavailable");
    return number;
  };

  /** Exactly zero or one open pull request exists per author branch. Two rows
   * is an ambiguity this path refuses rather than resolves, and it never
   * merges, closes, labels, reviews, or comments. */
  const ensurePullRequest = async (config, branch, docId, via) => {
    const query = `state=open&base=${encodeURIComponent(config.base)}` +
      `&head=${encodeURIComponent(`${config.owner}:${branch}`)}&per_page=2`;
    const listed = await callGitHub(config, "GET", `/repos/${config.repo}/pulls?${query}`);
    if (listed.status !== 200 || !isDenseArray(listed.body)) {
      throw applyFail("repository-unavailable");
    }
    if (listed.body.length > 1) throw applyFail("repository-unavailable");
    if (listed.body.length === 1) return pullNumber(listed.body[0], config, branch);
    const created = await callGitHub(config, "POST", `/repos/${config.repo}/pulls`, {
      title: `Inline edits for document ${docId}`,
      head: branch,
      base: config.base,
      body: via === "suggestion" ? SUGGESTION_PULL_BODY : PULL_BODY,
    });
    if (created.status !== 201) throw applyFail("repository-unavailable");
    return pullNumber(created.body, config, branch);
  };

  /* ------------------------------------------------------------- the commit */

  /** Replace only `[innerStart, innerEnd)` and preserve every other source
   * byte. The text author stays the commit author; the site is only the
   * committer. */
  const commitSection = async (config, branch, path, file, located, html, message, commitAuthor) =>
    callGitHub(config, "PUT", `/repos/${config.repo}/contents/${encodeSegments(path)}`, {
      message,
      content: Buffer.from(
        file.text.slice(0, located.innerStart) + html + file.text.slice(located.innerEnd),
        "utf8",
      ).toString("base64"),
      sha: file.sha,
      branch,
      author: commitAuthor,
      committer: { name: COMMITTER_NAME, email: config.botEmail },
    });

  /** The one bounded suggestion replay probe: the branch head commit, read
   * once. A trailer match is one complete line exactly `X-Suggestion-Id:
   * <sugId>`. Older commits are never searched, and no substring, case, or
   * whitespace variant matches. */
  const headCarriesSuggestion = async (config, branch, sugId) => {
    const result = await callGitHub(
      config, "GET", `/repos/${config.repo}/commits/${encodeSegments(branch)}`,
    );
    if (result.status !== 200) throw applyFail("repository-unavailable");
    const body = result.body;
    if (!isPlainRecord(body)) throw applyFail("repository-unavailable");
    const commit = body.commit;
    if (!isPlainRecord(commit)) throw applyFail("repository-unavailable");
    const message = commit.message;
    if (typeof message !== "string") throw applyFail("repository-unavailable");
    return message.split("\n").includes(`${TRAILER_NAME}: ${sugId}`);
  };

  /* ------------------------------------------------------- receipt writing */

  /**
   * Write the one receipt slot under the captured-snapshot contract.
   *
   * The callback is pure: it reads no clock, computes no hash, runs no
   * converter, consults no access table, appends no event, performs no network
   * call, and logs nothing. It only compares the draft it was handed with the
   * two values captured before the write began.
   */
  const writeReceipt = async (store, key, aid, snapshot, nextReceipt) => {
    let result;
    try {
      result = await deps.mutateFn(store, key, nextReceipt, (draft) => {
        const observed = assertApplyReceipt(draft, aid);
        if (snapshot === null) {
          if (sameReceipt(observed, nextReceipt)) return structuredClone(nextReceipt);
          // A concurrent writer completed the very same suggestion operation
          // for the very same accepter while this call was in flight. Only
          // then is a rewrite of the identical operation safe; anything else,
          // including the same operation credited to a different decider, is a
          // conflict the caller re-evaluates against the winner.
          if (sameSuggestionOperation(observed, nextReceipt)) {
            return structuredClone(nextReceipt);
          }
          throw new ReceiptConflict(observed);
        }
        if (sameReceipt(observed, nextReceipt)) return null;
        if (sameReceipt(observed, snapshot)) return structuredClone(nextReceipt);
        throw new ReceiptConflict(observed);
      });
    } catch (error) {
      if (error instanceof ReceiptConflict) {
        const current = error.observed;
        throw applyConflict(sha256(toHtmlOf(current.text)), representable(toHtmlOf(current.text)));
      }
      if (error instanceof ApplyError) throw error;
      // Every other compare-and-swap failure, including six lost races, is the
      // 503 this path has always reported. It is not a conflict the caller can
      // resolve with a fresher base, and it is never a silent success.
      throw applyFail("unavailable");
    }
    if (!isExactRecord(result, RESULT_KEYS)) throw applyFail("unavailable");
    const committed = assertApplyReceipt(result.value, aid);
    if (!sameReceipt(committed, nextReceipt)) throw applyFail("unavailable");
    return committed;
  };

  /** Best effort, and only after receipt success. An audit failure never rolls
   * back, retries, or changes the apply result.
   *
   * A document built with no history head carries the empty canonical commit,
   * and P3-B has no representation for an edit event without a document
   * version. That audit row is skipped rather than attempted: a call that
   * cannot succeed is not a better outcome than an honest absence, and the
   * apply is already durable either way. */
  const appendAudit = async (store, docId, manifest, row, actor, kind, verb) => {
    if (manifest.commit === "") return;
    try {
      await deps.appendEventFn({
        store,
        docId,
        actor: cloneActor(actor),
        kind,
        target: { aid: row.aid },
        docVersion: manifest.commit,
        summary: `${verb} edit to ${row.section}`,
      });
    } catch {
      // The apply already succeeded. The audit trail may be absent.
    }
  };

  /* ------------------------------------------------------------- the input */

  const parseInput = (input) => {
    if (!isExactRecord(input, INPUT_KEYS)) throw applyFail("invalid-body");
    const { docId, aid, text, author, acceptedBy, sugId, via, expectBase } = input;
    if (typeof docId !== "string" || !DOC_ID_PATTERN.test(docId)) throw applyFail("invalid-body");
    if (typeof aid !== "string" || !AID_PATTERN.test(aid)) throw applyFail("invalid-body");
    if (!isEditableText(text)) throw applyFail("invalid-body");
    if (!isActor(author)) throw applyFail("invalid-body");
    if (typeof expectBase !== "string" || !HASH_PATTERN.test(expectBase)) {
      throw applyFail("invalid-body");
    }
    if (via === "edit") {
      if (acceptedBy !== null || sugId !== null) throw applyFail("invalid-body");
    } else if (via === "suggestion") {
      if (!isActor(acceptedBy)) throw applyFail("invalid-body");
      if (typeof sugId !== "string" || !SUGGESTION_ID_PATTERN.test(sugId)) {
        throw applyFail("invalid-body");
      }
      if (author.sub === "system") throw applyFail("invalid-body");
    } else {
      throw applyFail("invalid-body");
    }
    return {
      docId,
      aid,
      text,
      author: cloneActor(author),
      acceptedBy: via === "suggestion" ? cloneActor(acceptedBy) : null,
      sugId: via === "suggestion" ? sugId : null,
      via,
      expectBase,
    };
  };

  /* -------------------------------------------------------------- the apply */

  /**
   * The one apply operation.
   *
   * It accepts only a trusted server actor: the caller has already
   * authenticated the identity and proven the capability. Standalone writes
   * only the receipt; repository writes Git first and the receipt second, and
   * never claims a rollback it cannot perform.
   *
   * @param {object} input
   * @returns {Promise<{receipt: object, pr: number | null}>}
   */
  async function applyText(input) {
    const call = parseInput(input);
    const { docId, aid, text, author, acceptedBy, sugId, via, expectBase } = call;

    const { mode, manifest } = await readApplyManifest(docId);
    const row = manifest.blocks[aid];
    if (row === undefined) throw applyFail("not-found");

    const store = openStore();
    const key = slotKey(docId, aid);
    const snapshot = await strongReceipt(store, key, aid);

    // Completed replay is decided before the effective base and before any
    // provider work, so a resumed acceptance can never be charged twice and
    // never rewrites the accepter that landed first.
    if (via === "suggestion" && snapshot !== null && snapshot.via === "suggestion" &&
        snapshot.sugId === sugId) {
      if (snapshot.aid === aid && snapshot.text === text && sameActor(snapshot.by, author) &&
          snapshot.baseHash === row.hash) {
        return Object.freeze({ receipt: snapshot, pr: snapshot.pr });
      }
      throw applyConflict(
        sha256(toHtmlOf(snapshot.text)), representable(toHtmlOf(snapshot.text)),
      );
    }

    const effective = effectiveBaseOf(mode, docId, aid, manifest, row, snapshot);
    if (expectBase !== effective.hash) throw applyConflict(effective.hash, effective.text);
    const html = toHtmlOf(text);
    if (sha256(html) === expectBase) throw applyFail("invalid-body");

    const auditRow = { aid, section: row.section };
    if (mode === STANDALONE) {
      const nextReceipt = buildReceipt(
        { aid, text, author, acceptedBy, sugId, via, baseHash: row.hash, pr: null },
        sampleTimestamp(),
      );
      const receipt = await writeReceipt(store, key, aid, snapshot, nextReceipt);
      if (via === "edit") {
        await appendAudit(store, docId, manifest, auditRow, author, "edit.apply", "applied");
      }
      return Object.freeze({ receipt, pr: null });
    }

    const { config } = selectMode();
    if (config === null) throw applyFail("invalid-state");
    // The text author must remain the Git commit author. A degraded actor with
    // no mailbox fails safe here, before any branch or provider work: the bot,
    // the accepter, and any request value are all forbidden substitutes.
    if (!isNormalizedEmail(author.email)) throw applyFail("invalid-state");
    const commitAuthor = {
      name: author.name === "" ? author.email : author.name,
      email: author.email,
    };

    const branch = branchFor(docId, author.sub);
    await resolveBranch(config, branch);

    const anchorsPath = `${manifest.instance}/anchors.json`;
    const sectionPath = `${manifest.instance}/${row.file}`;
    const message = via === "suggestion"
      ? `Edit block ${aid} in document ${docId}\n\nAccepted suggestion ${sugId}.\n\n` +
        `${TRAILER_NAME}: ${sugId}`
      : `Edit block ${aid} in document ${docId}`;

    // The branch may legitimately already carry the captured overlay when a
    // different reader is accepting this author's text. Branch transport state
    // is check three; it never redefines the accepted effective base, which
    // `expectBase` above and the receipt compare-and-swap below still protect.
    const allowed = snapshot === null || snapshot.baseHash !== row.hash
      ? [row.hash]
      : [row.hash, effective.hash];

    // Exactly one retry, and only for a GitHub file-SHA race. The second
    // attempt repeats every locator, trailer, and hash check from scratch; a
    // second 409 is the public conflict and nothing here ever loops.
    for (let attempt = 0; ; attempt += 1) {
      const anchors = await readRepositoryFile(config, branch, anchorsPath);
      const source = await readRepositoryFile(config, branch, sectionPath);
      const located = locateBlock(row, aid, anchors.text, source.text);

      if (via === "suggestion" && await headCarriesSuggestion(config, branch, sugId)) {
        // This exact operation already committed at this exact head. Its
        // source must still be the text it wrote; anything else means a later
        // change this bounded probe cannot reason about.
        if (located.inner !== html) {
          throw applyConflict(sha256(located.inner), representable(located.inner));
        }
        break;
      }

      const sourceHash = sha256(located.inner);
      if (!allowed.includes(sourceHash)) {
        throw applyConflict(sourceHash, representable(located.inner));
      }

      const written = await commitSection(
        config, branch, sectionPath, source, located, html, message, commitAuthor,
      );
      if (written.status === 200 || written.status === 201) break;
      if (written.status !== 409) throw applyFail("repository-unavailable");
      if (attempt !== 0) throw applyConflict(sourceHash, representable(located.inner));
    }

    const pr = await ensurePullRequest(config, branch, docId, via);

    // The commit already landed. The receipt is a second, ordered act: a
    // failure here is reported honestly and never claims a rollback.
    const nextReceipt = buildReceipt(
      { aid, text, author, acceptedBy, sugId, via, baseHash: row.hash, pr },
      sampleTimestamp(),
    );
    const receipt = await writeReceipt(store, key, aid, snapshot, nextReceipt);
    if (via === "edit") {
      await appendAudit(store, docId, manifest, auditRow, author, "edit.propose", "proposed");
    }
    return Object.freeze({ receipt, pr });
  }

  const sampleTimestamp = () => {
    let sampled;
    try {
      sampled = deps.nowFn();
    } catch {
      throw applyFail("invalid-state");
    }
    if (!Number.isSafeInteger(sampled)) throw applyFail("invalid-state");
    let at;
    try {
      at = new Date(sampled).toISOString();
    } catch {
      throw applyFail("invalid-state");
    }
    if (!isTimestamp(at)) throw applyFail("invalid-state");
    return at;
  };

  return Object.freeze({
    readApplyManifest,
    readApplyReceipt,
    readEffectiveBase,
    applyText,
  });
}

/** P3-E's exact receipt shapes, built in their exact declared field order. */
function buildReceipt(parts, at) {
  const receipt = {
    v: 1,
    aid: parts.aid,
    text: parts.text,
    by: cloneActor(parts.author),
    at,
    baseHash: parts.baseHash,
    pr: parts.pr,
    via: parts.via,
  };
  if (parts.via !== "suggestion") return receipt;
  receipt.sugId = parts.sugId;
  receipt.acceptedBy = cloneActor(parts.acceptedBy);
  receipt.acceptedAt = at;
  return receipt;
}

/** Two receipts describing the identical suggestion operation, credited to the
 * identical accepter, differing at most in their sampled timestamps. */
function sameSuggestionOperation(a, b) {
  return a.via === "suggestion" && b.via === "suggestion" &&
    a.sugId === b.sugId && a.aid === b.aid && a.text === b.text &&
    a.baseHash === b.baseHash && a.pr === b.pr &&
    sameActor(a.by, b.by) && sameActor(a.acceptedBy, b.acceptedBy);
}

/* -------------------------------------------------------- the one service */

let productionService = null;

/** One production service, created once and reused by every module export. */
function production() {
  if (productionService === null) productionService = createGitEditService();
  return productionService;
}

/**
 * Select the authoritative manifest for a document.
 * @param {string} docId
 * @returns {Promise<{mode: string, manifest: object}>}
 */
export async function readApplyManifest(docId) {
  return production().readApplyManifest(docId);
}

/**
 * Strongly read the one pending receipt for a block, or `null`.
 * @param {string} docId @param {string} aid
 * @returns {Promise<object | null>}
 */
export async function readApplyReceipt(docId, aid) {
  return production().readApplyReceipt(docId, aid);
}

/**
 * The one effective base a write must target.
 * @param {string} docId @param {string} aid
 * @returns {Promise<object>}
 */
export async function readEffectiveBase(docId, aid) {
  return production().readEffectiveBase(docId, aid);
}

/**
 * Apply one text to one block through the one apply path.
 * @param {object} input
 * @returns {Promise<{receipt: object, pr: number | null}>}
 */
export async function applyText(input) {
  return production().applyText(input);
}
