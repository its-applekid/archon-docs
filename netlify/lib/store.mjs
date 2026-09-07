import { getStore } from "@netlify/blobs";

/**
 * P2-B — the site-wide Netlify Blobs store helper.
 *
 * This module is the single storage-boundary library for every later state
 * API. It opens the versioned, site-wide `doc-state` store, defines the
 * version-1 record envelope, and exposes strongly consistent reads plus a
 * bounded optimistic compare-and-swap mutation path so that two requests
 * updating one mutable record re-read and reapply instead of silently
 * overwriting each other (Netlify Blobs is last-write-wins unless a caller
 * supplies a conditional-write guard).
 *
 * Downstream import contract
 * --------------------------
 * - P2-G imports `docState`, `read`, `upgrade`, `assertDocId`, `assertKey`,
 *   and `StoreError`. It reads through `read()`/`upgrade()` and performs only
 *   direct create-only writes guarded by `onlyIfNew`; it owns every `access/`
 *   key builder and all authorization.
 * - P3-A/P3-B/P3-E and P4-B/P4-N/P4-O import the domain key builders here.
 * - Consumers must not duplicate key strings, call `getStore()` directly for
 *   `doc-state`, weaken consistency, use an unguarded `setJSON()` for mutable
 *   state, or add a second CAS loop.
 *
 * Append-only and create-only records do not use `mutate()`. Their owner calls
 * `store.setJSON(key, upgrade(record), { onlyIfNew: true })`, checks the
 * returned `modified` boolean, and treats `modified: false` as a
 * duplicate/collision. A collision is never retried with a different key here;
 * event and suggestion IDs are endpoint-owned, so a collision signals a bug or
 * a replay.
 *
 * Module interface notes
 * ----------------------
 * - Exactly the runtime exports below are public; private helpers (regular
 *   expressions, sleep/random helpers, the JSON-safe validator, segment
 *   validators) are module-local and never exported. There is no default
 *   export.
 * - Tests may pass a duck-typed store with `getWithMetadata()` and `setJSON()`
 *   to `read()` and `mutate()`; production callers pass the `Store` returned
 *   by `docState()`.
 */

/** The one site-wide store name for all document state. */
export const STORE_NAME = "doc-state";

/** Exactly six conditional write attempts are allowed for one mutation. */
export const MAX_MUTATE_ATTEMPTS = 6;

/** Stable, generic error messages. Never embed rejected values, keys, ETags,
 * provider text, tokens, URLs, or actor data in a public message. */
const ERROR_MESSAGES = Object.freeze({
  "invalid-key": "Invalid state key",
  "invalid-record": "Invalid stored record",
  "unsupported-version": "Unsupported stored record version",
  conflict: "Concurrent write limit reached",
  unavailable: "State store unavailable",
});

/** Options passed to every helper read: JSON decoding plus strong consistency.
 * The operation-level option is deliberate defense in depth on top of the
 * store-level strong-consistency selection and makes the behavior observable
 * in a deterministic fake store. */
const READ_OPTIONS = Object.freeze({ type: "json", consistency: "strong" });

const MAX_KEY_BYTES = 600;
const FORBIDDEN_PREFIX = "%2F";

const DOC_ID_PATTERN = /^[0-9a-f]{6}$/;
const THREAD_ID_PATTERN = /^t_[0-9a-z]+_[0-9a-f]{8}$/;
const MONTH_PATTERN = /^\d{4}-(0[1-9]|1[0-2])$/;
const EVENT_ID_PATTERN = /^\d{13}-[0-9a-f]{6}$/;
// Anchor IDs are canonically `a` + 8 hex (P1-D: `"a" + sha1(text)[:8]`). The
// ticket's own executable key fixture uses the 7-hex sample `a3f19c2b`, so
// 7 hex is tolerated as well; the Executor ruled this range must not widen.
const ANCHOR_ID_PATTERN = /^a[0-9a-f]{7,8}$/;
const SUGGESTION_ID_PATTERN = /^s_[0-9a-z]+_[0-9a-f]{8}$/;
const ISO_TIMESTAMP_PATTERN =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

/**
 * The storage helper error. Carries a stable machine-readable `code`, a stable
 * HTTP `status`, and an optional original provider error as `cause`.
 *
 * The module creates only these errors:
 * | code | status | meaning |
 * |---|---|---|
 * | `invalid-key` | 400 | A key or key-builder input violates the key contract. |
 * | `invalid-record` | 500 | Stored/default/next state or a resolved provider envelope is malformed, an ETag is missing, JSON cannot be decoded, or `apply` is not a synchronous record transformation. |
 * | `unsupported-version` | 500 | A stored, default, or callback record has an integer `v` other than 1. |
 * | `conflict` | 409 | All six guarded writes resolved with `modified: false`. |
 * | `unavailable` | 503 | A Blobs write, or a Blobs read for any reason other than a JSON-decoding `SyntaxError`, threw instead of returning a result. |
 *
 * Downstream handlers may use `error.status` but must create their own
 * endpoint-specific response body; they must never serialize a `StoreError`,
 * its `cause`, or its stack.
 */
export class StoreError extends Error {
  /**
   * @param {string} code Stable machine-readable code.
   * @param {number} status Stable HTTP status number.
   * @param {string} message Generic public message.
   * @param {{ cause?: unknown }} [options]
   */
  constructor(code, status, message, { cause } = {}) {
    if (cause !== undefined) {
      super(message, { cause });
    } else {
      super(message);
    }
    this.name = "StoreError";
    this.code = code;
    this.status = status;
  }
}

function storeError(code, { cause } = {}) {
  return new StoreError(code, storeErrorStatus(code), ERROR_MESSAGES[code], {
    cause,
  });
}

function storeErrorStatus(code) {
  switch (code) {
    case "invalid-key":
      return 400;
    case "conflict":
      return 409;
    case "unavailable":
      return 503;
    default:
      return 500;
  }
}

function invalidRecordError() {
  return storeError("invalid-record");
}

/**
 * Open the site-wide `doc-state` store with store-level strong consistency.
 *
 * Accepts no arguments and returns the package `Store`. It must not read a
 * token, site ID, URL, deploy ID, or environment variable itself; Netlify
 * supplies the Blobs execution context to `@netlify/blobs`. It never uses
 * `getDeployStore()` because document state is site-wide and must survive
 * deploys.
 *
 * @returns {ReturnType<typeof getStore>} The package `Store`.
 */
export function docState() {
  return getStore({ name: STORE_NAME, consistency: "strong" });
}

/**
 * Recursive JSON-safe validator.
 *
 * A record is JSON-safe only when every reachable value is `null`, a boolean,
 * a string, a finite number (not `-0`), a dense array with no non-index own
 * keys, or a plain object whose prototype is exactly `Object.prototype` or
 * `null` and whose own properties are enumerable string-keyed data properties.
 *
 * The walk inspects only own descriptors — it never invokes a getter — and
 * rejects a second visit to the same object, which makes sparse/extended
 * arrays, `undefined`, `NaN`, infinities, `-0`, bigint, symbols, functions,
 * dates, maps, sets, typed arrays, class instances, accessors,
 * non-enumerable properties, symbol keys, cycles, and shared/cyclic identity
 * all invalid.
 *
 * @param {unknown} value
 * @param {Set<object>} seen
 * @returns {boolean}
 */
function isJsonSafe(value, seen) {
  if (value === null) {
    return true;
  }
  const type = typeof value;
  if (type === "boolean" || type === "string") {
    return true;
  }
  if (type === "number") {
    return Number.isFinite(value) && !Object.is(value, -0);
  }
  if (type !== "object") {
    return false;
  }
  if (seen.has(value)) {
    return false;
  }
  seen.add(value);
  if (Array.isArray(value)) {
    return isDenseArray(value, seen);
  }
  const proto = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null) {
    return false;
  }
  return hasOnlyDataProperties(value, seen);
}

/** @param {unknown} name @returns {boolean} */
function isArrayIndexName(name) {
  if (typeof name !== "string") {
    return false;
  }
  if (name === "") {
    return false;
  }
  if (String(Number(name)) !== name) {
    return false;
  }
  const index = Number(name);
  return Number.isInteger(index) && index >= 0;
}

/**
 * A dense array with no non-index own keys. `length` is inherent and ignored;
 * every index `0..length - 1` must exist as an own enumerable data property
 * (a hole has no own key, so fewer than `length` index keys means a sparse
 * array), and any other own string or symbol key, accessor, non-enumerable
 * element, or index at or beyond `length` makes the array invalid. Each
 * element value is validated exactly once.
 *
 * @param {unknown[]} array
 * @param {Set<object>} seen
 * @returns {boolean}
 */
function isDenseArray(array, seen) {
  const length = array.length;
  if (Object.getOwnPropertySymbols(array).length !== 0) {
    return false;
  }
  let indexKeyCount = 0;
  for (const name of Object.getOwnPropertyNames(array)) {
    if (name === "length") {
      continue;
    }
    if (!isArrayIndexName(name) || Number(name) >= length) {
      return false;
    }
    const descriptor = Object.getOwnPropertyDescriptor(array, name);
    if (
      descriptor === undefined ||
      !Object.prototype.hasOwnProperty.call(descriptor, "value") ||
      descriptor.enumerable !== true ||
      !isJsonSafe(descriptor.value, seen)
    ) {
      return false;
    }
    indexKeyCount += 1;
  }
  return indexKeyCount === length;
}

/**
 * A plain object whose own properties are enumerable string-keyed data
 * properties. Symbol keys, non-enumerable properties, and accessors are
 * rejected. Values are validated recursively without invoking any getter.
 *
 * @param {object} object
 * @param {Set<object>} seen
 * @returns {boolean}
 */
function hasOnlyDataProperties(object, seen) {
  if (Object.getOwnPropertySymbols(object).length !== 0) {
    return false;
  }
  for (const name of Object.getOwnPropertyNames(object)) {
    const descriptor = Object.getOwnPropertyDescriptor(object, name);
    if (
      descriptor === undefined ||
      !Object.prototype.hasOwnProperty.call(descriptor, "value") ||
      descriptor.enumerable !== true ||
      !isJsonSafe(descriptor.value, seen)
    ) {
      return false;
    }
  }
  return true;
}

/**
 * The one record-version gate.
 *
 * Rejects `null`, arrays, primitives, objects without their own `v`,
 * non-integer versions, or any value that fails the complete recursive
 * JSON-safe contract with code `invalid-record`; rejects every other integer
 * version with code `unsupported-version`; and returns a valid version-1
 * object unchanged (preserving an accepted null prototype).
 *
 * No version is inferred for an unversioned object: no legacy production state
 * exists, so a silent default would hide corruption. Future schema work adds a
 * branch here and nowhere else.
 *
 * @param {unknown} value
 * @returns {object} The validated version-1 record (the same reference).
 */
export function upgrade(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw invalidRecordError();
  }
  const proto = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null) {
    throw invalidRecordError();
  }
  if (!hasOnlyDataProperties(value, new Set())) {
    throw invalidRecordError();
  }
  const versionDescriptor = Object.getOwnPropertyDescriptor(value, "v");
  if (
    versionDescriptor === undefined ||
    typeof versionDescriptor.value !== "number" ||
    !Number.isInteger(versionDescriptor.value)
  ) {
    throw invalidRecordError();
  }
  if (versionDescriptor.value === 1) {
    return value;
  }
  throw storeError("unsupported-version");
}

/**
 * Validate a storage key.
 *
 * Returns the same string or throws `invalid-key`. A key must be a string
 * whose UTF-8 encoding is 1 through 600 bytes, must not start with `/`, and
 * must not start with the literal, case-sensitive encoded-slash prefix `%2F`.
 * Embedded `/` is deliberately permitted because the ruling layout uses
 * path-like prefixes; this is not a substitute for segment validation.
 *
 * @param {string} key
 * @returns {string} The same key.
 */
export function assertKey(key) {
  if (typeof key !== "string") {
    throw storeError("invalid-key");
  }
  const byteLength = Buffer.byteLength(key, "utf8");
  if (
    byteLength < 1 ||
    byteLength > MAX_KEY_BYTES ||
    key.startsWith("/") ||
    key.startsWith(FORBIDDEN_PREFIX)
  ) {
    throw storeError("invalid-key");
  }
  return key;
}

/**
 * Validate a permanent document ID.
 *
 * Returns the same string or throws `invalid-key`. Requires `^[0-9a-f]{6}$`
 * (the permanent ID contract from P1-A). Never trims, lowercases, or accepts
 * a slug.
 *
 * @param {string} docId
 * @returns {string} The same document ID.
 */
export function assertDocId(docId) {
  if (typeof docId !== "string" || !DOC_ID_PATTERN.test(docId)) {
    throw storeError("invalid-key");
  }
  return docId;
}

/**
 * Read one record under a key with strong consistency.
 *
 * Resolves with exactly `{ value, etag }`. On a hit, `value` is the result of
 * `upgrade(found.data)` and `etag` is the non-empty ETag string returned by
 * Blobs. On a miss, `value` is `structuredClone(initial)` after validation
 * (or `null` when `initial` is omitted/`null`) and `etag` is `null`. The clone
 * prevents a caller from mutating a shared default object after a miss.
 *
 * A hit without a non-empty string ETag, a malformed resolved provider shape,
 * or a JSON-decoding `SyntaxError` is `invalid-record`; any other provider
 * failure is `unavailable` with the original error preserved only as `cause`.
 * A read or a no-op mutation never performs an unsolicited migration write.
 *
 * @param {{ getWithMetadata(key: string, options: object): Promise<unknown> }} store
 * @param {string} key
 * @param {unknown} [initial]
 * @returns {Promise<{ value: object | null, etag: string | null }>}
 */
export async function read(store, key, initial = null) {
  assertKey(key);
  if (initial !== null) {
    upgrade(initial);
  }
  let found;
  try {
    found = await store.getWithMetadata(key, READ_OPTIONS);
  } catch (error) {
    if (error instanceof SyntaxError) {
      throw storeError("invalid-record", { cause: error });
    }
    throw storeError("unavailable", { cause: error });
  }
  if (found === null) {
    if (initial === null) {
      return { value: null, etag: null };
    }
    return { value: structuredClone(initial), etag: null };
  }
  if (
    typeof found !== "object" ||
    Array.isArray(found) ||
    !Object.prototype.hasOwnProperty.call(found, "data")
  ) {
    throw invalidRecordError();
  }
  const value = upgrade(found.data);
  const { etag } = found;
  if (typeof etag !== "string" || etag.length === 0) {
    throw invalidRecordError();
  }
  return { value, etag };
}

/**
 * Whether `value` looks like a thenable without invoking a `then` getter.
 * Inspects only descriptors: a callable data `then` or an accessor `then` is
 * treated as thenable (an accessor cannot be proved synchronous without
 * running it). A data `then` that is not callable is not a thenable.
 *
 * @param {object} value
 * @returns {boolean}
 */
function isThenable(value) {
  for (let object = value; object !== null; object = Object.getPrototypeOf(object)) {
    const descriptor = Object.getOwnPropertyDescriptor(object, "then");
    if (descriptor === undefined) {
      continue;
    }
    if (typeof descriptor.value === "function") {
      return true;
    }
    if (
      !Object.prototype.hasOwnProperty.call(descriptor, "value") ||
      descriptor.get !== undefined ||
      descriptor.set !== undefined
    ) {
      return true;
    }
    return false;
  }
  return false;
}

/**
 * The bounded retry backoff: `20 * 2 ** attemptIndex + Math.random() * 40`
 * milliseconds. Base delays are 20, 40, 80, 160, and 320 ms for attempts 0..4,
 * each plus jitter in `[0, 40)`. There is no wait after the final attempt.
 *
 * @param {number} attemptIndex
 * @returns {number}
 */
function backoffMilliseconds(attemptIndex) {
  return 20 * 2 ** attemptIndex + Math.random() * 40;
}

/**
 * @param {number} milliseconds
 * @returns {Promise<void>}
 */
function sleep(milliseconds) {
  return new Promise((resolve) => {
    globalThis.setTimeout(resolve, milliseconds);
  });
}

/**
 * Optimistically mutate one mutable record with compare-and-swap.
 *
 * `apply` receives a fresh `structuredClone` on every attempt and must be a
 * pure, repeatable synchronous transformation of its draft plus immutable
 * request-scoped values:
 *
 * - Generate IDs, actor snapshots, and timestamps once before calling
 *   `mutate()` and capture them in the callback.
 * - Do not perform network calls, event writes, notifications, logging with
 *   side effects, random generation, or clock reads inside `apply`.
 * - Write an audit event only after the mutation succeeds. A thread write and
 *   its event are two ordered acts; there is no cross-blob transaction. A
 *   process crash after the state write but before an event write may omit the
 *   event, but it must not lose or duplicate the state mutation within the CAS
 *   loop.
 *
 * Retry/idempotency boundary: `apply` may run up to six times for one
 * `mutate()` call. The algorithm retries only a resolved conditional write
 * with `modified: false` (proof no write occurred); it never retries a thrown
 * provider error or a successful write with a missing ETag, either of which is
 * ambiguous. `mutate()` provides concurrency safety for one invocation, not
 * request replay idempotency — an endpoint that needs replay protection must
 * own an idempotency key (P4-N later owns the `X-Suggestion-Id` contract).
 *
 * Algorithm per attempt: read the current record; pass `structuredClone` of
 * the value to `apply`; on `null` return the current no-op envelope; on a
 * missing key write with `{ onlyIfNew: true }`, otherwise write with
 * `{ onlyIfMatch: etag }` using the opaque ETag unchanged (including quotes or
 * a weakness prefix). `modified: true` requires a non-empty ETag and returns
 * the success envelope; `modified: false` re-reads and reapplies after the
 * bounded backoff, and after six consecutive conditional rejections throws the
 * 409 `conflict` error immediately (no terminal sleep).
 *
 * Resolves with exactly `{ value, etag, changed }`. On a successful
 * conditional write, `value` is the validated value that was written, `etag`
 * is its new non-empty ETag, and `changed` is `true`. On a callback no-op,
 * `value` is the current upgraded value, `etag` is its current ETag or `null`,
 * and `changed` is `false`. No result exposes Blobs metadata or a raw provider
 * response.
 *
 * An error thrown by `apply` is preserved and rethrown exactly; domain
 * validation and not-found decisions belong to the caller. The callback may
 * return `null` for no change but must not return a Promise or thenable.
 *
 * @param {{ getWithMetadata(key: string, options: object): Promise<unknown>,
 *          setJSON(key: string, value: object, options: object): Promise<unknown> }} store
 * @param {string} key
 * @param {object | null} initial Non-null default record used when the key is absent.
 * @param {(draft: object | null) => object | null} apply Synchronous pure transformation.
 * @returns {Promise<{ value: object | null, etag: string | null, changed: boolean }>}
 */
export async function mutate(store, key, initial, apply) {
  assertKey(key);
  if (typeof apply !== "function") {
    throw invalidRecordError();
  }
  if (initial !== null) {
    upgrade(initial);
  }

  for (let attempt = 0; attempt < MAX_MUTATE_ATTEMPTS; attempt += 1) {
    const current = await read(store, key, initial);
    const draft = structuredClone(current.value);
    const next = apply(draft);

    if (next === null) {
      return { value: current.value, etag: current.etag, changed: false };
    }

    if (
      (typeof next === "object" && isThenable(next)) ||
      typeof next === "function"
    ) {
      throw invalidRecordError();
    }
    const record = upgrade(next);

    let result;
    const writeOptions =
      current.etag === null ? { onlyIfNew: true } : { onlyIfMatch: current.etag };
    try {
      result = await store.setJSON(key, record, writeOptions);
    } catch (error) {
      throw storeError("unavailable", { cause: error });
    }

    if (
      result === null ||
      typeof result !== "object" ||
      Array.isArray(result)
    ) {
      throw invalidRecordError();
    }
    const modifiedDescriptor = Object.getOwnPropertyDescriptor(result, "modified");
    if (
      modifiedDescriptor === undefined ||
      !Object.prototype.hasOwnProperty.call(modifiedDescriptor, "value")
    ) {
      throw invalidRecordError();
    }
    if (typeof result.modified !== "boolean") {
      throw invalidRecordError();
    }
    if (result.modified === true) {
      if (typeof result.etag !== "string" || result.etag.length === 0) {
        throw invalidRecordError();
      }
      return { value: record, etag: result.etag, changed: true };
    }

    if (attempt === MAX_MUTATE_ATTEMPTS - 1) {
      throw storeError("conflict");
    }
    await sleep(backoffMilliseconds(attempt));
  }
  throw storeError("conflict");
}

/**
 * Thread prefix for a document: `threads/<docId>/`.
 * @param {string} docId @returns {string}
 */
export function threadPrefix(docId) {
  return assertKey(`threads/${assertDocId(docId)}/`);
}

/**
 * Thread record key for a document and thread:
 * `threads/<docId>/<threadId>.json`.
 * @param {string} docId @param {string} threadId @returns {string}
 */
export function threadKey(docId, threadId) {
  assertDocId(docId);
  if (typeof threadId !== "string" || !THREAD_ID_PATTERN.test(threadId)) {
    throw storeError("invalid-key");
  }
  return assertKey(`threads/${docId}/${threadId}.json`);
}

/**
 * Event prefix for a document, or for one month when `month` is supplied:
 * `events/<docId>/` or `events/<docId>/<month>/`.
 * @param {string} docId @param {string} [month] @returns {string}
 */
export function eventPrefix(docId, month) {
  const base = `events/${assertDocId(docId)}/`;
  if (month === undefined) {
    return assertKey(base);
  }
  if (typeof month !== "string" || !MONTH_PATTERN.test(month)) {
    throw storeError("invalid-key");
  }
  return assertKey(`${base}${month}/`);
}

/**
 * Event record key: `events/<docId>/<YYYY-MM>/<eventId>.json`. The timestamp
 * must be an exact UTC ISO timestamp with milliseconds whose `YYYY-MM`
 * chooses the month segment, and the event ID's millisecond prefix must equal
 * `Date.parse(timestamp)` so a record body never sorts into the wrong
 * month/key chronology.
 * @param {string} docId @param {string} timestamp @param {string} eventId @returns {string}
 */
export function eventKey(docId, timestamp, eventId) {
  assertDocId(docId);
  if (
    typeof timestamp !== "string" ||
    !ISO_TIMESTAMP_PATTERN.test(timestamp) ||
    new Date(timestamp).toISOString() !== timestamp
  ) {
    throw storeError("invalid-key");
  }
  if (typeof eventId !== "string" || !EVENT_ID_PATTERN.test(eventId)) {
    throw storeError("invalid-key");
  }
  if (eventId.slice(0, 13) !== String(Date.parse(timestamp))) {
    throw storeError("invalid-key");
  }
  const month = timestamp.slice(0, 7);
  return assertKey(`events/${docId}/${month}/${eventId}.json`);
}

/**
 * Edit prefix for a document: `edits/<docId>/`.
 * @param {string} docId @returns {string}
 */
export function editPrefix(docId) {
  return assertKey(`edits/${assertDocId(docId)}/`);
}

/**
 * Edit record key: `edits/<docId>/<anchorId>.json`.
 * @param {string} docId @param {string} aid @returns {string}
 */
export function editKey(docId, aid) {
  assertDocId(docId);
  if (typeof aid !== "string" || !ANCHOR_ID_PATTERN.test(aid)) {
    throw storeError("invalid-key");
  }
  return assertKey(`edits/${docId}/${aid}.json`);
}

/**
 * Suggestion prefix for a document, or for one anchor when `aid` is supplied:
 * `suggest/<docId>/` or `suggest/<docId>/<aid>/`.
 * @param {string} docId @param {string} [aid] @returns {string}
 */
export function suggestionPrefix(docId, aid) {
  const base = `suggest/${assertDocId(docId)}/`;
  if (aid === undefined) {
    return assertKey(base);
  }
  if (typeof aid !== "string" || !ANCHOR_ID_PATTERN.test(aid)) {
    throw storeError("invalid-key");
  }
  return assertKey(`${base}${aid}/`);
}

/**
 * Suggestion record key:
 * `suggest/<docId>/<aid>/<suggestionId>.json`.
 * @param {string} docId @param {string} aid @param {string} suggestionId @returns {string}
 */
export function suggestionKey(docId, aid, suggestionId) {
  assertDocId(docId);
  if (typeof aid !== "string" || !ANCHOR_ID_PATTERN.test(aid)) {
    throw storeError("invalid-key");
  }
  if (
    typeof suggestionId !== "string" ||
    !SUGGESTION_ID_PATTERN.test(suggestionId)
  ) {
    throw storeError("invalid-key");
  }
  return assertKey(`suggest/${docId}/${aid}/${suggestionId}.json`);
}
