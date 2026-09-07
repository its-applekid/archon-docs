import { identify, requireOrigin } from "../lib/identity.mjs";
import {
  resolveRole,
  capabilitiesFor,
  normalizeEmail,
  assertIdentitySub,
  validateAccessRow,
  AccessError,
} from "../lib/access.mjs";
import {
  docState,
  eventPrefix,
  eventKey,
  upgrade,
  assertDocId,
  StoreError,
} from "../lib/store.mjs";
import { randomBytes } from "node:crypto";

/**
 * P3-B — the events API.
 *
 * `POST /api/events?doc=<docId>` appends one actor-attributed, append-only
 * audit event as one immutable blob under
 * `events/<docId>/<YYYY-MM>/<eventId>.json`, written with `onlyIfNew` so a
 * generated-ID collision can never overwrite an existing fact.
 * `GET /api/events?doc=<docId>&month=<YYYY-MM>` returns one deterministic,
 * bounded page of one document/month prefix with an exclusive event-ID
 * cursor.
 *
 * Events are audit evidence, never feature state. Authoritative feature
 * handlers mutate their own record first and call `appendEvent()` second;
 * they never roll state back because the append failed.
 *
 * The module has no clock, randomness, network, environment, or logging
 * side effect outside the injected dependency seam, and it never places
 * identity or event fields in Blob metadata.
 */

/** The closed, ordered set of audit event kinds. */
export const EVENT_KINDS = Object.freeze([
  "comment.create",
  "comment.reply",
  "comment.edit",
  "thread.resolve",
  "thread.reopen",
  "edit.propose",
  "suggest.create",
  "suggest.accept",
  "suggest.reject",
  "suggest.withdraw",
  "suggest.supersede",
  "edit.apply",
  "access.invite",
  "access.change",
  "access.revoke",
  "access.transfer",
]);

export const config = { path: "/api/events" };

const JSON_HEADERS = Object.freeze({
  "Content-Type": "application/json; charset=utf-8",
  "Cache-Control": "private, no-store",
});

const MAX_BODY_BYTES = 8192;
const MAX_LIST_PAGES = 10;
const MAX_PAGE_ENTRIES = 1000;
const MAX_LIST_KEYS = 10000;
const MAX_LISTED_KEY_BYTES = 96;
const MIN_NOW_MS = 1000000000000;
const MAX_NOW_MS = 9999999999999;
const DEFAULT_LIMIT = 50;

const EVENT_ID_PATTERN = /^[0-9]{13}-[0-9a-f]{6}$/;
const TIMESTAMP_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const MONTH_PATTERN = /^[0-9]{4}-(0[1-9]|1[0-2])$/;
const LIMIT_PATTERN = /^(?:[1-9][0-9]?|100)$/;
const DOC_VERSION_PATTERN = /^[0-9a-f]{7,64}$/;
const ANCHOR_ID_PATTERN = /^a[0-9a-f]{8}$/;
const THREAD_ID_PATTERN = /^t_[a-z0-9]{1,48}_[0-9a-f]{8}$/;
const COMMENT_ID_PATTERN = /^c_[a-z0-9]{1,48}_[0-9a-f]{8}$/;
const SUGGESTION_ID_PATTERN = /^s_[a-z0-9]{1,48}_[0-9a-f]{8}$/;
const CONTROL_PATTERN = /[\u0000-\u001f\u007f-\u009f]/;
const SUMMARY_BARRED_PATTERN = /[@<>]/;

const EVENT_FIELDS = Object.freeze([
  "v",
  "id",
  "docId",
  "ts",
  "actor",
  "kind",
  "target",
  "docVersion",
  "summary",
]);
const ACTOR_FIELDS = Object.freeze(["sub", "name", "email"]);
const BODY_FIELDS = Object.freeze(["kind", "target", "docVersion", "summary"]);
const INPUT_FIELDS = Object.freeze([
  "store",
  "docId",
  "actor",
  "kind",
  "target",
  "docVersion",
  "summary",
]);
const OPTION_FIELDS = Object.freeze(["nowMs", "randomBytesFn"]);
const DEPENDENCY_FIELDS = Object.freeze([
  "requireOriginFn",
  "identifyFn",
  "resolveRoleFn",
  "storeFn",
  "nowFn",
  "randomBytesFn",
]);
const IDENTITY_FIELDS = Object.freeze(["sub", "email", "name", "isOrg"]);
const ACCESS_BOOLEAN_FIELDS = Object.freeze([
  "shared",
  "canRead",
  "canComment",
  "canSuggest",
  "canEdit",
  "canAccept",
  "canShare",
  "canSeeMembers",
]);

/** Exact target key lists by kind, in documented order. */
const TARGET_KEYS = Object.freeze({
  "comment.create": Object.freeze(["threadId", "aid"]),
  "comment.reply": Object.freeze(["threadId", "commentId", "aid"]),
  "comment.edit": Object.freeze(["threadId", "commentId", "aid"]),
  "thread.resolve": Object.freeze(["threadId", "aid"]),
  "thread.reopen": Object.freeze(["threadId", "aid"]),
  "edit.propose": Object.freeze(["aid"]),
  "suggest.create": Object.freeze(["suggestionId", "aid"]),
  "suggest.accept": Object.freeze(["suggestionId", "aid"]),
  "suggest.reject": Object.freeze(["suggestionId", "aid"]),
  "suggest.withdraw": Object.freeze(["suggestionId", "aid"]),
  "suggest.supersede": Object.freeze(["suggestionId", "aid"]),
  "edit.apply": Object.freeze(["aid"]),
  "access.transfer": Object.freeze(["fromSub", "toSub"]),
});
const ACCESS_IDENTIFIER_KINDS = Object.freeze([
  "access.invite",
  "access.change",
  "access.revoke",
]);

/** The resolved capability each kind requires on the generic endpoint. */
const KIND_CAPABILITY = Object.freeze({
  "comment.create": Object.freeze(["canComment", true]),
  "comment.reply": Object.freeze(["canComment", true]),
  "comment.edit": Object.freeze(["canComment", true]),
  "thread.resolve": Object.freeze(["threadControl", "any"]),
  "thread.reopen": Object.freeze(["threadControl", "any"]),
  "edit.propose": Object.freeze(["canSuggest", true]),
  "suggest.create": Object.freeze(["canSuggest", true]),
  "suggest.withdraw": Object.freeze(["canSuggest", true]),
  "suggest.supersede": Object.freeze(["canSuggest", true]),
  "suggest.accept": Object.freeze(["canAccept", true]),
  "suggest.reject": Object.freeze(["canAccept", true]),
  "edit.apply": Object.freeze(["canEdit", true]),
  "access.invite": Object.freeze(["canShare", true]),
  "access.change": Object.freeze(["canShare", true]),
  "access.revoke": Object.freeze(["canShare", true]),
  "access.transfer": Object.freeze(["canShare", true]),
});

/** A private validation failure. Never serialized; it selects a status only. */
class EventValidationError extends Error {
  constructor(message) {
    super(message);
    this.name = "EventValidationError";
  }
}

function invalid(message) {
  return new EventValidationError(message);
}

function utf8Length(value) {
  return new TextEncoder().encode(value).length;
}

/**
 * Own string keys of an ordinary object whose every own property is an
 * enumerable, writable, configurable data property. Throws otherwise.
 * Inspects descriptors only; never invokes a getter or a proxy get trap.
 */
function ownDataKeys(value, message) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw invalid(message);
  }
  if (Object.getPrototypeOf(value) !== Object.prototype) {
    throw invalid(message);
  }
  if (Object.getOwnPropertySymbols(value).length !== 0) {
    throw invalid(message);
  }
  const names = Object.getOwnPropertyNames(value);
  for (const name of names) {
    const descriptor = Object.getOwnPropertyDescriptor(value, name);
    if (
      descriptor === undefined ||
      !Object.prototype.hasOwnProperty.call(descriptor, "value") ||
      descriptor.enumerable !== true ||
      descriptor.writable !== true ||
      descriptor.configurable !== true
    ) {
      throw invalid(message);
    }
  }
  return names;
}

/** Assert an exact object whose own keys are exactly `keys` (any order). */
function assertExactKeys(value, keys, message) {
  const names = ownDataKeys(value, message);
  if (names.length !== keys.length) {
    throw invalid(message);
  }
  for (const key of keys) {
    if (!names.includes(key)) {
      throw invalid(message);
    }
  }
  return value;
}

/** Assert an exact object whose own keys are exactly `keys` in that order. */
function assertOrderedKeys(value, keys, message) {
  const names = ownDataKeys(value, message);
  if (names.length !== keys.length) {
    throw invalid(message);
  }
  for (let index = 0; index < keys.length; index += 1) {
    if (names[index] !== keys[index]) {
      throw invalid(message);
    }
  }
  return value;
}

/** Assert an exact object whose own keys are a subset of `keys`. */
function assertSubsetKeys(value, keys, message) {
  const names = ownDataKeys(value, message);
  for (const name of names) {
    if (!keys.includes(name)) {
      throw invalid(message);
    }
  }
  return names;
}

/** A well-formed string with no lone surrogate or C0/C1 control character. */
function assertCleanString(value, message) {
  if (typeof value !== "string" || !value.isWellFormed()) {
    throw invalid(message);
  }
  if (CONTROL_PATTERN.test(value)) {
    throw invalid(message);
  }
  return value;
}

function assertPattern(value, pattern, message) {
  assertCleanString(value, message);
  if (!pattern.test(value)) {
    throw invalid(message);
  }
  return value;
}

function assertEventId(value) {
  return assertPattern(value, EVENT_ID_PATTERN, "invalid event id");
}

function assertTimestamp(value) {
  assertPattern(value, TIMESTAMP_PATTERN, "invalid timestamp");
  const parsed = Date.parse(value);
  if (!Number.isSafeInteger(parsed) || new Date(parsed).toISOString() !== value) {
    throw invalid("invalid timestamp");
  }
  return value;
}

function assertKind(value) {
  if (typeof value !== "string" || !EVENT_KINDS.includes(value)) {
    throw invalid("invalid kind");
  }
  return value;
}

function assertSub(value) {
  assertCleanString(value, "invalid subject");
  return assertIdentitySub(value);
}

/** A non-empty, already-normalized email in P2-G's accepted domain. */
function assertNormalizedEmail(value) {
  assertCleanString(value, "invalid email");
  if (value.length === 0 || utf8Length(value) > 320) {
    throw invalid("invalid email");
  }
  if (normalizeEmail(value) !== value) {
    throw invalid("invalid email");
  }
  return value;
}

function assertActor(value) {
  assertExactKeys(value, ACTOR_FIELDS, "invalid actor");
  const sub = assertSub(value.sub);
  const name = value.name;
  if (typeof name !== "string" || name.length > 200) {
    throw invalid("invalid actor name");
  }
  const email = value.email === "" ? "" : assertNormalizedEmail(value.email);
  if (sub === "system" && (name !== "Build" || email !== "")) {
    throw invalid("invalid system actor");
  }
  return { sub, name, email };
}

function assertAid(value) {
  if (value === null) {
    return null;
  }
  return assertPattern(value, ANCHOR_ID_PATTERN, "invalid anchor id");
}

function assertTargetField(name, value) {
  switch (name) {
    case "aid":
      return assertAid(value);
    case "threadId":
      return assertPattern(value, THREAD_ID_PATTERN, "invalid thread id");
    case "commentId":
      return assertPattern(value, COMMENT_ID_PATTERN, "invalid comment id");
    case "suggestionId":
      return assertPattern(
        value,
        SUGGESTION_ID_PATTERN,
        "invalid suggestion id",
      );
    case "sub":
    case "fromSub":
    case "toSub":
      return assertSub(value);
    case "email":
      return assertNormalizedEmail(value);
    default:
      throw invalid("invalid target");
  }
}

/** Validate and clone the exact kind-specific target in documented order. */
function assertTarget(kind, value) {
  let keys;
  if (ACCESS_IDENTIFIER_KINDS.includes(kind)) {
    const names = assertSubsetKeys(value, ["email", "sub"], "invalid target");
    if (names.length !== 1) {
      throw invalid("invalid target");
    }
    keys = names;
  } else {
    keys = TARGET_KEYS[kind];
    assertExactKeys(value, keys, "invalid target");
  }
  const target = {};
  for (const key of keys) {
    target[key] = assertTargetField(key, value[key]);
  }
  if (kind === "access.transfer" && target.fromSub === target.toSub) {
    throw invalid("invalid target");
  }
  return target;
}

function assertDocVersion(kind, value) {
  if (kind.startsWith("access.")) {
    if (value !== null) {
      throw invalid("invalid document version");
    }
    return null;
  }
  return assertPattern(value, DOC_VERSION_PATTERN, "invalid document version");
}

function assertSummary(value) {
  assertCleanString(value, "invalid summary");
  if (value.trim() !== value || SUMMARY_BARRED_PATTERN.test(value)) {
    throw invalid("invalid summary");
  }
  const bytes = utf8Length(value);
  if (bytes < 1 || bytes > 160) {
    throw invalid("invalid summary");
  }
  return value;
}

/**
 * Validate the caller-supplied event fields shared by the POST body and
 * `appendEvent()` input: `kind`, `target`, `docVersion`, and `summary`.
 * Returns fresh validated values.
 */
function assertEventFacts(kind, target, docVersion, summary) {
  const validKind = assertKind(kind);
  return {
    kind: validKind,
    target: assertTarget(validKind, target),
    docVersion: assertDocVersion(validKind, docVersion),
    summary: assertSummary(summary),
  };
}

/**
 * Validate one complete version-1 event against its exact storage key.
 *
 * Calls P2-B `upgrade()` first, then validates and clones the complete
 * schema. `expectedKey` is mandatory and must equal
 * `eventKey(event.docId, event.ts, event.id)`. Any mismatch, unknown field
 * or kind, malformed actor/target, or invalid string throws; nothing is
 * repaired, skipped, or partially returned. The function has no clock,
 * randomness, network, store, identity, logging, or mutation side effect.
 *
 * @param {unknown} value
 * @param {string} expectedKey
 * @returns {object} A fresh validated event in documented field order.
 */
export function assertEvent(value, expectedKey) {
  if (typeof expectedKey !== "string") {
    throw invalid("invalid expected key");
  }
  upgrade(value);
  assertOrderedKeys(value, EVENT_FIELDS, "invalid event");
  if (value.v !== 1) {
    throw invalid("invalid event version");
  }
  const id = assertEventId(value.id);
  const docId = assertDocId(assertCleanString(value.docId, "invalid doc id"));
  const ts = assertTimestamp(value.ts);
  if (id.slice(0, 13) !== String(Date.parse(ts))) {
    throw invalid("invalid event id");
  }
  const actor = assertActor(value.actor);
  const facts = assertEventFacts(
    value.kind,
    value.target,
    value.docVersion,
    value.summary,
  );
  if (eventKey(docId, ts, id) !== expectedKey) {
    throw invalid("event key mismatch");
  }
  return {
    v: 1,
    id,
    docId,
    ts,
    actor,
    kind: facts.kind,
    target: facts.target,
    docVersion: facts.docVersion,
    summary: facts.summary,
  };
}

function assertNowMs(value) {
  if (
    !Number.isSafeInteger(value) ||
    value < MIN_NOW_MS ||
    value > MAX_NOW_MS
  ) {
    throw invalid("invalid time");
  }
  return value;
}

function hexOfThreeBytes(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length !== 3) {
    throw invalid("invalid random bytes");
  }
  let hex = "";
  for (const byte of bytes) {
    hex += byte.toString(16).padStart(2, "0");
  }
  return hex;
}

function unavailable(cause) {
  return new StoreError("unavailable", 503, "State store unavailable", {
    cause,
  });
}

/**
 * Whether a resolved provider envelope carries an own data `modified`
 * boolean. Reads descriptors only; a getter is never executed.
 */
function modifiedOf(result) {
  if (result === null || typeof result !== "object" || Array.isArray(result)) {
    return null;
  }
  const descriptor = Object.getOwnPropertyDescriptor(result, "modified");
  if (
    descriptor === undefined ||
    !Object.prototype.hasOwnProperty.call(descriptor, "value") ||
    typeof descriptor.value !== "boolean"
  ) {
    return null;
  }
  return descriptor.value;
}

/**
 * Append one audit event with a create-only write.
 *
 * `input` is an exact object with keys `store`, `docId`, `actor`, `kind`,
 * `target`, `docVersion`, and `summary`. `options` is an exact object with
 * optional keys `nowMs` and `randomBytesFn`. Every caller-supplied value is
 * validated before time or randomness is read and before the store is
 * touched. The ID is `<nowMs>-<six hex>` from exactly one `randomBytesFn(3)`
 * call, the key comes only from P2-B `eventKey()`, and the one `setJSON`
 * call uses `{ onlyIfNew: true }`. `modified: false` throws the P2-B
 * `conflict` error and is never retried; a thrown or ambiguous provider
 * result becomes the P2-B `unavailable` error.
 *
 * The helper does not authorize. A domain handler authorizes and commits its
 * own state before calling it, and never rolls state back on failure.
 *
 * @param {{ store: object, docId: string, actor: object, kind: string,
 *          target: object, docVersion: string | null, summary: string }} input
 * @param {{ nowMs?: number, randomBytesFn?: (size: number) => Uint8Array }} [options]
 * @returns {Promise<object>} A fresh validated event.
 */
export async function appendEvent(input, options = {}) {
  assertExactKeys(input, INPUT_FIELDS, "invalid append input");
  const optionNames = assertSubsetKeys(
    options,
    OPTION_FIELDS,
    "invalid append options",
  );
  const store = input.store;
  if (store === null || typeof store !== "object") {
    throw invalid("invalid store");
  }
  const docId = assertDocId(assertCleanString(input.docId, "invalid doc id"));
  const actor = assertActor(input.actor);
  const facts = assertEventFacts(
    input.kind,
    input.target,
    input.docVersion,
    input.summary,
  );
  let randomBytesFn = randomBytes;
  if (optionNames.includes("randomBytesFn")) {
    if (typeof options.randomBytesFn !== "function") {
      throw invalid("invalid append options");
    }
    randomBytesFn = options.randomBytesFn;
  }
  let nowMs;
  if (optionNames.includes("nowMs")) {
    nowMs = assertNowMs(options.nowMs);
  } else {
    nowMs = assertNowMs(Date.now());
  }
  const ts = new Date(nowMs).toISOString();
  const hex = hexOfThreeBytes(randomBytesFn(3));
  const id = `${String(nowMs)}-${hex}`;
  const event = {
    v: 1,
    id,
    docId,
    ts,
    actor,
    kind: facts.kind,
    target: facts.target,
    docVersion: facts.docVersion,
    summary: facts.summary,
  };
  const key = eventKey(docId, ts, id);
  const validated = assertEvent(event, key);

  let result;
  try {
    result = await store.setJSON(key, validated, { onlyIfNew: true });
  } catch (error) {
    throw unavailable(error);
  }
  const modified = modifiedOf(result);
  if (modified === null) {
    throw unavailable(undefined);
  }
  if (modified === false) {
    throw new StoreError("conflict", 409, "Concurrent write limit reached");
  }
  return assertEvent(validated, key);
}

function jsonResponse(status, body, extraHeaders) {
  const headers = { ...JSON_HEADERS };
  if (extraHeaders !== undefined) {
    Object.assign(headers, extraHeaders);
  }
  return new Response(JSON.stringify(body), { status, headers });
}

function errorResponse(status, code, extraHeaders) {
  return jsonResponse(status, { error: code }, extraHeaders);
}

/** Map a thrown value to a generic public status using descriptors only. */
function classifyError(error) {
  if (error instanceof StoreError) {
    const descriptor = Object.getOwnPropertyDescriptor(error, "code");
    if (
      descriptor !== undefined &&
      Object.prototype.hasOwnProperty.call(descriptor, "value")
    ) {
      if (descriptor.value === "unavailable") {
        return errorResponse(503, "state-unavailable");
      }
      if (descriptor.value === "conflict") {
        return errorResponse(409, "event-id-collision");
      }
    }
  }
  return errorResponse(500, "internal-error");
}

function isRequestValidationError(error) {
  return (
    error instanceof EventValidationError ||
    error instanceof AccessError ||
    (error instanceof StoreError &&
      Object.getOwnPropertyDescriptor(error, "code")?.value === "invalid-key")
  );
}

/**
 * Parse the query into exactly the allowed keys, each occurring at most
 * once, in canonical spelling. Returns a plain map or throws a validation
 * error.
 */
function parseQuery(req, allowedKeys, requiredKeys) {
  let url;
  try {
    url = new URL(req.url);
  } catch (error) {
    throw invalid("invalid url");
  }
  const raw = url.search.startsWith("?") ? url.search.slice(1) : url.search;
  const params = new URLSearchParams(raw);
  if (params.toString() !== raw) {
    throw invalid("invalid query");
  }
  const query = {};
  for (const [key, value] of params) {
    if (!allowedKeys.includes(key) || key in query || value === "") {
      throw invalid("invalid query");
    }
    query[key] = value;
  }
  for (const key of requiredKeys) {
    if (!(key in query)) {
      throw invalid("invalid query");
    }
  }
  return query;
}

function monthStartMs(month) {
  assertPattern(month, MONTH_PATTERN, "invalid month");
  const parsed = Date.parse(`${month}-01T00:00:00.000Z`);
  if (!Number.isSafeInteger(parsed) || parsed < MIN_NOW_MS || parsed > MAX_NOW_MS) {
    throw invalid("invalid month");
  }
  return parsed;
}

function monthOfEventId(id) {
  return new Date(Number(id.slice(0, 13))).toISOString().slice(0, 7);
}

function assertIdentity(user) {
  assertExactKeys(user, IDENTITY_FIELDS, "invalid identity");
  if (typeof user.isOrg !== "boolean") {
    throw invalid("invalid identity");
  }
  const actor = assertActor({
    sub: user.sub,
    name: user.name,
    email: user.email,
  });
  return {
    user: { sub: actor.sub, email: actor.email, name: actor.name, isOrg: user.isOrg },
    actor,
  };
}

/**
 * Validate the complete P2-G `ResolvedAccess` shape without trusting it, then
 * project the fields this handler uses onto a fresh object it owns.
 *
 * The validation is `validateAccessRow()` — this function used to reimplement
 * it under a name the acceptance grep for #125 could not see, which is exactly
 * how it stayed a fourth copy through that ticket (#128). The projection is
 * still local: the caller reads `access.role`, `access.threadControl` and the
 * booleans, and gets them from a row nothing else holds a reference to.
 */
function assertResolvedAccess(value) {
  if (!validateAccessRow(value, capabilitiesFor)) {
    throw invalid("invalid access result");
  }
  const access = { role: value.role, threadControl: value.threadControl };
  for (const field of ACCESS_BOOLEAN_FIELDS) {
    access[field] = value[field];
  }
  return access;
}

function mediaTypeIsJson(req) {
  const header = req.headers.get("content-type");
  if (header === null) {
    return false;
  }
  const type = header.split(";", 1)[0].trim().toLowerCase();
  return type === "application/json";
}

/**
 * Read at most 8,192 body bytes through one reader, decoding with a fatal
 * UTF-8 decoder. Resolves `{ text }` or `{ status }` for a bounded failure.
 * The reader lock is released exactly once; the stream is canceled only on
 * overflow.
 */
async function readBoundedBody(req) {
  const body = req.body;
  if (body === null || body === undefined) {
    return { text: "" };
  }
  const reader = body.getReader();
  const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
  let text = "";
  let total = 0;
  try {
    for (;;) {
      let result;
      try {
        result = await reader.read();
      } catch (error) {
        return { status: 400 };
      }
      if (result === null || typeof result !== "object") {
        return { status: 400 };
      }
      if (result.done === true) {
        break;
      }
      const chunk = result.value;
      if (!(chunk instanceof Uint8Array)) {
        return { status: 400 };
      }
      total += chunk.byteLength;
      if (total > MAX_BODY_BYTES) {
        try {
          await reader.cancel();
        } catch (error) {
          // The overflow verdict stands even when cancellation rejects.
        }
        return { status: 413 };
      }
      try {
        text += decoder.decode(chunk, { stream: true });
      } catch (error) {
        return { status: 400 };
      }
    }
    try {
      text += decoder.decode();
    } catch (error) {
      return { status: 400 };
    }
    return { text };
  } finally {
    reader.releaseLock();
  }
}

/** Parse and validate the exact four-field POST body. */
function parseBody(text) {
  if (text.length === 0) {
    throw invalid("empty body");
  }
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch (error) {
    throw invalid("invalid json");
  }
  assertExactKeys(parsed, BODY_FIELDS, "invalid body");
  return assertEventFacts(
    parsed.kind,
    parsed.target,
    parsed.docVersion,
    parsed.summary,
  );
}

function hasCapability(access, kind) {
  const [field, required] = KIND_CAPABILITY[kind];
  return access[field] === required;
}

/** Validate one provider list page envelope; returns its entry keys. */
function pageKeys(page) {
  const names = ownDataKeys(page, "invalid list page");
  if (!names.includes("blobs") || !names.includes("directories")) {
    throw invalid("invalid list page");
  }
  const { blobs, directories } = page;
  if (!isDenseArray(directories) || directories.length !== 0) {
    throw invalid("invalid list page");
  }
  if (!isDenseArray(blobs) || blobs.length > MAX_PAGE_ENTRIES) {
    throw invalid("invalid list page");
  }
  const keys = [];
  for (const entry of blobs) {
    const entryNames = ownDataKeys(entry, "invalid list entry");
    if (!entryNames.includes("key")) {
      throw invalid("invalid list entry");
    }
    const key = entry.key;
    if (typeof key !== "string" || utf8Length(key) > MAX_LISTED_KEY_BYTES) {
      throw invalid("invalid list entry");
    }
    keys.push(key);
  }
  return keys;
}

/** A dense array on `Array.prototype` with no symbol or extra properties. */
function isDenseArray(value) {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) {
    return false;
  }
  if (Object.getOwnPropertySymbols(value).length !== 0) {
    return false;
  }
  const length = value.length;
  let indexCount = 0;
  for (const name of Object.getOwnPropertyNames(value)) {
    if (name === "length") {
      continue;
    }
    const index = Number(name);
    if (
      !Number.isInteger(index) ||
      String(index) !== name ||
      index < 0 ||
      index >= length
    ) {
      return false;
    }
    const descriptor = Object.getOwnPropertyDescriptor(value, name);
    if (
      descriptor === undefined ||
      !Object.prototype.hasOwnProperty.call(descriptor, "value") ||
      descriptor.enumerable !== true
    ) {
      return false;
    }
    indexCount += 1;
  }
  return indexCount === length;
}

/**
 * Consume the provider iterator serially under the ten-page/10,000-key
 * ceiling, pulling at most one extra result to prove exhaustion. Envelope
 * violations reject as unavailable state; the returned keys are raw strings
 * still to be validated against the prefix.
 */
async function collectListedKeys(store, prefix) {
  let listing;
  try {
    listing = store.list({ prefix, paginate: true });
  } catch (error) {
    throw unavailable(error);
  }
  if (listing === null || typeof listing !== "object") {
    throw unavailable(undefined);
  }
  const keys = [];
  try {
    const factory = listing[Symbol.asyncIterator];
    if (typeof factory !== "function") {
      throw invalid("invalid list iterator");
    }
    const iterator = factory.call(listing);
    if (iterator === null || typeof iterator !== "object" || typeof iterator.next !== "function") {
      throw invalid("invalid list iterator");
    }
    for (let pull = 0; pull <= MAX_LIST_PAGES; pull += 1) {
      const result = await iterator.next();
      assertExactKeys(result, ["done", "value"], "invalid list result");
      if (typeof result.done !== "boolean") {
        throw invalid("invalid list result");
      }
      if (result.done === true) {
        if (result.value !== undefined) {
          throw invalid("invalid list result");
        }
        return keys;
      }
      if (pull === MAX_LIST_PAGES) {
        throw invalid("list page ceiling exceeded");
      }
      const pageEntries = pageKeys(result.value);
      if (keys.length + pageEntries.length > MAX_LIST_KEYS) {
        throw invalid("list key ceiling exceeded");
      }
      for (const key of pageEntries) {
        keys.push(key);
      }
    }
    throw invalid("list page ceiling exceeded");
  } catch (error) {
    throw unavailable(error);
  }
}

/** Validate listed keys against the prefix/month and sort by event ID. */
function validateListedKeys(keys, prefix, month) {
  const ids = [];
  const seen = new Set();
  for (const key of keys) {
    if (!key.startsWith(prefix) || !key.endsWith(".json")) {
      throw invalid("out-of-prefix key");
    }
    const id = key.slice(prefix.length, key.length - ".json".length);
    if (!EVENT_ID_PATTERN.test(id) || monthOfEventId(id) !== month) {
      throw invalid("malformed listed key");
    }
    if (seen.has(id)) {
      throw invalid("duplicate listed key");
    }
    seen.add(id);
    ids.push(id);
  }
  ids.sort((left, right) => (left < right ? -1 : left > right ? 1 : 0));
  return ids;
}

/**
 * Build the events handler from a closed dependency object.
 *
 * Allowed keys are `requireOriginFn`, `identifyFn`, `resolveRoleFn`,
 * `storeFn`, `nowFn`, and `randomBytesFn`; omitted values use the production
 * imports, `Date.now`, and `randomBytes`. Anything else throws synchronously.
 *
 * @param {object} [dependencies]
 * @returns {(req: Request) => Promise<Response>}
 */
export function createEventsHandler(dependencies = {}) {
  const names = assertSubsetKeys(
    dependencies,
    DEPENDENCY_FIELDS,
    "invalid dependencies",
  );
  for (const name of names) {
    if (typeof dependencies[name] !== "function") {
      throw invalid("invalid dependencies");
    }
  }
  const requireOriginFn = names.includes("requireOriginFn")
    ? dependencies.requireOriginFn
    : requireOrigin;
  const identifyFn = names.includes("identifyFn")
    ? dependencies.identifyFn
    : identify;
  const resolveRoleFn = names.includes("resolveRoleFn")
    ? dependencies.resolveRoleFn
    : resolveRole;
  const storeFn = names.includes("storeFn") ? dependencies.storeFn : docState;
  const nowFn = names.includes("nowFn") ? dependencies.nowFn : Date.now;
  const randomBytesFn = names.includes("randomBytesFn")
    ? dependencies.randomBytesFn
    : randomBytes;

  async function authorize(req, docId) {
    const user = await identifyFn(req);
    if (user === null) {
      return { response: errorResponse(401, "unauthenticated") };
    }
    const identity = assertIdentity(user);
    const resolved = await resolveRoleFn(docId, identity.user);
    const access = assertResolvedAccess(resolved);
    return { actor: identity.actor, access };
  }

  function openStore() {
    try {
      return storeFn();
    } catch (error) {
      throw unavailable(error);
    }
  }

  async function handlePost(req) {
    try {
      requireOriginFn(req);
    } catch (error) {
      if (error instanceof Response) {
        return error;
      }
      return errorResponse(500, "internal-error");
    }

    let docId;
    try {
      const query = parseQuery(req, ["doc"], ["doc"]);
      docId = assertDocId(query.doc);
    } catch (error) {
      return errorResponse(400, "invalid-request");
    }

    const auth = await authorize(req, docId);
    if (auth.response !== undefined) {
      return auth.response;
    }

    if (!mediaTypeIsJson(req)) {
      return errorResponse(415, "unsupported-media-type");
    }
    const read = await readBoundedBody(req);
    if (read.status !== undefined) {
      return errorResponse(read.status, read.status === 413 ? "payload-too-large" : "invalid-request");
    }

    let facts;
    try {
      facts = parseBody(read.text);
    } catch (error) {
      if (isRequestValidationError(error)) {
        return errorResponse(400, "invalid-request");
      }
      throw error;
    }

    if (!hasCapability(auth.access, facts.kind)) {
      return errorResponse(403, "forbidden");
    }

    const store = openStore();
    const nowMs = nowFn();
    const event = await appendEvent(
      {
        store,
        docId,
        actor: auth.actor,
        kind: facts.kind,
        target: facts.target,
        docVersion: facts.docVersion,
        summary: facts.summary,
      },
      { nowMs, randomBytesFn },
    );
    return jsonResponse(201, event);
  }

  async function handleGet(req) {
    let docId;
    let month;
    let limit = DEFAULT_LIMIT;
    let after = null;
    try {
      const query = parseQuery(
        req,
        ["doc", "month", "limit", "after"],
        ["doc", "month"],
      );
      docId = assertDocId(query.doc);
      month = query.month;
      monthStartMs(month);
      if ("limit" in query) {
        assertPattern(query.limit, LIMIT_PATTERN, "invalid limit");
        limit = Number(query.limit);
      }
      if ("after" in query) {
        after = assertEventId(query.after);
        if (monthOfEventId(after) !== month) {
          throw invalid("cursor outside month");
        }
      }
    } catch (error) {
      return errorResponse(400, "invalid-request");
    }

    const auth = await authorize(req, docId);
    if (auth.response !== undefined) {
      return auth.response;
    }
    if (auth.access.canSeeMembers !== true) {
      return errorResponse(403, "forbidden");
    }

    const store = openStore();
    const prefix = eventPrefix(docId, month);
    const listed = await collectListedKeys(store, prefix);
    const ids = validateListedKeys(listed, prefix, month);

    const events = [];
    for (const id of ids) {
      if (after !== null && id <= after) {
        continue;
      }
      if (events.length === limit + 1) {
        break;
      }
      const key = `${prefix}${id}.json`;
      let value;
      try {
        value = await store.get(key, { type: "json", consistency: "strong" });
      } catch (error) {
        throw unavailable(error);
      }
      if (value === null) {
        continue;
      }
      events.push(assertEvent(value, key));
    }

    let nextAfter = null;
    if (events.length === limit + 1) {
      events.pop();
      nextAfter = events[events.length - 1].id;
    }
    return jsonResponse(200, { v: 1, docId, month, events, nextAfter });
  }

  return async function eventsHandler(req) {
    const method = req.method;
    if (method !== "GET" && method !== "POST") {
      return errorResponse(405, "method-not-allowed", { Allow: "GET, POST" });
    }
    try {
      return method === "POST" ? await handlePost(req) : await handleGet(req);
    } catch (error) {
      return classifyError(error);
    }
  };
}

const productionHandler = createEventsHandler();

/**
 * The production Functions v2 handler.
 * @param {Request} req
 * @returns {Promise<Response>}
 */
export default async function handler(req) {
  return productionHandler(req);
}
