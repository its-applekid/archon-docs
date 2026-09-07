import { identify, requireOrigin } from "../lib/identity.mjs";
import {
  StoreError,
  assertDocId,
  docState,
  read,
  threadKey,
  threadPrefix,
  upgrade,
} from "../lib/store.mjs";
import { capabilitiesFor, resolveRole, validateAccessRow } from "../lib/access.mjs";
import { appendEvent } from "./events.mjs";
import { notify } from "../lib/notify.mjs";

/**
 * P3-A — `/api/threads`: list one page of a document's threads (`GET`) and
 * create a thread with its first comment (`POST`).
 *
 * Every actor is projected from the verified server identity. `GET` is
 * authorized through P2-G's non-consuming `canRead` result before thread
 * storage is opened. P4-M adds the matching `canComment` gate to `POST`, the
 * post-commit `comment.create` audit append, and the `thread.created`
 * fan-out.
 *
 * The access-row check is *not* one of the private validators below: it is
 * `validateAccessRow()` from `../lib/access.mjs`, shared with every other path
 * that resolves a role. This header used to say that duplicating it here was
 * deliberate and that a shared helper was forbidden; that was the reason the
 * copies drifted until one of them stopped being covered at all (#125, #128).
 * Do not reintroduce a local copy.
 */

const MAX_REQUEST_BYTES = 65_536;
const MAX_PROVIDER_PAGES = 10;
const MAX_LISTED_KEYS = 10_000;
const MAX_PAGE_ENTRIES = 1_000;
const MAX_LISTED_KEY_BYTES = 96;
const MAX_COMMENTS = 500;
const MAX_RESPONSE_COMMENTS = 5_000;
const DEFAULT_LIMIT = 50;
const MAX_LIMIT = 100;
const MAX_BODY_UNITS = 8_000;
const MAX_TITLE_UNITS = 200;
const MAX_NAME_UNITS = 200;
const MAX_EXACT_UNITS = 1_000;
const MAX_AFFIX_UNITS = 32;
const MAX_EMAIL_UNITS = 254;
const MAX_EMAIL_LOCAL_UNITS = 64;

const DOC_ID_PATTERN = /^[0-9a-f]{6}$/;
const THREAD_ID_PATTERN = /^t_[a-z0-9]{1,48}_[0-9a-f]{8}$/;
const COMMENT_ID_PATTERN = /^c_[a-z0-9]{1,48}_[0-9a-f]{8}$/;
const SECTION_PATTERN = /^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/;
const DOC_VERSION_PATTERN = /^[0-9a-f]{7}$/;
const ANCHOR_BLOCK_PATTERN = /^a[0-9a-f]{8}$/;
const SUBJECT_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._~-]{0,127}$/;
const EMAIL_LOCAL_PATTERN =
  /^[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*$/;
const DNS_LABEL_PATTERN = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const TIMESTAMP_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const OPERATION_MS_PATTERN = /^[0-9]{13}$/;
const CANONICAL_INTEGER_PATTERN = /^(?:0|[1-9][0-9]*)$/;
const POSITIVE_INTEGER_PATTERN = /^[1-9][0-9]*$/;
const NON_SPACE_WHITESPACE_PATTERN = /[^\S ]/;
const MEDIA_TYPE_PATTERN =
  /^[ \t]*([!#$%&'*+.^_`|~0-9A-Za-z-]+)\/([!#$%&'*+.^_`|~0-9A-Za-z-]+)[ \t]*(?:;[ \t]*[!#$%&'*+.^_`|~0-9A-Za-z-]+=(?:[!#$%&'*+.^_`|~0-9A-Za-z-]+|"(?:[^"\\\x00-\x1f\x7f]|\\[\x00-\x7f])*")[ \t]*)*$/;

const THREAD_KEYS = Object.freeze([
  "v",
  "id",
  "docId",
  "kind",
  "status",
  "section",
  "anchor",
  "title",
  "docVersion",
  "createdAt",
  "author",
  "resolvedAt",
  "resolvedBy",
  "comments",
]);
const COMMENT_KEYS = Object.freeze(["id", "body", "author", "createdAt", "editedAt"]);
const ACTOR_KEYS = Object.freeze(["sub", "name", "email"]);
const ANCHOR_KEYS = Object.freeze(["block", "exact", "prefix", "suffix", "start"]);
const CREATE_KEYS = Object.freeze([
  "kind",
  "section",
  "anchor",
  "docVersion",
  "body",
  "title",
  "author",
  "email",
  "name",
]);
const LIST_QUERY_KEYS = Object.freeze(["doc", "limit", "cursor"]);

const NO_STORE = "private, no-store";
const JSON_CONTENT_TYPE = "application/json; charset=utf-8";

/** The complete public error table: code -> [status, message]. */
const PUBLIC_ERRORS = Object.freeze({
  "method-not-allowed": [405, "Method not allowed"],
  unauthenticated: [401, "Authentication required"],
  forbidden: [403, "Document access denied"],
  "invalid-request": [400, "Invalid request"],
  "unsupported-media-type": [415, "Content-Type must be application/json"],
  "payload-too-large": [413, "Request body exceeds 65536 bytes"],
  "invalid-body": [400, "Invalid request body"],
  "not-found": [404, "Thread not found"],
  conflict: [409, "Concurrent update limit reached"],
  "id-collision": [409, "Generated identifier collision"],
  "comment-limit": [409, "Thread comment limit reached"],
  "invalid-state": [500, "Invalid thread state"],
  unavailable: [503, "Thread store unavailable"],
});

/** Private domain sentinel carrying one public error code. Never serialized. */
class EndpointError extends Error {
  constructor(code) {
    super(code);
    this.name = "EndpointError";
    this.code = code;
  }
}

function fail(code) {
  return new EndpointError(code);
}

function jsonResponse(status, body, extraHeaders) {
  const headers = {
    "Cache-Control": NO_STORE,
    "Content-Type": JSON_CONTENT_TYPE,
    ...extraHeaders,
  };
  return new Response(JSON.stringify(body), { status, headers });
}

function errorResponse(code, extraHeaders) {
  const [status, message] = PUBLIC_ERRORS[code];
  return jsonResponse(status, { error: { code, message } }, extraHeaders);
}

function classify(error) {
  if (error instanceof EndpointError) {
    return error.code;
  }
  if (error instanceof StoreError) {
    if (error.code === "conflict") {
      return "conflict";
    }
    if (error.code === "unavailable") {
      return "unavailable";
    }
  }
  return "invalid-state";
}

// ---------------------------------------------------------------------------
// Descriptor-safe object inspection. None of these helpers invoke a getter.
// ---------------------------------------------------------------------------

function hasOwn(object, key) {
  return Object.prototype.hasOwnProperty.call(object, key);
}

/** A non-null, non-array object whose prototype is exactly Object.prototype
 * and which carries no symbol-keyed own properties. */
function isPlainObject(value) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype &&
    Object.getOwnPropertySymbols(value).length === 0
  );
}

/** Returns `{ value }` when `key` is an own enumerable data property of
 * `object`, or `null` otherwise, without invoking any accessor. */
function ownData(object, key) {
  const descriptor = Object.getOwnPropertyDescriptor(object, key);
  if (
    descriptor === undefined ||
    !hasOwn(descriptor, "value") ||
    descriptor.enumerable !== true
  ) {
    return null;
  }
  return { value: descriptor.value };
}

/** Own enumerable data-property names of a plain object whose every own
 * property is such a property, or `null` when any accessor, non-enumerable,
 * or symbol-keyed property exists. */
function ownDataKeys(object) {
  if (!isPlainObject(object)) {
    return null;
  }
  const names = Object.getOwnPropertyNames(object);
  for (const name of names) {
    if (ownData(object, name) === null) {
      return null;
    }
  }
  return names;
}

function hasExactKeys(object, expected) {
  const names = ownDataKeys(object);
  if (names === null || names.length !== expected.length) {
    return false;
  }
  return expected.every((key) => names.includes(key));
}

/** A dense array with only index keys plus `length`, every element an own
 * enumerable data property, and no symbol keys. */
function isDenseArray(value) {
  if (!Array.isArray(value)) {
    return false;
  }
  if (Object.getOwnPropertySymbols(value).length !== 0) {
    return false;
  }
  const names = Object.getOwnPropertyNames(value);
  if (names.length !== value.length + 1) {
    return false;
  }
  for (let index = 0; index < value.length; index += 1) {
    if (ownData(value, String(index)) === null) {
      return false;
    }
  }
  return true;
}

// ---------------------------------------------------------------------------
// Scalar grammar.
// ---------------------------------------------------------------------------

function isTimestamp(value) {
  return (
    typeof value === "string" &&
    TIMESTAMP_PATTERN.test(value) &&
    new Date(value).toISOString() === value
  );
}

function isSubject(value) {
  return typeof value === "string" && SUBJECT_PATTERN.test(value);
}

function isActorName(value) {
  return typeof value === "string" && value.length <= MAX_NAME_UNITS;
}

function isEmail(value) {
  if (typeof value !== "string") {
    return false;
  }
  if (value === "") {
    return true;
  }
  if (value.length > MAX_EMAIL_UNITS) {
    return false;
  }
  const at = value.indexOf("@");
  if (at === -1 || value.indexOf("@", at + 1) !== -1) {
    return false;
  }
  const local = value.slice(0, at);
  const domain = value.slice(at + 1);
  if (
    local.length < 1 ||
    local.length > MAX_EMAIL_LOCAL_UNITS ||
    !EMAIL_LOCAL_PATTERN.test(local)
  ) {
    return false;
  }
  const labels = domain.split(".");
  return labels.length >= 2 && labels.every((label) => DNS_LABEL_PATTERN.test(label));
}

function isBodyText(value) {
  return (
    typeof value === "string" &&
    value.length >= 1 &&
    value.length <= MAX_BODY_UNITS &&
    value.trim().length > 0
  );
}

function isTitleText(value) {
  return (
    typeof value === "string" &&
    value.length <= MAX_TITLE_UNITS &&
    value.trim().length > 0
  );
}

function isNormalizedExact(value) {
  return (
    typeof value === "string" &&
    value.length >= 1 &&
    value.length <= MAX_EXACT_UNITS &&
    value === value.replace(/\s+/g, " ").trim()
  );
}

function isNormalizedAffix(value) {
  return (
    typeof value === "string" &&
    value.length <= MAX_AFFIX_UNITS &&
    !NON_SPACE_WHITESPACE_PATTERN.test(value) &&
    !value.includes("  ")
  );
}

function isOffset(value) {
  return Number.isSafeInteger(value) && value >= 0 && !Object.is(value, -0);
}

// ---------------------------------------------------------------------------
// Persisted version-1 thread validation.
// ---------------------------------------------------------------------------

function isActor(value) {
  return (
    hasExactKeys(value, ACTOR_KEYS) &&
    isSubject(value.sub) &&
    isActorName(value.name) &&
    isEmail(value.email)
  );
}

function isAnchor(value) {
  return (
    hasExactKeys(value, ANCHOR_KEYS) &&
    typeof value.block === "string" &&
    ANCHOR_BLOCK_PATTERN.test(value.block) &&
    isNormalizedExact(value.exact) &&
    isNormalizedAffix(value.prefix) &&
    isNormalizedAffix(value.suffix) &&
    isOffset(value.start)
  );
}

function isComment(value) {
  return (
    hasExactKeys(value, COMMENT_KEYS) &&
    typeof value.id === "string" &&
    COMMENT_ID_PATTERN.test(value.id) &&
    isBodyText(value.body) &&
    isActor(value.author) &&
    isTimestamp(value.createdAt) &&
    (value.editedAt === null || isTimestamp(value.editedAt))
  );
}

function sameActor(left, right) {
  return (
    left.sub === right.sub && left.name === right.name && left.email === right.email
  );
}

/**
 * Fail-closed validation of one stored or constructed thread against the key
 * it lives under. Returns the same record or throws `invalid-state`.
 */
function validateThread(record, docId, threadId) {
  try {
    upgrade(record);
  } catch {
    throw fail("invalid-state");
  }
  if (!hasExactKeys(record, THREAD_KEYS)) {
    throw fail("invalid-state");
  }
  const valid =
    record.v === 1 &&
    record.id === threadId &&
    typeof threadId === "string" &&
    THREAD_ID_PATTERN.test(threadId) &&
    record.docId === docId &&
    typeof docId === "string" &&
    DOC_ID_PATTERN.test(docId) &&
    (record.kind === "comment" || record.kind === "discussion") &&
    (record.status === "open" || record.status === "resolved") &&
    typeof record.section === "string" &&
    SECTION_PATTERN.test(record.section) &&
    typeof record.docVersion === "string" &&
    DOC_VERSION_PATTERN.test(record.docVersion) &&
    isTimestamp(record.createdAt) &&
    isActor(record.author);
  if (!valid) {
    throw fail("invalid-state");
  }
  if (record.kind === "comment") {
    if (!isAnchor(record.anchor) || record.title !== null) {
      throw fail("invalid-state");
    }
  } else if (record.anchor !== null || !isTitleText(record.title)) {
    throw fail("invalid-state");
  }
  if (record.status === "open") {
    if (record.resolvedAt !== null || record.resolvedBy !== null) {
      throw fail("invalid-state");
    }
  } else if (!isTimestamp(record.resolvedAt) || !isActor(record.resolvedBy)) {
    throw fail("invalid-state");
  }
  const comments = record.comments;
  if (
    !isDenseArray(comments) ||
    comments.length < 1 ||
    comments.length > MAX_COMMENTS
  ) {
    throw fail("invalid-state");
  }
  const seen = new Set();
  for (const comment of comments) {
    if (!isComment(comment) || seen.has(comment.id)) {
      throw fail("invalid-state");
    }
    seen.add(comment.id);
  }
  const first = comments[0];
  if (!sameActor(first.author, record.author) || first.createdAt !== record.createdAt) {
    throw fail("invalid-state");
  }
  return record;
}

// ---------------------------------------------------------------------------
// Identity, actor projection, clock, and identifiers.
// ---------------------------------------------------------------------------

/** Validate the verified identity's three actor scalars and project them to a
 * fresh actor. Only `sub`, `name`, and `email` are ever read. */
function requireActor(identity) {
  if (identity === null) {
    throw fail("unauthenticated");
  }
  if (typeof identity !== "object" || Array.isArray(identity)) {
    throw fail("invalid-state");
  }
  const sub = identity.sub;
  const name = identity.name;
  const email = identity.email;
  if (!isSubject(sub) || !isActorName(name) || !isEmail(email)) {
    throw fail("invalid-state");
  }
  return { sub, name, email };
}

function copyActor(actor) {
  return { sub: actor.sub, name: actor.name, email: actor.email };
}

/** Sample the one operation clock value; an impossible result is a 500. */
function sampleOperationTime() {
  const operationMs = Date.now();
  if (typeof operationMs !== "number" || !OPERATION_MS_PATTERN.test(String(operationMs))) {
    throw fail("invalid-state");
  }
  const operationTime = new Date(operationMs).toISOString();
  if (!isTimestamp(operationTime)) {
    throw fail("invalid-state");
  }
  return { operationMs, operationTime };
}

function sampleIdentifier(prefix, operationMs) {
  const uuid = crypto.randomUUID();
  if (typeof uuid !== "string" || !UUID_PATTERN.test(uuid)) {
    throw fail("invalid-state");
  }
  return `${prefix}_${operationMs.toString(36)}_${uuid.slice(0, 8)}`;
}

// ---------------------------------------------------------------------------
// Request parsing.
// ---------------------------------------------------------------------------

/** Query parameters as a Map; a duplicate name is invalid. */
function queryMap(req) {
  let url;
  try {
    url = new URL(req.url);
  } catch {
    throw fail("invalid-request");
  }
  const values = new Map();
  for (const [name, value] of url.searchParams) {
    if (values.has(name)) {
      throw fail("invalid-request");
    }
    values.set(name, value);
  }
  return values;
}

function parseDocId(values) {
  const docId = values.get("doc");
  if (typeof docId !== "string" || !DOC_ID_PATTERN.test(docId)) {
    throw fail("invalid-request");
  }
  return assertDocId(docId);
}

function parseListQuery(req) {
  const values = queryMap(req);
  for (const name of values.keys()) {
    if (!LIST_QUERY_KEYS.includes(name)) {
      throw fail("invalid-request");
    }
  }
  const docId = parseDocId(values);
  let limit = DEFAULT_LIMIT;
  if (values.has("limit")) {
    const raw = values.get("limit");
    if (!POSITIVE_INTEGER_PATTERN.test(raw)) {
      throw fail("invalid-request");
    }
    limit = Number(raw);
    if (!Number.isSafeInteger(limit) || limit > MAX_LIMIT) {
      throw fail("invalid-request");
    }
  }
  let cursor = null;
  if (values.has("cursor")) {
    cursor = values.get("cursor");
    if (!THREAD_ID_PATTERN.test(cursor)) {
      throw fail("invalid-request");
    }
  }
  return { docId, limit, cursor };
}

function parseCreateQuery(req) {
  const values = queryMap(req);
  for (const name of values.keys()) {
    if (name !== "doc") {
      throw fail("invalid-request");
    }
  }
  return parseDocId(values);
}

function isJsonMediaType(header) {
  if (typeof header !== "string") {
    return false;
  }
  const match = header.match(MEDIA_TYPE_PATTERN);
  return match !== null && `${match[1]}/${match[2]}`.toLowerCase() === "application/json";
}

/** Stream at most 65,536 bytes through exactly one reader. */
async function readBoundedBytes(req) {
  const body = req.body;
  if (
    body === null ||
    body === undefined ||
    typeof body.getReader !== "function" ||
    body.locked === true
  ) {
    throw fail("invalid-body");
  }
  let reader;
  try {
    reader = body.getReader();
  } catch {
    throw fail("invalid-body");
  }
  const chunks = [];
  let total = 0;
  let failure = null;
  try {
    for (;;) {
      const result = await reader.read();
      if (result.done === true) {
        break;
      }
      const chunk = result.value;
      if (!(chunk instanceof Uint8Array)) {
        failure = "invalid-body";
        break;
      }
      if (total + chunk.byteLength > MAX_REQUEST_BYTES) {
        failure = "payload-too-large";
        break;
      }
      chunks.push(chunk);
      total += chunk.byteLength;
    }
  } catch {
    failure = "invalid-body";
  }
  if (failure !== null) {
    try {
      await reader.cancel();
    } catch {
      // A rejected cancellation is tolerated; the lock is still released once.
    }
  }
  try {
    reader.releaseLock();
  } catch {
    // The lock release is best effort and never repeated.
  }
  if (failure !== null) {
    throw fail(failure);
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return bytes;
}

/** Media type, canonical Content-Length, bounded stream read, one fatal
 * UTF-8 decode, and one parse into a non-null, non-array ordinary object. */
async function readJsonObject(req) {
  if (!isJsonMediaType(req.headers.get("content-type"))) {
    throw fail("unsupported-media-type");
  }
  const declared = req.headers.get("content-length");
  if (declared !== null) {
    if (!CANONICAL_INTEGER_PATTERN.test(declared) || !Number.isSafeInteger(Number(declared))) {
      throw fail("invalid-body");
    }
    if (Number(declared) > MAX_REQUEST_BYTES) {
      throw fail("payload-too-large");
    }
  }
  const bytes = await readBoundedBytes(req);
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    throw fail("invalid-body");
  }
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw fail("invalid-body");
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw fail("invalid-body");
  }
  return parsed;
}

/** Exact create-body grammar. The reserved `author`, `email`, and `name`
 * keys are tolerated but never read. */
function parseCreateBody(parsed) {
  for (const key of Object.keys(parsed)) {
    if (!CREATE_KEYS.includes(key)) {
      throw fail("invalid-body");
    }
  }
  const kind = parsed.kind;
  const section = parsed.section;
  const docVersion = parsed.docVersion;
  const body = parsed.body;
  if (
    (kind !== "comment" && kind !== "discussion") ||
    typeof section !== "string" ||
    !SECTION_PATTERN.test(section) ||
    typeof docVersion !== "string" ||
    !DOC_VERSION_PATTERN.test(docVersion) ||
    !isBodyText(body)
  ) {
    throw fail("invalid-body");
  }
  const hasAnchor = hasOwn(parsed, "anchor");
  const hasTitle = hasOwn(parsed, "title");
  if (kind === "comment") {
    if (!hasAnchor || !isAnchor(parsed.anchor) || (hasTitle && parsed.title !== null)) {
      throw fail("invalid-body");
    }
    const source = parsed.anchor;
    const anchor = {
      block: source.block,
      exact: source.exact,
      prefix: source.prefix,
      suffix: source.suffix,
      start: source.start,
    };
    return { kind, section, docVersion, body, anchor, title: null };
  }
  if ((hasAnchor && parsed.anchor !== null) || !hasTitle || !isTitleText(parsed.title)) {
    throw fail("invalid-body");
  }
  return { kind, section, docVersion, body, anchor: null, title: parsed.title };
}

// ---------------------------------------------------------------------------
// Read authorization (P3-A's only access decision).
// ---------------------------------------------------------------------------

/** The safe classification of an access rejection: own data properties
 * `name === "StoreError"`, `code === "unavailable"`, `status === 503`. */
function isUnavailableRejection(error) {
  if (error === null || typeof error !== "object" || Array.isArray(error)) {
    return false;
  }
  const name = ownData(error, "name");
  const code = ownData(error, "code");
  const status = ownData(error, "status");
  return (
    name !== null &&
    code !== null &&
    status !== null &&
    name.value === "StoreError" &&
    code.value === "unavailable" &&
    status.value === 503
  );
}

/**
 * The single non-consuming P2-G lookup for this request. It runs after every
 * public request gate and before any clock, randomness, or thread-store work;
 * its own access-store reads are the authority lookup, not domain work.
 */
async function resolveAccess(docId, identity) {
  let result;
  try {
    result = await resolveRole(docId, identity, { consumeInvitation: false });
  } catch (error) {
    throw fail(isUnavailableRejection(error) ? "unavailable" : "invalid-state");
  }
  if (!validateAccessRow(result, capabilitiesFor)) {
    throw fail("invalid-state");
  }
  return result;
}

async function requireReadAccess(docId, identity) {
  const access = await resolveAccess(docId, identity);
  if (access.canRead !== true) {
    throw fail("forbidden");
  }
}

async function requireCommentAccess(docId, identity) {
  const access = await resolveAccess(docId, identity);
  if (access.canComment !== true) {
    throw fail("forbidden");
  }
}

// ---------------------------------------------------------------------------
// Bounded provider enumeration.
// ---------------------------------------------------------------------------

function utf8Length(value) {
  return new TextEncoder().encode(value).byteLength;
}

/** Validate one iterator result envelope; returns its `done` boolean. */
function iteratorDone(result) {
  if (!isPlainObject(result)) {
    throw fail("unavailable");
  }
  const done = ownData(result, "done");
  if (done === null || typeof done.value !== "boolean") {
    throw fail("unavailable");
  }
  if (done.value === false && ownData(result, "value") === null) {
    throw fail("unavailable");
  }
  return done.value;
}

/** Validate one provider page envelope and project its key strings. */
function pageKeys(page) {
  if (!isPlainObject(page)) {
    throw fail("unavailable");
  }
  const blobs = ownData(page, "blobs");
  if (blobs === null || !isDenseArray(blobs.value) || blobs.value.length > MAX_PAGE_ENTRIES) {
    throw fail("unavailable");
  }
  const keys = [];
  for (const entry of blobs.value) {
    if (!isPlainObject(entry)) {
      throw fail("unavailable");
    }
    const key = ownData(entry, "key");
    if (key === null || typeof key.value !== "string" || utf8Length(key.value) > MAX_LISTED_KEY_BYTES) {
      throw fail("unavailable");
    }
    keys.push(key.value);
  }
  return keys;
}

/** The thread ID encoded by a listed key, or `null` for corrupt data. */
function parseListedThreadId(key, docId, prefix) {
  if (!key.startsWith(prefix) || !key.endsWith(".json")) {
    return null;
  }
  const threadId = key.slice(prefix.length, key.length - ".json".length);
  if (!THREAD_ID_PATTERN.test(threadId)) {
    return null;
  }
  let expected;
  try {
    expected = threadKey(docId, threadId);
  } catch {
    return null;
  }
  return expected === key ? threadId : null;
}

async function closeIterator(iterator) {
  if (iterator === null || typeof iterator !== "object") {
    return;
  }
  try {
    const close = iterator.return;
    if (typeof close === "function") {
      await close.call(iterator);
    }
  } catch {
    // Cleanup failures never replace the original provider failure.
  }
}

/** Manually drive the provider iterator: at most ten data pages plus one
 * exhaustion probe. Returns the set of unique listed thread IDs. */
async function listThreadIds(store, docId) {
  const prefix = threadPrefix(docId);
  let iterator = null;
  try {
    const iterable = store.list({ prefix, paginate: true });
    if (iterable === null || typeof iterable !== "object") {
      throw fail("unavailable");
    }
    const open = iterable[Symbol.asyncIterator];
    if (typeof open !== "function") {
      throw fail("unavailable");
    }
    iterator = open.call(iterable);
    if (iterator === null || typeof iterator !== "object" || typeof iterator.next !== "function") {
      throw fail("unavailable");
    }
  } catch (error) {
    await closeIterator(iterator);
    throw error instanceof EndpointError ? error : fail("unavailable");
  }
  const ids = new Set();
  try {
    for (let page = 0; page <= MAX_PROVIDER_PAGES; page += 1) {
      let result;
      try {
        result = await iterator.next();
      } catch {
        throw fail("unavailable");
      }
      if (iteratorDone(result)) {
        return ids;
      }
      if (page === MAX_PROVIDER_PAGES) {
        throw fail("unavailable");
      }
      for (const key of pageKeys(result.value)) {
        const threadId = parseListedThreadId(key, docId, prefix);
        if (threadId === null || ids.has(threadId)) {
          throw fail("invalid-state");
        }
        ids.add(threadId);
        if (ids.size > MAX_LISTED_KEYS) {
          throw fail("unavailable");
        }
      }
    }
  } catch (error) {
    await closeIterator(iterator);
    throw error;
  }
  throw fail("unavailable");
}

// ---------------------------------------------------------------------------
// Operations.
// ---------------------------------------------------------------------------

function openStore() {
  try {
    return docState();
  } catch {
    throw fail("unavailable");
  }
}

async function listThreads(req) {
  const identity = await identify(req);
  requireActor(identity);
  const { docId, limit, cursor } = parseListQuery(req);
  await requireReadAccess(docId, identity);

  const store = openStore();
  const ids = await listThreadIds(store, docId);
  const candidates = [...ids].sort().filter((id) => cursor === null || id > cursor);

  const threads = [];
  let totalComments = 0;
  let index = 0;
  while (index < candidates.length && threads.length < limit) {
    const threadId = candidates[index];
    const found = await read(store, threadKey(docId, threadId));
    if (found === null || typeof found !== "object" || !hasOwn(found, "value")) {
      throw fail("invalid-state");
    }
    if (found.value === null) {
      index += 1;
      continue;
    }
    const record = validateThread(found.value, docId, threadId);
    if (totalComments + record.comments.length > MAX_RESPONSE_COMMENTS) {
      break;
    }
    threads.push(record);
    totalComments += record.comments.length;
    index += 1;
  }
  const nextCursor =
    index < candidates.length && threads.length > 0 ? threads[threads.length - 1].id : null;
  return jsonResponse(200, { threads, nextCursor });
}

async function createThread(req, context) {
  requireOrigin(req);
  const identity = await identify(req);
  const actor = requireActor(identity);
  const docId = parseCreateQuery(req);
  const input = parseCreateBody(await readJsonObject(req));

  // P4-M: the one non-consuming P2-G lookup, after every public request gate
  // and before the clock, the identifier randomness, and `docState()`.
  await requireCommentAccess(docId, identity);

  const { operationMs, operationTime } = sampleOperationTime();
  const threadId = sampleIdentifier("t", operationMs);
  const commentId = sampleIdentifier("c", operationMs);
  const thread = {
    v: 1,
    id: threadId,
    docId,
    kind: input.kind,
    status: "open",
    section: input.section,
    anchor: input.anchor,
    title: input.title,
    docVersion: input.docVersion,
    createdAt: operationTime,
    author: copyActor(actor),
    resolvedAt: null,
    resolvedBy: null,
    comments: [
      {
        id: commentId,
        body: input.body,
        author: copyActor(actor),
        createdAt: operationTime,
        editedAt: null,
      },
    ],
  };
  validateThread(thread, docId, threadId);
  const key = threadKey(docId, threadId);

  const store = openStore();
  let result;
  try {
    result = await store.setJSON(key, thread, { onlyIfNew: true });
  } catch {
    throw fail("unavailable");
  }
  if (result === null || typeof result !== "object" || Array.isArray(result)) {
    throw fail("unavailable");
  }
  const modified = Object.getOwnPropertyDescriptor(result, "modified");
  if (modified === undefined || !hasOwn(modified, "value") || typeof modified.value !== "boolean") {
    throw fail("unavailable");
  }
  if (modified.value === false) {
    throw fail("id-collision");
  }

  // The thread is durable from here on. P3-B has no transaction with the
  // domain record, so the audit append and the fan-out are both best effort:
  // neither may change this response, retry, roll back, or encourage a replay
  // of a non-idempotent POST.
  await auditThreadCreate(store, thread, actor);
  fanOutThreadCreated(context, thread);
  return jsonResponse(201, { thread });
}

/** One canonical P3-B `comment.create` append, attempted only after the
 * authoritative write succeeded. Every failure is absorbed here. */
async function auditThreadCreate(store, thread, actor) {
  try {
    await appendEvent({
      store,
      docId: thread.docId,
      actor: { sub: actor.sub, name: actor.name, email: actor.email },
      kind: "comment.create",
      target: { threadId: thread.id, aid: thread.anchor?.block ?? null },
      docVersion: thread.docVersion,
      summary: `commented on ${thread.section}`,
    });
  } catch {
    // A collision, an unavailable store, and an unexpected throw are all
    // absorbed identically: the audit row may be lost, the thread may not.
  }
}

/** The sole P4-D/P4-H fan-out call for a durable thread creation. Its boolean
 * result is ignored and any throw is absorbed: a notification can never turn
 * a landed write into a failed response. */
function fanOutThreadCreated(context, thread) {
  try {
    notify(context, {
      t: "thread.created",
      docId: thread.docId,
      threadId: thread.id,
      actorName: thread.author.name,
      threadKind: thread.kind,
      body: thread.comments[0].body,
      quote: thread.kind === "comment" ? thread.anchor.exact : null,
    });
  } catch {
    // Best effort by contract.
  }
}

/**
 * `GET /api/threads` lists one page; `POST /api/threads` creates a thread.
 *
 * @param {Request} req
 * @param {object} context
 * @returns {Promise<Response>}
 */
export default async function handler(req, context) {
  try {
    if (req.method === "GET") {
      return await listThreads(req);
    }
    if (req.method === "POST") {
      return await createThread(req, context);
    }
    return errorResponse("method-not-allowed", { Allow: "GET, POST" });
  } catch (error) {
    if (error instanceof Response) {
      return error;
    }
    return errorResponse(classify(error));
  }
}

export const config = { path: "/api/threads" };
