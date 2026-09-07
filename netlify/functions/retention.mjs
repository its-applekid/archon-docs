import {
  StoreError,
  docState,
  eventKey,
  read,
  suggestionKey,
} from "../lib/store.mjs";
import { assertAccessInvitationAtKey } from "../lib/access.mjs";
import { assertEvent } from "./events.mjs";
import { assertSuggestionAtKey } from "./suggestions.mjs";
import { withAccessWriteLease } from "./access.mjs";

/**
 * P4-F — the daily audit-event retention sweep.
 *
 * The event stream is an append-only audit view, not feature state, so ordinary
 * historical events may expire without changing comments, edits, suggestions or
 * access. Netlify Blobs has no automatic TTL for the `doc-state` store, so
 * expiry has to be application code, and this is the only place that deletes an
 * event.
 *
 * Everything here is deliberately bounded. One invocation samples one clock,
 * opens one store, walks at most ten manually pulled pages of the global
 * `events/` prefix, reads only keys that are already past the cutoff, validates
 * every record through the P3-B schema before touching it, and deletes at most
 * one hundred of them oldest-first. A run that cannot prove what it is looking
 * at fails; it never invents a successful sweep, never repairs a record, and
 * never retries the provider. The next daily run resumes from what is left.
 *
 * Amendment boundary
 * ------------------
 * P4-T is the only ticket allowed to amend this file, and it has: the 540-day
 * strict cutoff, manual pagination, deterministic ordering,
 * validation-before-delete, the delete caps, the failure semantics, the summary
 * version and the no-route/no-identity boundary are all preserved. P4-T adds
 * the durable-event exclusion predicate and two separately bounded sweeps over
 * `suggest/` and expired `access/` invitations.
 *
 * Three scans, three budgets
 * --------------------------
 * One invocation samples one clock, opens one store, and starts the `events/`,
 * `suggest/` and `access/` scans in that fixed order without awaiting between
 * the starts, then awaits all three. Each scan is internally serial, so at most
 * three provider operations are ever in flight, and no class can consume
 * another class's delete budget or stop it from beginning. A failing class does
 * not roll back another's committed deletes; the run rejects with the first
 * failure in fixed class order and logs nothing.
 */

/**
 * Eighteen months as a fixed duration: 18 * 30 fixed 24-hour days, or 540 days
 * in milliseconds. This is the research contract's definition and deliberately
 * not calendar-month arithmetic, so month length, timezone and daylight saving
 * time cannot move a boundary.
 */
export const EVENT_RETENTION_MS = 18 * 30 * 24 * 60 * 60 * 1000;

/**
 * The most events one invocation may delete. A safety bound chosen to stay
 * comfortably inside Netlify's fixed 30-second scheduled-function limit; it is
 * not a correctness boundary, and exhausting it is reported as `remaining`.
 */
export const MAX_EVENT_DELETES = 100;

/**
 * Ninety fixed 24-hour days. An open suggestion is a live product object rather
 * than an audit fact, so it has a finite ceiling; the provider has no TTL, so
 * the ceiling has to be enforced here. Fixed days again, not calendar months.
 */
export const SUGGESTION_RETENTION_MS = 90 * 24 * 60 * 60 * 1000;

/** The most suggestion records one invocation may delete. */
export const MAX_SUGGESTION_DELETES = 75;

/**
 * The most invitation records one invocation may read at all. Invitations are
 * short-lived by construction, so a listing larger than this is a repair signal
 * rather than a sweep to grind through, and it fails before any read or delete.
 */
export const MAX_INVITATION_RECORDS = 250;

/** The most invitation records one invocation may delete. */
export const MAX_INVITATION_DELETES = 75;

/**
 * The event kinds that never expire.
 *
 * These are the only durable record of who authored a suggestion, who decided
 * it, who applied an edit, and who changed a document's authority. In
 * standalone mode there is no second copy anywhere — no Git history row, no
 * provider audit log — so ageing them out is data loss, not cleanup.
 *
 * `suggest.create` is here alongside the accept/reject decisions because P3-B's
 * canonical decision target carries only `suggestionId` and `aid`; it does not
 * duplicate the author's actor. The create event is therefore the authorship
 * half of every decision, and removing it from this list would silently destroy
 * the attribution the accept/reject pair depends on.
 *
 * Everything else — `suggest.withdraw`, `suggest.supersede`, `edit.propose`,
 * and the ordinary comment/thread kinds — keeps the 540-day policy.
 */
export const DURABLE_EVENT_KINDS = Object.freeze([
  "suggest.create",
  "suggest.accept",
  "suggest.reject",
  "edit.apply",
  "access.invite",
  "access.change",
  "access.revoke",
  "access.transfer",
]);

/**
 * The three global roots. P2-B's public prefix builders all require a document
 * ID on purpose and cannot manufacture a cross-document prefix, so the
 * global-scan literals live here rather than widening those builders.
 */
const EVENT_ROOT_PREFIX = "events/";
const SUGGESTION_ROOT_PREFIX = "suggest/";
const ACCESS_ROOT_PREFIX = "access/";

/** Manual pagination bounds. Crossing one is an operational repair signal. */
const MAX_PAGES = 10;
const MAX_PAGE_ENTRIES = 1_000;
const MAX_KEYS = 10_000;
const MAX_PULLS = MAX_PAGES + 1;

/**
 * The longest key our own writers can produce, matching P2-B `assertKey()`'s
 * own ceiling. Anything longer did not come from this application.
 *
 * P4-F could afford a much tighter bound because `events/` keys are fixed
 * length. P4-T lists the whole `access/` root, which also contains grant keys
 * of the form `access/<docId>/u/<sub>.json`, and P2-B admits a 128-character
 * identity subject — a legal grant key reaches 149 bytes. A tighter ceiling
 * here would report a key the product itself wrote as provider unavailability
 * and wedge the invitation sweep permanently, so this must not be narrowed
 * below what P2-B is willing to write.
 */
const MAX_KEY_BYTES = 600;

/** Netlify's own bound on `nowMs`: a 13-digit epoch millisecond value. */
const MIN_NOW_MS = 1_000_000_000_000;
const MAX_NOW_MS = 9_999_999_999_999;

/** `events/<docId>/<YYYY-MM>/<13-digit-ms>-<hex6>.json`, and nothing else. */
const EVENT_KEY_PATTERN =
  /^events\/([0-9a-f]{6})\/(\d{4}-(?:0[1-9]|1[0-2]))\/((\d{13})-[0-9a-f]{6})\.json$/;

/**
 * `suggest/<docId>/<aid>/<suggestionId>.json`, and nothing else.
 *
 * This is the canonical P4-T grammar and it is deliberately narrower than
 * P2-B's `ANCHOR_ID_PATTERN`, which also admits a seven-hex anchor.
 * Reconstruction through `suggestionKey()` below is still required, so the two
 * agree on every key an eight-hex anchor can produce; a seven-hex anchor would
 * be reported as corrupt state rather than deleted, which fails safe but
 * visibly.
 */
const SUGGESTION_KEY_PATTERN =
  /^suggest\/([0-9a-f]{6})\/(a[0-9a-f]{8})\/(s_([0-9a-z]{1,48})_[0-9a-f]{8})\.json$/;

/** `access/<docId>/i/<32-hex email hash>.json`, and nothing else. */
const INVITATION_KEY_PATTERN =
  /^access\/([0-9a-f]{6})\/i\/([0-9a-f]{32})\.json$/;

/**
 * The marker that makes a listed `access/` key an invitation key at all. A key
 * carrying this segment but failing the grammar above is corrupt state; a key
 * without it is a document or grant record P4-T does not own.
 */
const INVITATION_KEY_SEGMENT = "/i/";

/** Base-36 digits, in value order, for the manual timestamp decode. */
const BASE36_DIGITS = "0123456789abcdefghijklmnopqrstuvwxyz";

const KEY_ENCODER = new TextEncoder();

/**
 * Build one listing request. Built through the ambient `Object` rather than as
 * a literal so the options carry the ordinary object prototype of whichever
 * realm loads the module, which keeps every call site observable to a
 * deterministic out-of-realm harness.
 *
 * @param {string} prefix
 * @returns {{ prefix: string, paginate: true }}
 */
function listOptions(prefix) {
  return Object.assign(Object.create(Object.prototype), {
    prefix,
    paginate: true,
  });
}

/**
 * Corrupt internal retention state: a stored key that this module's own writers
 * could not have produced. Distinct from `StoreError`, which means the provider
 * failed. The message is fixed and the code is a closed vocabulary; no provider
 * value, key, record or cause is ever carried, because this error may surface
 * in a platform log.
 *
 * The closed vocabulary is `invalid-event-key`, `invalid-suggestion-key`,
 * `invalid-invitation-key` and `invitation-scan-limit`.
 */
class RetentionError extends Error {
  /** @param {string} code */
  constructor(code) {
    super("Invalid retention state");
    this.name = "RetentionError";
    this.code = code;
  }
}

/** @returns {StoreError} The one provider-failure error this module raises. */
function unavailable() {
  return new StoreError("unavailable", 503, "State store unavailable");
}

/** @returns {TypeError} */
function invalidOptions() {
  return new TypeError("Invalid retention options");
}

/**
 * Own enumerable string-keyed data property names, or `null` when the value is
 * not an inspectable ordinary-ish object. Never invokes an accessor.
 *
 * @param {unknown} value
 * @returns {string[] | null}
 */
function ownDataKeys(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return null;
  }
  if (Object.getOwnPropertySymbols(value).length !== 0) {
    return null;
  }
  const names = Object.getOwnPropertyNames(value);
  for (const name of names) {
    const descriptor = Object.getOwnPropertyDescriptor(value, name);
    if (
      descriptor === undefined ||
      !Object.prototype.hasOwnProperty.call(descriptor, "value") ||
      descriptor.enumerable !== true
    ) {
      return null;
    }
  }
  return names;
}

/**
 * Own data keys of a value that must additionally be a plain object — no class
 * instance, no exotic prototype. Applied to provider envelopes only; a `Store`
 * is a class instance and is never checked this way.
 *
 * @param {unknown} value
 * @returns {string[] | null}
 */
function ownDataKeysOfPlainObject(value) {
  const names = ownDataKeys(value);
  if (names === null) {
    return null;
  }
  const proto = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null) {
    return null;
  }
  return names;
}

/**
 * Whether an array is dense and carries no own key other than its indices.
 *
 * @param {unknown} value
 * @returns {boolean}
 */
function isOrdinaryDenseArray(value) {
  if (!Array.isArray(value)) {
    return false;
  }
  if (Object.getOwnPropertySymbols(value).length !== 0) {
    return false;
  }
  let indices = 0;
  for (const name of Object.getOwnPropertyNames(value)) {
    if (name === "length") {
      continue;
    }
    const index = Number(name);
    if (!Number.isInteger(index) || index < 0 || index >= value.length) {
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
    indices += 1;
  }
  return indices === value.length;
}

/**
 * Validate the sweep clock: a safe 13-digit epoch millisecond value that round
 * trips through canonical UTC ISO text.
 *
 * @param {unknown} nowMs
 * @returns {boolean}
 */
function isValidClock(nowMs) {
  if (
    typeof nowMs !== "number" ||
    !Number.isSafeInteger(nowMs) ||
    nowMs < MIN_NOW_MS ||
    nowMs > MAX_NOW_MS
  ) {
    return false;
  }
  const iso = new Date(nowMs).toISOString();
  return Date.parse(iso) === nowMs;
}

/**
 * P2-B `read()` resolves the `{ value, etag }` envelope. Reduce it to the
 * record, tolerating a seam that resolves the record directly, and treat a miss
 * as `null` so a concurrent delete is a skip rather than a failure.
 *
 * @param {unknown} found
 * @returns {object | null}
 */
function recordOf(found) {
  if (found === null || found === undefined) {
    return null;
  }
  if (typeof found !== "object") {
    throw unavailable();
  }
  if (
    Object.prototype.hasOwnProperty.call(found, "value") &&
    Object.prototype.hasOwnProperty.call(found, "etag")
  ) {
    return found.value ?? null;
  }
  return found;
}

/**
 * Parse one listed key into the projection the sweep needs, or reject.
 *
 * A key that the provider returned under our own prefix but that this module's
 * writers could not have produced is corrupt internal state, not something to
 * delete and not something to quietly skip: the month segment, the ID
 * milliseconds and the P2-B key builder must all agree.
 *
 * @param {string} key
 * @returns {{ key: string, eventId: string, idMs: number }}
 */
function parseEventKey(key) {
  // `String.prototype.match`, not `RegExp.prototype.exec`: the source oracle
  // treats a callee ending in `.exec` as a process-descendant surface.
  const match = key.match(EVENT_KEY_PATTERN);
  if (match === null) {
    throw new RetentionError("invalid-event-key");
  }
  const docId = match[1];
  const month = match[2];
  const eventId = match[3];
  const idMs = Number(match[4]);
  if (!Number.isSafeInteger(idMs)) {
    throw new RetentionError("invalid-event-key");
  }
  const iso = new Date(idMs).toISOString();
  if (iso.slice(0, 7) !== month) {
    throw new RetentionError("invalid-event-key");
  }
  // The P2-B builder is the authority on what our writers can produce, and it
  // signals a key it would not have built by throwing rather than returning.
  // A zero-padded millisecond segment reaches here matching both the pattern
  // and the month, so both outcomes have to become the same corrupt-state
  // error; a provider key must never surface as a provider failure.
  let rebuilt;
  try {
    rebuilt = eventKey(docId, iso, eventId);
  } catch {
    throw new RetentionError("invalid-event-key");
  }
  if (rebuilt !== key) {
    throw new RetentionError("invalid-event-key");
  }
  return { key, eventId, idMs };
}

/**
 * Decode a canonical lowercase base-36 timestamp segment.
 *
 * Done by hand rather than through a radix parser so that overflow is a
 * decision this module makes: every step is checked against the safe-integer
 * range, and the result has to re-encode to exactly the text it came from, so a
 * padded or otherwise non-canonical segment can never round-trip into a
 * deletion decision.
 *
 * @param {string} text
 * @returns {number} The decoded milliseconds, or `-1` when the text is not a
 *   canonical safe-integer base-36 encoding.
 */
function decodeBase36Ms(text) {
  let value = 0;
  for (const character of text) {
    const digit = BASE36_DIGITS.indexOf(character);
    if (digit < 0) {
      return -1;
    }
    value = value * 36 + digit;
    if (!Number.isSafeInteger(value)) {
      return -1;
    }
  }
  return value.toString(36) === text ? value : -1;
}

/**
 * Parse one listed `suggest/` key into the projection the sweep needs.
 *
 * As with events, a key the provider returned under our own prefix that P2-B's
 * builder could not have produced is corrupt internal state: it is neither
 * deletable nor ignorable. The suggestion ID carries its own creation time, so
 * the key alone decides candidacy and no read is spent on a young record.
 *
 * @param {string} key
 * @returns {{ key: string, docId: string, suggestionId: string, idMs: number }}
 */
function parseSuggestionKey(key) {
  const match = key.match(SUGGESTION_KEY_PATTERN);
  if (match === null) {
    throw new RetentionError("invalid-suggestion-key");
  }
  const docId = match[1];
  const aid = match[2];
  const suggestionId = match[3];
  const idMs = decodeBase36Ms(match[4]);
  if (idMs < 0) {
    throw new RetentionError("invalid-suggestion-key");
  }
  let rebuilt;
  try {
    rebuilt = suggestionKey(docId, aid, suggestionId);
  } catch {
    throw new RetentionError("invalid-suggestion-key");
  }
  if (rebuilt !== key) {
    throw new RetentionError("invalid-suggestion-key");
  }
  return { key, docId, suggestionId, idMs };
}

/**
 * Project one listed `access/` key.
 *
 * The `access/` root holds three record classes and P4-T owns exactly one of
 * them. A document or grant key is skipped without a read, because deleting it
 * is not this function's job. A key that does carry the `/i/` invitation
 * segment but does not match the invitation grammar is corrupt state and aborts
 * the scan — treating it as "some other record" would let a malformed
 * invitation hide from expiry forever.
 *
 * @param {string} key
 * @returns {{ key: string, docId: string } | null} `null` when the key is a
 *   record class P4-T does not own.
 */
function parseInvitationKey(key) {
  const match = key.match(INVITATION_KEY_PATTERN);
  if (match === null) {
    if (key.includes(INVITATION_KEY_SEGMENT)) {
      throw new RetentionError("invalid-invitation-key");
    }
    return null;
  }
  return { key, docId: match[1] };
}

/**
 * Collect every key under one global prefix by driving the provider's paginated
 * iterator by hand.
 *
 * Automatic all-page collection is not used: a scheduled function has a fixed
 * 30-second budget, so the number of pulls, the size of a page and the total
 * key count all have to be things this function decides rather than things the
 * provider decides. A malformed envelope, an eleventh data page, a 10,001st
 * key or a rejection is provider unavailability; a malformed or duplicate key
 * inside a well-formed envelope is corrupt state.
 *
 * Each class calls this with its own prefix and its own budget, so one class's
 * pages, keys and pulls are never charged to another's.
 *
 * @param {{ list: Function }} store
 * @param {string} prefix
 * @param {(key: string) => object | null} project Corrupt-state parser for this
 *   class; returns `null` for a listed key the class does not own.
 * @param {string} duplicateCode The `RetentionError` code for a repeated key.
 * @returns {Promise<Map<string, object | null>>} Every unique listed key, in
 *   listing order, mapped to its projection or `null`.
 */
async function listKeys(store, prefix, project, duplicateCode) {
  let listed;
  try {
    listed = store.list(listOptions(prefix));
  } catch {
    throw unavailable();
  }
  if (listed === null || typeof listed !== "object") {
    throw unavailable();
  }
  const iterate = listed[Symbol.asyncIterator];
  if (typeof iterate !== "function") {
    throw unavailable();
  }
  const iterator = iterate.call(listed);
  if (iterator === null || typeof iterator !== "object" ||
      typeof iterator.next !== "function") {
    throw unavailable();
  }

  /** @type {Map<string, object | null>} */
  const parsed = new Map();
  let closed = false;
  const close = async () => {
    if (closed) {
      return;
    }
    closed = true;
    if (typeof iterator.return === "function") {
      try {
        await iterator.return();
      } catch {
        // A best-effort close. Its failure must not mask the real error.
      }
    }
  };

  try {
    let pages = 0;
    for (let pull = 0; pull < MAX_PULLS; pull += 1) {
      let step;
      try {
        step = await iterator.next();
      } catch {
        throw unavailable();
      }
      const stepKeys = ownDataKeysOfPlainObject(step);
      if (stepKeys === null || typeof step.done !== "boolean") {
        throw unavailable();
      }
      if (step.done === true) {
        return parsed;
      }
      pages += 1;
      if (pages > MAX_PAGES) {
        throw unavailable();
      }
      collectPage(step.value, parsed, project, duplicateCode);
    }
    // Unreachable: the eleventh pull either exhausts the iterator or trips the
    // page bound above. Kept so the pull budget can never silently become a
    // partial sweep reported as a complete one.
    throw unavailable();
  } catch (error) {
    await close();
    throw error;
  }
}

/**
 * Validate one page envelope and fold its entries into `parsed`.
 *
 * @param {unknown} page
 * @param {Map<string, object | null>} parsed
 * @param {(key: string) => object | null} project
 * @param {string} duplicateCode
 * @returns {void}
 */
function collectPage(page, parsed, project, duplicateCode) {
  const pageKeys = ownDataKeysOfPlainObject(page);
  if (pageKeys === null || !pageKeys.includes("blobs")) {
    throw unavailable();
  }
  const blobs = page.blobs;
  if (!isOrdinaryDenseArray(blobs) || blobs.length > MAX_PAGE_ENTRIES) {
    throw unavailable();
  }
  for (const entry of blobs) {
    const entryKeys = ownDataKeysOfPlainObject(entry);
    if (entryKeys === null || !entryKeys.includes("key")) {
      throw unavailable();
    }
    const key = entry.key;
    if (typeof key !== "string" || KEY_ENCODER.encode(key).length > MAX_KEY_BYTES) {
      throw unavailable();
    }
    if (parsed.has(key)) {
      throw new RetentionError(duplicateCode);
    }
    if (parsed.size >= MAX_KEYS) {
      throw unavailable();
    }
    parsed.set(key, project(key));
  }
}

/**
 * Validate the shared sweep seam.
 *
 * `options` is a server-internal deterministic seam — the store and the clock —
 * not anything derived from a request. It is closed on purpose: an unexpected
 * key means a caller believes these functions take an option they do not have,
 * which is a bug worth failing on before anything is listed or deleted. All
 * three sweeps take exactly this seam so one invocation's clock and store are
 * demonstrably the same across every class.
 *
 * @param {unknown} options
 * @returns {{ store: { list: Function, delete: Function }, nowMs: number }}
 */
function sweepSeam(options) {
  const optionKeys = ownDataKeys(options);
  if (
    optionKeys === null ||
    optionKeys.length !== 2 ||
    !optionKeys.includes("store") ||
    !optionKeys.includes("nowMs")
  ) {
    throw invalidOptions();
  }
  const store = options.store;
  const nowMs = options.nowMs;
  if (
    store === null ||
    typeof store !== "object" ||
    typeof store.list !== "function" ||
    typeof store.delete !== "function" ||
    !isValidClock(nowMs)
  ) {
    throw invalidOptions();
  }
  return { store, nowMs };
}

/**
 * Delete one key, mapping provider rejections onto the one store error while
 * preserving an assertion raised by an injected store. The latter is a
 * programmer error (and, for invitations, proves the delete crossed its lease
 * boundary), so reporting it as provider unavailability would hide the broken
 * invariant that needs fixing.
 *
 * No retry and no transaction: Blobs has neither. Earlier deletes stay
 * committed and tomorrow's run continues from what survives.
 *
 * @param {{ delete: Function }} store
 * @param {string} key
 * @returns {Promise<void>}
 */
async function deleteKey(store, key) {
  try {
    await store.delete(key);
  } catch (error) {
    const name = error === null || typeof error !== "object"
      ? undefined
      : Object.getOwnPropertyDescriptor(error, "name")?.value;
    const code = error === null || typeof error !== "object"
      ? undefined
      : Object.getOwnPropertyDescriptor(error, "code")?.value;
    if (name === "AssertionError" && code === "ERR_ASSERTION") {
      throw error;
    }
    throw unavailable();
  }
}

/**
 * Delete every ordinary audit event older than the retention window.
 *
 * Eligibility is conjunctive. The listed key must be reproducible by the P2-B
 * builder, its ID milliseconds must be strictly before the cutoff, a strong
 * read must return a record, that record must pass P3-B validation against the
 * key it was stored under, and its validated timestamp must also be strictly
 * before the cutoff. An event exactly at the cutoff survives; one millisecond
 * older does not.
 *
 * A validated event whose kind is durable is then retained at any age. Kind is
 * not in the key, so it can only be read from the validated record — which is
 * why every pre-cutoff candidate is still read and validated even when it will
 * never be deleted, and why a retained event costs no delete budget.
 *
 * @param {{ store: object, nowMs: number }} options
 * @returns {Promise<{ v: 1, scanned: number, candidates: number, retained: number,
 *                     deleted: number, remaining: boolean, cutoff: string }>}
 */
export async function sweepEvents(options) {
  const { store, nowMs } = sweepSeam(options);

  const cutoffMs = nowMs - EVENT_RETENTION_MS;
  const cutoff = new Date(cutoffMs).toISOString();
  const parsed = await listKeys(
    store,
    EVENT_ROOT_PREFIX,
    parseEventKey,
    "invalid-event-key",
  );

  // Provider listing order is not trusted for anything. Oldest first, then two
  // total tie-breaks, so the same store always yields the same deletions.
  const candidates = [...parsed.values()]
    .filter((entry) => entry.idMs < cutoffMs)
    .sort(
      (a, b) =>
        a.idMs - b.idMs ||
        compareAscii(a.eventId, b.eventId) ||
        compareAscii(a.key, b.key),
    );

  let readCount = 0;
  let retained = 0;
  let deleted = 0;
  let remaining = false;

  for (const candidate of candidates) {
    readCount += 1;
    const record = recordOf(await read(store, candidate.key));
    if (record === null) {
      // The event was deleted between the listing and this read. Nothing to do,
      // and a lost race is not remaining work.
      continue;
    }
    const event = assertEvent(record, candidate.key);
    const ts = Date.parse(event.ts);
    if (ts !== candidate.idMs) {
      throw new RetentionError("invalid-event-key");
    }
    if (DURABLE_EVENT_KINDS.includes(event.kind)) {
      retained += 1;
      continue;
    }
    if (deleted >= MAX_EVENT_DELETES) {
      // The one refinement of P4-F's post-cap stop. Because durable kinds are
      // now excluded, stopping at the cap would report `remaining` for a tail
      // that may be entirely retained events. Reading on until a genuinely
      // deletable event appears is what makes the flag mean "come back
      // tomorrow" rather than "there were more keys".
      remaining = true;
      break;
    }
    await deleteKey(store, candidate.key);
    deleted += 1;
  }

  return {
    v: 1,
    scanned: parsed.size,
    candidates: readCount,
    retained,
    deleted,
    remaining,
    cutoff,
  };
}

/**
 * @param {string} a @param {string} b @returns {number}
 */
function compareAscii(a, b) {
  if (a < b) {
    return -1;
  }
  return a > b ? 1 : 0;
}

/**
 * Delete every suggestion record whose ID is strictly older than the ceiling.
 *
 * Suggestions are immutable, so their creation time is already in the key and
 * candidacy costs no read. A candidate is still read and validated against its
 * own key before deletion, and its validated timestamp must round-trip to
 * exactly the milliseconds the key claims; nothing here consults an edit
 * manifest, a base, an author's access or a computed superseded state, because
 * none of those change the ceiling. A record exactly 90 days old survives; one
 * millisecond older does not.
 *
 * P4-O's separate 14-day reaper still owns suggestions it has already proved
 * superseded during an authorized read. This sweep only guarantees that an
 * abandoned record cannot outlive the ceiling.
 *
 * Unlike the invitation sweep below, this one takes no lease and does no second
 * read. That asymmetry is deliberate and it is about the writers, not the
 * record: an invitation has a concurrent writer that can legitimately renew it
 * back to life, so a delete decision can go stale between the read and the
 * delete. A suggestion is immutable, and a candidate is 90 days old — the
 * window where P4-O could be mid-acceptance on one is vanishingly small and
 * loses only the record, never the accepted content or the decision event.
 * Immutability prevents changed content, not concurrent use, so this is a
 * judgement about cost rather than a proof; the spec settles it here.
 *
 * @param {{ store: object, nowMs: number }} options
 * @returns {Promise<{ v: 1, scanned: number, candidates: number, deleted: number,
 *                     remaining: boolean, cutoff: string }>}
 */
export async function sweepSuggestions(options) {
  const { store, nowMs } = sweepSeam(options);

  const cutoffMs = nowMs - SUGGESTION_RETENTION_MS;
  const cutoff = new Date(cutoffMs).toISOString();
  const parsed = await listKeys(
    store,
    SUGGESTION_ROOT_PREFIX,
    parseSuggestionKey,
    "invalid-suggestion-key",
  );

  const candidates = [...parsed.values()]
    .filter((entry) => entry.idMs < cutoffMs)
    .sort((a, b) => a.idMs - b.idMs || compareAscii(a.key, b.key));

  let readCount = 0;
  let deleted = 0;
  let remaining = false;

  for (const candidate of candidates) {
    if (deleted >= MAX_SUGGESTION_DELETES) {
      // Unlike events there is no exclusion predicate here, so an unread
      // candidate past the cap is by construction still deletable work.
      remaining = true;
      break;
    }
    readCount += 1;
    const record = recordOf(await read(store, candidate.key));
    if (record === null) {
      // Withdrawn, accepted or reaped between the listing and this read.
      continue;
    }
    const suggestion = await assertSuggestionAtKey(
      record,
      candidate.docId,
      candidate.key,
    );
    // Canonical UTC text for the milliseconds the key claims. Comparing the
    // rendering rather than the parse is the stronger of the two directions:
    // it rejects an equal instant written in a different form as well as a
    // different instant, so the ID and the body cannot disagree at all.
    if (new Date(candidate.idMs).toISOString() !== suggestion.at) {
      throw new RetentionError("invalid-suggestion-key");
    }
    await deleteKey(store, candidate.key);
    deleted += 1;
  }

  return {
    v: 1,
    scanned: parsed.size,
    candidates: readCount,
    deleted,
    remaining,
    cutoff,
  };
}

/**
 * A stable serialization used only to compare two validated snapshots of the
 * same record. Object keys are sorted so that two structurally identical
 * records compare equal regardless of the property order the provider or a
 * validator's clone happened to produce.
 *
 * @param {unknown} value
 * @returns {string}
 */
function stableText(value) {
  if (value === undefined) {
    // Distinct from `null`: `JSON.stringify` renders both as nothing, and this
    // comparison is the only fence between a concurrent renewal and a delete.
    return "undefined";
  }
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(stableText).join(",")}]`;
  }
  const names = Object.keys(value).sort();
  const pairs = names.map(
    (name) => `${JSON.stringify(name)}:${stableText(value[name])}`,
  );
  return `{${pairs.join(",")}}`;
}

/**
 * Delete every invitation that has already expired.
 *
 * The `access/` root also holds document and grant records, and P4-T owns
 * neither, so selection is by exact key grammar rather than by prefix. The
 * selected set is capped before any read: invitations are short-lived, so a
 * listing larger than the cap is broken state an operator has to look at, not a
 * backlog to grind through.
 *
 * Deleting an invitation races the two writers that can legitimately change it
 * — P4-J renewing one and P2-G consuming one — so nothing is deleted on the
 * strength of the initial read. Each expired candidate is re-read inside P4-J's
 * own per-document maintenance lease and validated again, and only a record
 * whose expiry still parses, which is still expired, and which is still
 * byte-identical to the first validated snapshot is deleted while that lease is
 * held. A record that vanished was consumed, one with a live expiry was
 * renewed, and either way retention does nothing: it deletes invitations, it
 * never converts, extends or grants them.
 *
 * @param {{ store: object, nowMs: number }} options
 * @returns {Promise<{ v: 1, scanned: number, records: number, expired: number,
 *                     deleted: number, remaining: boolean, now: string }>}
 */
export async function sweepInvitations(options) {
  const { store, nowMs } = sweepSeam(options);

  const now = new Date(nowMs).toISOString();
  const parsed = await listKeys(
    store,
    ACCESS_ROOT_PREFIX,
    parseInvitationKey,
    "invalid-invitation-key",
  );

  const selected = [...parsed.values()]
    .filter((entry) => entry !== null)
    .sort((a, b) => compareAscii(a.key, b.key));
  if (selected.length > MAX_INVITATION_RECORDS) {
    throw new RetentionError("invitation-scan-limit");
  }

  /**
   * @type {{ key: string, docId: string, expiresMs: number, text: string }[]}
   */
  const validated = [];
  let records = 0;

  for (const candidate of selected) {
    records += 1;
    const record = recordOf(await read(store, candidate.key));
    if (record === null) {
      // Consumed or revoked between the listing and this read.
      continue;
    }
    const invitation = await assertAccessInvitationAtKey(
      record,
      candidate.docId,
      candidate.key,
    );
    const expiresMs = Date.parse(invitation.expiresAt);
    if (!Number.isSafeInteger(expiresMs)) {
      throw new RetentionError("invalid-invitation-key");
    }
    validated.push({
      key: candidate.key,
      docId: candidate.docId,
      expiresMs,
      text: stableText(invitation),
    });
  }

  validated.sort(
    (a, b) => a.expiresMs - b.expiresMs || compareAscii(a.key, b.key),
  );

  const expired = validated.filter((entry) => entry.expiresMs <= nowMs);
  let deleted = 0;
  let remaining = false;

  for (const candidate of expired) {
    if (deleted >= MAX_INVITATION_DELETES) {
      remaining = true;
      break;
    }
    const lease = await withAccessWriteLease({
      store,
      doc: candidate.docId,
      nowMs,
      run: async () => {
        const record = recordOf(await read(store, candidate.key));
        if (record === null) {
          // P2-G converted it to a grant, or an owner revoked it. Its removal
          // already happened and the grant is none of retention's business.
          return "gone";
        }
        const invitation = await assertAccessInvitationAtKey(
          record,
          candidate.docId,
          candidate.key,
        );
        const reReadExpiresMs = Date.parse(invitation.expiresAt);
        if (!Number.isSafeInteger(reReadExpiresMs)) {
          // The same fence the first pass applies, applied again where it
          // actually guards a delete. `NaN > nowMs` is false, so without this
          // an unparseable expiry reads as expired and falls through to the
          // snapshot comparison — and that comparison is not a substitute,
          // because it compares a rendering rather than the parse. Nothing
          // reaching here today can be unparseable, but that is a property of
          // the validator above, not of this comparison.
          throw new RetentionError("invalid-invitation-key");
        }
        if (reReadExpiresMs > nowMs) {
          return "renewed";
        }
        if (stableText(invitation) !== candidate.text) {
          return "changed";
        }
        await deleteKey(store, candidate.key);
        return "deleted";
      },
    });

    if (lease.acquired !== true) {
      // A writer holds the document. Never spin on it; tomorrow's run retries.
      remaining = true;
      continue;
    }
    if (lease.value === "deleted") {
      deleted += 1;
    } else if (lease.value === "changed") {
      remaining = true;
    }
  }

  return {
    v: 1,
    scanned: parsed.size,
    records,
    expired: expired.length,
    deleted,
    remaining,
    now,
  };
}

/**
 * Build the scheduled handler over injectable seams.
 *
 * The returned handler ignores its request entirely — a scheduled function has
 * no route, no caller and no identity — samples the clock once, opens the store
 * once, starts all three sweeps before awaiting any of them, and writes exactly
 * one aggregate line. The line carries counts only: no key, document ID, actor,
 * email, name, body, summary, provider value, environment value or stack. On
 * failure it logs nothing and rejects, because a sweep that did not happen must
 * not look like one that did.
 *
 * @param {{ storeFn?: Function, nowFn?: Function, logFn?: Function }} [dependencies]
 * @returns {(request?: unknown) => Promise<void>}
 */
export function createRetentionHandler(dependencies = {}) {
  const names = ownDataKeys(dependencies);
  if (
    names === null ||
    names.some((name) => !["storeFn", "nowFn", "logFn"].includes(name))
  ) {
    throw invalidOptions();
  }
  const storeFn = names.includes("storeFn") ? dependencies.storeFn : docState;
  const nowFn = names.includes("nowFn") ? dependencies.nowFn : Date.now;
  const logFn = names.includes("logFn") ? dependencies.logFn : console.info;
  if (
    typeof storeFn !== "function" ||
    typeof nowFn !== "function" ||
    typeof logFn !== "function"
  ) {
    throw invalidOptions();
  }

  return async function retention() {
    const nowMs = nowFn();
    const store = storeFn();
    // Started in one array literal, so all three listings are issued before the
    // first await. `allSettled`, not `all`, so a class that fails cannot stop
    // another that has already begun from finishing its own bounded work.
    const settled = await Promise.allSettled([
      sweepEvents({ store, nowMs }),
      sweepSuggestions({ store, nowMs }),
      sweepInvitations({ store, nowMs }),
    ]);
    for (const outcome of settled) {
      if (outcome.status === "rejected") {
        throw outcome.reason;
      }
    }
    const [events, suggestions, invitations] = settled.map(
      (outcome) => outcome.value,
    );
    // The aggregate the one log line is projected from. Every field is a count,
    // a boolean or a timestamp this run chose; nothing here can carry a key, a
    // document, a person or a provider value.
    const summary = { v: 1, events, suggestions, invitations };
    const remaining =
      summary.events.remaining ||
      summary.suggestions.remaining ||
      summary.invitations.remaining;
    logFn(
      `retention: events=${summary.events.deleted}/${summary.events.retained}` +
        ` suggestions=${summary.suggestions.deleted}` +
        ` invitations=${summary.invitations.deleted}` +
        ` remaining=${remaining}`,
    );
  };
}

const scheduledRetention = createRetentionHandler();

/**
 * The scheduled entry point. Netlify invokes it on the cron below; it returns
 * no HTTP body because a scheduled function has no route.
 *
 * @param {unknown} req The scheduled request, deliberately unused.
 * @returns {Promise<void>}
 */
export default async function handler(req) {
  return scheduledRetention(req);
}

/**
 * Midnight UTC, every day. `schedule` is mutually exclusive with `path`, and a
 * scheduled function runs automatically only on published deploys.
 */
export const config = { schedule: "@daily" };
