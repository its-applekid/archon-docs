import {
  StoreError,
  assertDocId,
  assertKey,
  docState,
  read,
  upgrade,
} from "./store.mjs";

/**
 * P2-G — the access library.
 *
 * Identity proves who a caller is. This module is the sole authority on what
 * that person may do on one document. Every later gate and API imports
 * `resolveRole()` and projects or enforces its result; none of them may grow a
 * competing role rule.
 *
 * Authority is runtime state, not document content. The first owner is seeded
 * by the site-level `DOC_OWNERS` environment variable and captured once, with a
 * create-only write, into the site-wide `doc-state` store. Later grants and
 * transfers live only in that store. No owner, role, email, or capability
 * claim from a built document, a request, or a client global is authoritative.
 *
 * Storage goes through the P2-B helpers imported above: every record read is a
 * strongly consistent `read()`, every stored record passes `upgrade()` before
 * its domain shape is checked, and the only writes this module performs are
 * `onlyIfNew` creates for the first owner and for an invitation-to-grant
 * conversion. Deletion of a consumed invitation is the one operation P2-B does
 * not wrap.
 *
 * The module emits no console output, embeds no rejected value, key, ETag,
 * environment value, or provider text in a public message, and never places a
 * plain email address in a storage key.
 */

/** @typedef {"owner" | "editor" | "commenter" | "viewer" | "none"} DocumentRole */
/** @typedef {"any" | "own" | "none"} ThreadControl */
/** @typedef {{ sub: string, email: string, name: string, isOrg: boolean }} AccessUser */
/** @typedef {{ sub: string, name: string, email: string }} AccessActor */
/**
 * @typedef {{
 *   v: 1,
 *   docId: string,
 *   ownerSub: string,
 *   ownerEmail: string,
 *   orgDefault: "commenter" | "viewer" | "none",
 *   boundAt: string,
 *   boundFrom: "env:DOC_OWNERS"
 * }} AccessDocument
 */
/**
 * @typedef {{
 *   v: 1,
 *   docId: string,
 *   sub: string,
 *   email: string,
 *   name: string,
 *   role: "editor" | "commenter" | "viewer",
 *   grantedBy: AccessActor,
 *   grantedAt: string,
 *   fromInvitation: string | null
 * }} AccessGrant
 */
/**
 * @typedef {{
 *   v: 1,
 *   docId: string,
 *   email: string,
 *   role: "editor" | "commenter" | "viewer",
 *   invitedBy: AccessActor,
 *   invitedAt: string,
 *   expiresAt: string,
 *   accountCreated: boolean
 * }} AccessInvitation
 */
/**
 * @typedef {{
 *   canRead: boolean,
 *   canComment: boolean,
 *   threadControl: ThreadControl,
 *   canSuggest: boolean,
 *   canEdit: boolean,
 *   canAccept: boolean,
 *   canShare: boolean,
 *   canSeeMembers: boolean
 * }} AccessCapabilities
 */
/** @typedef {{ role: DocumentRole, shared: boolean } & AccessCapabilities} ResolvedAccess */
/**
 * @typedef {{
 *   getWithMetadata(key: string, options: { type: "json", consistency: "strong" }): Promise<null | { data: unknown, etag: string }>,
 *   setJSON(key: string, value: object, options: { onlyIfNew: true }): Promise<{ modified: boolean, etag?: string }>,
 *   delete(key: string): Promise<unknown>
 * }} AccessStore
 */
/**
 * @typedef {{
 *   consumeInvitation?: boolean,
 *   store?: AccessStore,
 *   docOwners?: string,
 *   now?: string
 * }} ResolveOptions
 */

/** Stable, generic public messages. Never embed a rejected value. */
const ERROR_MESSAGES = Object.freeze({
  "invalid-email": "Invalid email address",
  "invalid-sub": "Invalid identity subject",
  "invalid-role": "Invalid document role",
  "invalid-user": "Invalid access user",
  "invalid-option": "Invalid access option",
  "invalid-config": "Invalid DOC_OWNERS configuration",
  "invalid-record": "Invalid access record",
});

const ERROR_STATUSES = Object.freeze({
  "invalid-email": 400,
  "invalid-sub": 400,
  "invalid-role": 400,
  "invalid-user": 500,
  "invalid-option": 500,
  "invalid-config": 500,
  "invalid-record": 500,
});

const STORE_UNAVAILABLE_MESSAGE = "State store unavailable";

const BOUND_FROM = "env:DOC_OWNERS";
const MAX_DOC_OWNERS_BYTES = 5000;
const MAX_EMAIL_LENGTH = 254;
const MAX_NAME_LENGTH = 200;
const INVITATION_LIFETIME_MS = 30 * 24 * 60 * 60 * 1000;

const ASCII_WHITESPACE = /^[ \t\n\r\f\v]+|[ \t\n\r\f\v]+$/g;
const EMAIL_EDGE_WHITESPACE = /^[ \t\n\r\f]+|[ \t\n\r\f]+$/g;
const EMAIL_LOCAL_PATTERN = /^[a-z0-9.!#$%&'*+=?^_`{|}~-]{1,64}$/;
const DNS_LABEL_PATTERN = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const IDENTITY_SUB_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._~-]{0,127}$/;
const INVITATION_HASH_PATTERN = /^[0-9a-f]{32}$/;
const ISO_TIMESTAMP_PATTERN =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

/**
 * The roles an owner may grant, and the organization-wide defaults a document
 * may carry. Exported because `netlify/functions/access.mjs` validates request
 * bodies against exactly these lists, and a second copy declared there would be
 * free to drift away from the record validators below — the defect #125 fixed
 * elsewhere in the deploy tree.
 */
export const GRANTABLE_ROLES = Object.freeze(["editor", "commenter", "viewer"]);
export const ORG_DEFAULTS = Object.freeze(["commenter", "viewer", "none"]);

const USER_KEYS = Object.freeze(["email", "isOrg", "name", "sub"]);
const ACTOR_KEYS = Object.freeze(["email", "name", "sub"]);
const DOCUMENT_KEYS = Object.freeze([
  "boundAt",
  "boundFrom",
  "docId",
  "orgDefault",
  "ownerEmail",
  "ownerSub",
  "v",
]);
const GRANT_KEYS = Object.freeze([
  "docId",
  "email",
  "fromInvitation",
  "grantedAt",
  "grantedBy",
  "name",
  "role",
  "sub",
  "v",
]);
const INVITATION_KEYS = Object.freeze([
  "accountCreated",
  "docId",
  "email",
  "expiresAt",
  "invitedAt",
  "invitedBy",
  "role",
  "v",
]);
const OPTION_KEYS = Object.freeze(["consumeInvitation", "docOwners", "now", "store"]);

/**
 * The access-library error. Carries a stable machine-readable `code`, a stable
 * HTTP `status`, a generic public `message`, and an optional original error as
 * `cause`. Downstream handlers may use `status` but must never serialize the
 * error, its `cause`, or its stack.
 */
export class AccessError extends Error {
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
    this.name = "AccessError";
    this.code = code;
    this.status = status;
  }
}

/**
 * @param {keyof typeof ERROR_MESSAGES} code
 * @param {{ cause?: unknown }} [options]
 * @returns {AccessError}
 */
function accessError(code, options = {}) {
  return new AccessError(code, ERROR_STATUSES[code], ERROR_MESSAGES[code], options);
}

/** @returns {AccessError} */
function invalidRecord() {
  return accessError("invalid-record");
}

/**
 * @param {{ cause?: unknown }} [options]
 * @returns {StoreError}
 */
function storeUnavailable(options = {}) {
  return new StoreError("unavailable", 503, STORE_UNAVAILABLE_MESSAGE, options);
}

/**
 * @param {boolean} canRead
 * @param {boolean} canComment
 * @param {ThreadControl} threadControl
 * @param {boolean} canSuggest
 * @param {boolean} canEdit
 * @param {boolean} canAccept
 * @param {boolean} canShare
 * @param {boolean} canSeeMembers
 * @returns {Readonly<AccessCapabilities>}
 */
function row(
  canRead,
  canComment,
  threadControl,
  canSuggest,
  canEdit,
  canAccept,
  canShare,
  canSeeMembers,
) {
  return Object.freeze({
    canRead,
    canComment,
    threadControl,
    canSuggest,
    canEdit,
    canAccept,
    canShare,
    canSeeMembers,
  });
}

/**
 * The immutable capability matrix. `threadControl` applies equally to resolve
 * and reopen: `"any"` permits any thread, `"own"` requires the thread author's
 * subject to equal the caller's, and `"none"` denies. `canShare` is the one
 * owner-only server check for every access mutation.
 */
export const ROLE_CAPABILITIES = Object.freeze({
  owner: row(true, true, "any", true, true, true, true, true),
  editor: row(true, true, "any", true, true, true, false, true),
  commenter: row(true, true, "own", true, false, false, false, false),
  viewer: row(true, false, "none", false, false, false, false, false),
  none: row(false, false, "none", false, false, false, false, false),
});

/**
 * Return the ASCII-trimmed, lower-case address, or throw `invalid-email`.
 *
 * The grammar is deliberately bounded ASCII: a 1–64 character local part from
 * the unquoted RFC 5322 atom set, exactly one `@`, and a domain of at least two
 * DNS labels of at most 63 alphanumeric-or-hyphen characters each. The result
 * is at most 254 characters. Commas, colons, slashes, backslashes, controls,
 * whitespace, quoted local parts, and non-ASCII spellings are all rejected. No
 * mailbox or DNS lookup is performed.
 *
 * @param {unknown} value
 * @returns {string}
 */
export function normalizeEmail(value) {
  if (typeof value !== "string") {
    throw accessError("invalid-email");
  }
  const trimmed = value.replace(EMAIL_EDGE_WHITESPACE, "");
  if (/[^\x00-\x7f]/.test(trimmed)) {
    throw accessError("invalid-email");
  }
  const normalized = trimmed.toLowerCase();
  if (normalized.length === 0 || normalized.length > MAX_EMAIL_LENGTH) {
    throw accessError("invalid-email");
  }
  const at = normalized.indexOf("@");
  if (at === -1 || normalized.indexOf("@", at + 1) !== -1) {
    throw accessError("invalid-email");
  }
  const local = normalized.slice(0, at);
  const domain = normalized.slice(at + 1);
  if (!EMAIL_LOCAL_PATTERN.test(local)) {
    throw accessError("invalid-email");
  }
  const labels = domain.split(".");
  if (labels.length < 2 || !labels.every((label) => DNS_LABEL_PATTERN.test(label))) {
    throw accessError("invalid-email");
  }
  return normalized;
}

/**
 * Parse the site-level `DOC_OWNERS` value into a fresh map from permanent
 * document ID to normalized seed-owner email.
 *
 * `undefined`, `""`, or ASCII-whitespace-only input is an empty map. Every
 * other malformed form — a non-string, a value above 5000 UTF-8 bytes, an
 * empty pair, a pair without exactly one colon, an invalid document ID, an
 * invalid email, or a repeated document ID — is `invalid-config`. The raw
 * value is never exposed.
 *
 * @param {unknown} value
 * @returns {Map<string, string>}
 */
export function parseDocOwners(value) {
  const owners = new Map();
  if (value === undefined) {
    return owners;
  }
  if (typeof value !== "string") {
    throw accessError("invalid-config");
  }
  if (value.replace(ASCII_WHITESPACE, "") === "") {
    return owners;
  }
  if (new TextEncoder().encode(value).length > MAX_DOC_OWNERS_BYTES) {
    throw accessError("invalid-config");
  }
  for (const rawPair of value.split(",")) {
    const pair = rawPair.replace(ASCII_WHITESPACE, "");
    if (pair === "") {
      throw accessError("invalid-config");
    }
    const segments = pair.split(":");
    if (segments.length !== 2) {
      throw accessError("invalid-config");
    }
    const docId = segments[0].replace(ASCII_WHITESPACE, "");
    let email;
    try {
      assertDocId(docId);
      email = normalizeEmail(segments[1]);
    } catch (error) {
      throw accessError("invalid-config", { cause: error });
    }
    if (owners.has(docId)) {
      throw accessError("invalid-config");
    }
    owners.set(docId, email);
  }
  return owners;
}

/**
 * @param {string} value Already-normalized text.
 * @returns {Promise<string>} The first 32 lower-case hex characters of SHA-256.
 */
async function sha256Prefix(value) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  let hex = "";
  for (const byte of new Uint8Array(digest).subarray(0, 16)) {
    hex += byte.toString(16).padStart(2, "0");
  }
  return hex;
}

/**
 * Normalize an email and return the invitation-key hash: the first 32
 * lower-case hexadecimal characters of the SHA-256 of the normalized UTF-8
 * address. The hash is key hygiene, not secrecy or anonymization; plain
 * addresses remain inside access records. No precomputed hash is accepted.
 *
 * @param {unknown} email
 * @returns {Promise<string>}
 */
export async function emailHash(email) {
  return sha256Prefix(normalizeEmail(email));
}

/**
 * Return the unchanged identity subject, or throw `invalid-sub`. A subject is
 * 1–128 characters matching `^[A-Za-z0-9][A-Za-z0-9._~-]{0,127}$`; it is never
 * trimmed or lowercased, so `/`, `\`, `%`, whitespace, and controls are all
 * rejected before a subject can become a key segment.
 *
 * @param {unknown} sub
 * @returns {string}
 */
export function assertIdentitySub(sub) {
  if (typeof sub !== "string" || !IDENTITY_SUB_PATTERN.test(sub)) {
    throw accessError("invalid-sub");
  }
  return sub;
}

/**
 * @param {unknown} value
 * @returns {boolean} True for an exact `YYYY-MM-DDTHH:mm:ss.sssZ` timestamp
 * that round-trips through `toISOString()`.
 */
function isTimestamp(value) {
  if (typeof value !== "string" || !ISO_TIMESTAMP_PATTERN.test(value)) {
    return false;
  }
  try {
    return new Date(value).toISOString() === value;
  } catch {
    return false;
  }
}

/**
 * @param {unknown} value
 * @param {readonly string[]} expectedKeys Sorted own string keys.
 * @returns {value is Record<string, unknown>} True for a non-null, non-array
 * object with prototype exactly `Object.prototype`, no own symbol keys, and
 * exactly the expected own string keys (enumerable or not).
 */
function hasExactShape(value, expectedKeys) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  if (Object.getPrototypeOf(value) !== Object.prototype) {
    return false;
  }
  if (Object.getOwnPropertySymbols(value).length !== 0) {
    return false;
  }
  const names = Object.getOwnPropertyNames(value);
  if (names.length !== expectedKeys.length) {
    return false;
  }
  return expectedKeys.every((name) => Object.hasOwn(value, name));
}

/**
 * @param {unknown} value
 * @returns {boolean} True for `""` or a non-empty already-normalized email.
 */
function isEmailSnapshot(value) {
  if (typeof value !== "string") {
    return false;
  }
  if (value === "") {
    return true;
  }
  return isNormalizedEmail(value);
}

/**
 * @param {unknown} value
 * @returns {boolean} True for a non-empty email equal to its own normalization.
 */
function isNormalizedEmail(value) {
  if (typeof value !== "string" || value === "") {
    return false;
  }
  try {
    return normalizeEmail(value) === value;
  } catch {
    return false;
  }
}

/**
 * @param {unknown} value
 * @returns {boolean} True for a valid identity subject.
 */
function isIdentitySub(value) {
  try {
    assertIdentitySub(value);
    return true;
  } catch {
    return false;
  }
}

/**
 * @param {unknown} value
 * @returns {boolean} True for a string of at most 200 UTF-16 code units.
 */
function isName(value) {
  return typeof value === "string" && value.length <= MAX_NAME_LENGTH;
}

/**
 * @param {unknown} value
 * @returns {boolean} True for an exact person snapshot: `sub`, `name`, and
 * `email` under the shared scalar contract.
 */
function isActor(value) {
  return (
    hasExactShape(value, ACTOR_KEYS) &&
    isIdentitySub(value.sub) &&
    isName(value.name) &&
    isEmailSnapshot(value.email)
  );
}

/**
 * @param {unknown} docId
 * @param {unknown} expectedDocId
 * @returns {boolean} True when both are the same valid permanent document ID.
 */
function isExpectedDocId(docId, expectedDocId) {
  if (typeof docId !== "string" || docId !== expectedDocId) {
    return false;
  }
  try {
    assertDocId(docId);
    return true;
  } catch {
    return false;
  }
}

/**
 * Validate a stored document access record.
 *
 * Calls P2-B `upgrade()` first and preserves its `StoreError`; then requires
 * exactly the version-1 keys, a matching document ID, a valid `ownerSub`, a
 * non-empty normalized `ownerEmail`, an `orgDefault` of `commenter`, `viewer`,
 * or `none`, an exact `boundAt` timestamp, and `boundFrom` equal to
 * `env:DOC_OWNERS`. Returns the same reference; never repairs or defaults.
 *
 * @param {unknown} value
 * @param {string} expectedDocId
 * @returns {AccessDocument}
 */
export function assertAccessDocument(value, expectedDocId) {
  upgrade(value);
  if (
    !hasExactShape(value, DOCUMENT_KEYS) ||
    !isExpectedDocId(value.docId, expectedDocId) ||
    !isIdentitySub(value.ownerSub) ||
    !isNormalizedEmail(value.ownerEmail) ||
    !ORG_DEFAULTS.includes(value.orgDefault) ||
    !isTimestamp(value.boundAt) ||
    value.boundFrom !== BOUND_FROM
  ) {
    throw invalidRecord();
  }
  return value;
}

/**
 * Validate a stored grant record for one subject.
 *
 * Calls P2-B `upgrade()` first and preserves its `StoreError`; then requires
 * exactly the version-1 keys, a matching document ID and subject, the
 * person-snapshot scalar contract for `email`/`name` and for the nested
 * `grantedBy` actor, a grantable role, an exact `grantedAt` timestamp, and a
 * `fromInvitation` of `null` or 32 lower-case hex characters.
 *
 * @param {unknown} value
 * @param {string} expectedDocId
 * @param {string} expectedSub
 * @returns {AccessGrant}
 */
export function assertAccessGrant(value, expectedDocId, expectedSub) {
  upgrade(value);
  if (
    !hasExactShape(value, GRANT_KEYS) ||
    !isExpectedDocId(value.docId, expectedDocId) ||
    !isIdentitySub(value.sub) ||
    value.sub !== expectedSub ||
    !isEmailSnapshot(value.email) ||
    !isName(value.name) ||
    !GRANTABLE_ROLES.includes(value.role) ||
    !isActor(value.grantedBy) ||
    !isTimestamp(value.grantedAt) ||
    !(
      value.fromInvitation === null ||
      (typeof value.fromInvitation === "string" &&
        INVITATION_HASH_PATTERN.test(value.fromInvitation))
    )
  ) {
    throw invalidRecord();
  }
  return value;
}

/**
 * Validate a stored invitation body.
 *
 * Calls P2-B `upgrade()` first and preserves its `StoreError`; then requires
 * exactly the version-1 keys, a matching document ID, a non-empty normalized
 * `email`, a grantable role, the nested `invitedBy` actor, exact timestamps
 * with `expiresAt` exactly 30 days after `invitedAt`, and a boolean
 * `accountCreated`. This validator is synchronous and proves the body only; it
 * does not compare the email hash with a storage key.
 *
 * @param {unknown} value
 * @param {string} expectedDocId
 * @returns {AccessInvitation}
 */
export function assertAccessInvitation(value, expectedDocId) {
  upgrade(value);
  if (
    !hasExactShape(value, INVITATION_KEYS) ||
    !isExpectedDocId(value.docId, expectedDocId) ||
    !isNormalizedEmail(value.email) ||
    !GRANTABLE_ROLES.includes(value.role) ||
    !isActor(value.invitedBy) ||
    !isTimestamp(value.invitedAt) ||
    !isTimestamp(value.expiresAt) ||
    Date.parse(value.expiresAt) - Date.parse(value.invitedAt) !== INVITATION_LIFETIME_MS ||
    typeof value.accountCreated !== "boolean"
  ) {
    throw invalidRecord();
  }
  return value;
}

/**
 * Validate an invitation together with the storage key it was read from.
 *
 * Runs `assertAccessInvitation()` first. When `expectedEmail` is supplied it
 * must be a non-empty normalized address exactly equal to the body email. The
 * full key must then equal `accessInvitationKey(expectedDocId, value.email)`;
 * a prefix, a bare hash, a differently cased key, a non-string, a body/key
 * hash mismatch, or a supplied-email mismatch is `invalid-record`. No caller
 * may treat the synchronous body validator alone as proof that an invitation
 * came from its key.
 *
 * @param {unknown} value
 * @param {string} expectedDocId
 * @param {unknown} key
 * @param {string} [expectedEmail]
 * @returns {Promise<AccessInvitation>}
 */
export async function assertAccessInvitationAtKey(
  value,
  expectedDocId,
  key,
  expectedEmail = undefined,
) {
  const invitation = assertAccessInvitation(value, expectedDocId);
  if (expectedEmail !== undefined && expectedEmail !== invitation.email) {
    throw invalidRecord();
  }
  if (typeof key !== "string") {
    throw invalidRecord();
  }
  const expectedKey = await accessInvitationKey(expectedDocId, invitation.email);
  if (key !== expectedKey) {
    throw invalidRecord();
  }
  return invitation;
}

/**
 * The document access record key for a document.
 * @param {string} docId @returns {string}
 */
export function accessDocumentKey(docId) {
  return assertKey(`access/${assertDocId(docId)}/doc.json`);
}

/**
 * Grant prefix for a document: `access/<docId>/u/`.
 * @param {string} docId @returns {string}
 */
export function accessGrantPrefix(docId) {
  return assertKey(`access/${assertDocId(docId)}/u/`);
}

/**
 * Grant record key for a document and subject:
 * `access/<docId>/u/<sub>.json`.
 * @param {string} docId @param {string} sub @returns {string}
 */
export function accessGrantKey(docId, sub) {
  assertDocId(docId);
  assertIdentitySub(sub);
  return assertKey(`access/${docId}/u/${sub}.json`);
}

/**
 * Invitation prefix for a document: `access/<docId>/i/`.
 * @param {string} docId @returns {string}
 */
export function accessInvitationPrefix(docId) {
  return assertKey(`access/${assertDocId(docId)}/i/`);
}

/**
 * @param {string} docId An already-validated document ID.
 * @param {string} hash An already-derived 32-hex invitation hash.
 * @returns {string}
 */
function invitationKeyForHash(docId, hash) {
  return assertKey(`access/${docId}/i/${hash}.json`);
}

/**
 * Invitation record key for a document and email:
 * `access/<docId>/i/<emailHash>.json`. The email is normalized and hashed
 * here; a raw address or a precomputed hash is never a key segment.
 * @param {string} docId @param {string} email @returns {Promise<string>}
 */
export async function accessInvitationKey(docId, email) {
  assertDocId(docId);
  return invitationKeyForHash(docId, await emailHash(email));
}

/**
 * Return a fresh plain object holding exactly the eight capabilities of one
 * role, or throw `invalid-role`. The shared frozen row is never returned.
 *
 * @param {unknown} role
 * @returns {AccessCapabilities}
 */
export function capabilitiesFor(role) {
  if (typeof role !== "string" || !Object.hasOwn(ROLE_CAPABILITIES, role)) {
    throw accessError("invalid-role");
  }
  return { ...ROLE_CAPABILITIES[role] };
}

/** The exact keys of one resolved access row: the two identity fields, then
 * the eight capabilities in matrix order. */
const ACCESS_ROW_KEYS = Object.freeze([
  "role",
  "shared",
  "canRead",
  "canComment",
  "threadControl",
  "canSuggest",
  "canEdit",
  "canAccept",
  "canShare",
  "canSeeMembers",
]);

const ACCESS_CAPABILITY_KEYS = Object.freeze(ACCESS_ROW_KEYS.slice(2));
const ACCESS_ROLES = Object.freeze(Object.keys(ROLE_CAPABILITIES));
const THREAD_CONTROLS = Object.freeze(["any", "own", "none"]);

/**
 * `hasExactShape()` plus two further requirements: every own property is an
 * enumerable *data* property, and the own keys appear in exactly
 * `expectedKeys` order. An accessor is rejected without being invoked, so a
 * getter can never be read once and then differ from what the caller later
 * observes. Order is checked because a resolved access row is always built by
 * spreading the frozen capability matrix onto `role` and `shared`, so any row
 * whose keys arrive in another order was assembled by something other than
 * `resolveRole()` — and three of the seven hand copies this function replaced
 * asserted that (#125, #128).
 *
 * @param {unknown} value
 * @param {readonly string[]} expectedKeys
 * @returns {boolean}
 */
function hasExactOrderedDataShape(value, expectedKeys) {
  if (!hasExactShape(value, expectedKeys)) {
    return false;
  }
  const names = Object.getOwnPropertyNames(value);
  return expectedKeys.every((key, index) => {
    if (names[index] !== key) {
      return false;
    }
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    return Object.hasOwn(descriptor, "value") && descriptor.enumerable === true;
  });
}

/**
 * Is `result` a complete, internally consistent resolved access row?
 *
 * This is the single definition of that question. Every path that resolves a
 * role shares it rather than keeping its own copy: a hand-duplicated security
 * validator only has to drift in one file to open a hole the other copies
 * still close, and whichever copy no gate happens to exercise is the one that
 * drifts (#125). The four copies that outlived #125 proved the point —
 * `pending.mjs`'s had already grown a key-order requirement the others lacked,
 * and `events.mjs`'s had diverged far enough to be named `assertResolvedAccess`
 * and so escape the acceptance grep entirely (#128).
 *
 * A partial, extended, accessor-backed, array, non-ordinary-prototype, or
 * internally inconsistent object is invalid — never a falsy capability. The
 * caller decides what an invalid row means; here it is only ever `false`.
 *
 * `capabilityTable` is a parameter rather than the module's own
 * `capabilitiesFor` so that `edit.mjs` and `pending.mjs`, whose closed
 * factories receive the table as an injected dependency, validate against the
 * table they were actually given. A table that throws, or that answers with
 * anything other than the eight capability keys as ordinary enumerable data
 * properties in matrix order, is itself invalid.
 *
 * @param {unknown} result
 * @param {(role: unknown) => unknown} capabilityTable
 * @returns {boolean}
 */
export function validateAccessRow(result, capabilityTable) {
  if (!hasExactOrderedDataShape(result, ACCESS_ROW_KEYS)) {
    return false;
  }
  if (!ACCESS_ROLES.includes(result.role) || typeof result.shared !== "boolean") {
    return false;
  }
  for (const key of ACCESS_CAPABILITY_KEYS) {
    const value = result[key];
    if (key === "threadControl") {
      if (!THREAD_CONTROLS.includes(value)) {
        return false;
      }
    } else if (typeof value !== "boolean") {
      return false;
    }
  }
  let expected;
  try {
    expected = capabilityTable(result.role);
  } catch {
    return false;
  }
  if (!hasExactOrderedDataShape(expected, ACCESS_CAPABILITY_KEYS)) {
    return false;
  }
  return ACCESS_CAPABILITY_KEYS.every((key) => expected[key] === result[key]);
}

/**
 * @param {DocumentRole} role
 * @param {boolean} shared
 * @returns {ResolvedAccess}
 */
function resolved(role, shared) {
  return { role, shared, ...capabilitiesFor(role) };
}

/**
 * @param {unknown} options
 * @returns {void}
 */
function validateOptions(options) {
  if (options === null || typeof options !== "object" || Array.isArray(options)) {
    throw accessError("invalid-option");
  }
  if (Object.getPrototypeOf(options) !== Object.prototype) {
    throw accessError("invalid-option");
  }
  if (Object.getOwnPropertySymbols(options).length !== 0) {
    throw accessError("invalid-option");
  }
  for (const name of Object.getOwnPropertyNames(options)) {
    if (!OPTION_KEYS.includes(name)) {
      throw accessError("invalid-option");
    }
  }
  if (
    Object.hasOwn(options, "consumeInvitation") &&
    typeof options.consumeInvitation !== "boolean"
  ) {
    throw accessError("invalid-option");
  }
  if (Object.hasOwn(options, "docOwners") && typeof options.docOwners !== "string") {
    throw accessError("invalid-option");
  }
  if (Object.hasOwn(options, "now") && !isTimestamp(options.now)) {
    throw accessError("invalid-option");
  }
  if (Object.hasOwn(options, "store")) {
    const { store } = options;
    if (
      store === null ||
      typeof store !== "object" ||
      typeof store.getWithMetadata !== "function" ||
      typeof store.setJSON !== "function" ||
      typeof store.delete !== "function"
    ) {
      throw accessError("invalid-option");
    }
  }
}

/**
 * Validate a non-null server user and return its retained normalized email.
 * A bad subject keeps `assertIdentitySub()`'s narrower error; every other
 * malformed user, including an email that fails normalization, is
 * `invalid-user`.
 *
 * @param {unknown} user
 * @returns {string} The normalized email, or `""` for a degraded identity.
 */
function validateUser(user) {
  if (!hasExactShape(user, USER_KEYS)) {
    throw accessError("invalid-user");
  }
  assertIdentitySub(user.sub);
  if (!isName(user.name) || typeof user.isOrg !== "boolean" || typeof user.email !== "string") {
    throw accessError("invalid-user");
  }
  if (user.email === "") {
    return "";
  }
  try {
    return normalizeEmail(user.email);
  } catch (error) {
    throw accessError("invalid-user", { cause: error });
  }
}

/**
 * Read the seed-owner value for this invocation. An Edge Function exposes the
 * Functions-scoped site variable through `Netlify.env`; a Node Function
 * exposes it through `process.env`. Nothing is cached across invocations.
 *
 * @returns {unknown}
 */
function runtimeDocOwners() {
  const env = globalThis.Netlify?.env;
  if (env !== undefined && env !== null && typeof env.get === "function") {
    return globalThis.Netlify.env.get("DOC_OWNERS");
  }
  return globalThis.process?.env?.DOC_OWNERS;
}

/**
 * Perform one create-only write and report whether it was applied.
 *
 * A thrown provider error becomes `StoreError` `unavailable` with the original
 * error as `cause`. A resolved result is valid only when it is a non-null,
 * non-array object with an own boolean `modified`; anything else is
 * `unavailable` without a cause, even if the provider may have committed the
 * write, so a later caller reconciles from strongly read state.
 *
 * @param {AccessStore} store
 * @param {string} key
 * @param {object} record An already-validated record.
 * @returns {Promise<boolean>} The own boolean `modified`.
 */
async function createOnly(store, key, record) {
  let result;
  try {
    result = await store.setJSON(key, record, { onlyIfNew: true });
  } catch (error) {
    throw storeUnavailable({ cause: error });
  }
  if (result === null || typeof result !== "object" || Array.isArray(result)) {
    throw storeUnavailable();
  }
  const descriptor = Object.getOwnPropertyDescriptor(result, "modified");
  if (
    descriptor === undefined ||
    !Object.hasOwn(descriptor, "value") ||
    typeof descriptor.value !== "boolean"
  ) {
    throw storeUnavailable();
  }
  return descriptor.value;
}

/**
 * Delete a consumed invitation. Called only after a valid grant is durable; a
 * thrown or ambiguous delete is `unavailable` and the next consuming call
 * retries the delete without rewriting the grant.
 *
 * @param {AccessStore} store
 * @param {string} key
 * @returns {Promise<void>}
 */
async function deleteInvitation(store, key) {
  try {
    await store.delete(key);
  } catch (error) {
    throw storeUnavailable({ cause: error });
  }
}

/**
 * Read and validate the caller's live invitation, if any.
 *
 * @param {AccessStore} store
 * @param {string} docId
 * @param {string} key The caller's exact invitation key.
 * @param {string} email The retained normalized caller email.
 * @param {string} now The one sampled invocation time.
 * @returns {Promise<AccessInvitation | null>} The invitation when it exists
 * and `expiresAt` is later than `now`; otherwise `null`. An expired record is
 * left unchanged.
 */
async function liveInvitation(store, docId, key, email, now) {
  const found = await read(store, key);
  if (found.value === null) {
    return null;
  }
  const invitation = await assertAccessInvitationAtKey(found.value, docId, key, email);
  if (Date.parse(invitation.expiresAt) <= Date.parse(now)) {
    return null;
  }
  return invitation;
}

/**
 * Resolve one caller's role and capabilities on one document.
 *
 * Precedence is exact and is the only role precedence in the platform:
 *
 * ```text
 * bound ownerSub
 *   > explicit grant by sub
 *   > live invitation by normalized proven email
 *   > orgDefault for isOrg
 *   > none
 * ```
 *
 * A null user, an absent document record, an unset seed, a missing grant, a
 * missing invitation, and an expired invitation all resolve to a result.
 * Invalid input, malformed configuration or stored state, and provider
 * failures reject with the documented `AccessError` / `StoreError` so a
 * caller can fail closed instead of reporting an outage as a denial.
 *
 * With the default `consumeInvitation: false` the call performs no write.
 * With `consumeInvitation: true` a live invitation is converted grant-first
 * and deleted second, and an existing grant is preserved while its redundant
 * invitation is removed.
 *
 * @param {string} docId
 * @param {AccessUser | null} user
 * @param {ResolveOptions} [options]
 * @returns {Promise<ResolvedAccess>}
 */
export async function resolveRole(docId, user, options = {}) {
  assertDocId(docId);
  validateOptions(options);
  const email = user === null ? "" : validateUser(user);

  const now = options.now ?? new Date().toISOString();

  if (user === null) {
    return resolved("none", false);
  }

  const consume = options.consumeInvitation === true;
  const store = Object.hasOwn(options, "store") ? options.store : docState();
  const documentKey = accessDocumentKey(docId);

  const foundDocument = await read(store, documentKey);
  let document =
    foundDocument.value === null ? null : assertAccessDocument(foundDocument.value, docId);

  let shared = document !== null;
  let orgDefault = document === null ? "commenter" : document.orgDefault;

  if (document === null) {
    const owners = parseDocOwners(
      Object.hasOwn(options, "docOwners") ? options.docOwners : runtimeDocOwners(),
    );
    const seedEmail = owners.get(docId);
    if (seedEmail !== undefined) {
      shared = true;
      if (email !== "" && email === seedEmail) {
        const candidate = assertAccessDocument(
          {
            v: 1,
            docId,
            ownerSub: user.sub,
            ownerEmail: email,
            orgDefault: "commenter",
            boundAt: now,
            boundFrom: BOUND_FROM,
          },
          docId,
        );
        if (await createOnly(store, documentKey, candidate)) {
          document = candidate;
        } else {
          const winner = await read(store, documentKey);
          if (winner.value === null) {
            throw invalidRecord();
          }
          document = assertAccessDocument(winner.value, docId);
        }
        orgDefault = document.orgDefault;
      }
    }
  }

  if (document !== null) {
    if (document.ownerSub === user.sub) {
      return resolved("owner", true);
    }

    const grantKey = accessGrantKey(docId, user.sub);
    const foundGrant = await read(store, grantKey);
    let grant =
      foundGrant.value === null ? null : assertAccessGrant(foundGrant.value, docId, user.sub);

    if (grant !== null) {
      if (consume && email !== "") {
        const invitationKey = invitationKeyForHash(docId, await sha256Prefix(email));
        const invitation = await liveInvitation(store, docId, invitationKey, email, now);
        if (invitation !== null) {
          await deleteInvitation(store, invitationKey);
        }
      }
      return resolved(grant.role, true);
    }

    if (email !== "") {
      const hash = await sha256Prefix(email);
      const invitationKey = invitationKeyForHash(docId, hash);
      const invitation = await liveInvitation(store, docId, invitationKey, email, now);
      if (invitation !== null) {
        if (!consume) {
          return resolved(invitation.role, true);
        }
        const candidate = assertAccessGrant(
          {
            v: 1,
            docId,
            sub: user.sub,
            email,
            name: user.name,
            role: invitation.role,
            grantedBy: {
              sub: invitation.invitedBy.sub,
              name: invitation.invitedBy.name,
              email: invitation.invitedBy.email,
            },
            grantedAt: now,
            fromInvitation: hash,
          },
          docId,
          user.sub,
        );
        if (await createOnly(store, grantKey, candidate)) {
          grant = candidate;
        } else {
          const existing = await read(store, grantKey);
          if (existing.value === null) {
            throw invalidRecord();
          }
          grant = assertAccessGrant(existing.value, docId, user.sub);
        }
        await deleteInvitation(store, invitationKey);
        return resolved(grant.role, true);
      }
    }
  }

  if (user.isOrg) {
    return resolved(orgDefault, shared);
  }
  return resolved("none", shared);
}
