/**
 * P3-H/P4-J — the access API.
 *
 * `GET /api/access?doc=<docId>` returns the owner-visible roster (P3-H).
 * `POST`, `PATCH`, and `DELETE /api/access` plus `POST /api/access/transfer`
 * are the owner-only write surface (P4-J).
 *
 * Every mutation verifies origin, derives its actor from the server session,
 * requires P2-G `resolveRole()` to report `owner` with `shared` and
 * `canShare`, and then serializes its cross-key decisions behind one
 * per-document lease stored at the private key `access/<doc>/write.json`.
 * Runtime grants in `doc-state` are the only authority: never Identity roles,
 * committed metadata, or client state.
 *
 * State writes precede audit. There is no transaction across blobs, Identity,
 * email, and events: a successful state change is never rolled back because
 * an event append failed, and a crash can honestly leave a real access change
 * with no audit event. The coordinator's recovery and transfer markers make
 * account bootstrap and ownership transfer resumable; they never promise
 * audit repair.
 */

import { admin, requestPasswordRecovery } from "@netlify/identity";
import { randomBytes } from "node:crypto";
import { identify, isOrgEmail, requireOrigin } from "../lib/identity.mjs";
import {
  AccessError,
  accessDocumentKey,
  accessGrantKey,
  accessGrantPrefix,
  accessInvitationKey,
  accessInvitationPrefix,
  assertAccessDocument,
  assertAccessGrant,
  assertAccessInvitationAtKey,
  assertIdentitySub,
  capabilitiesFor,
  GRANTABLE_ROLES,
  normalizeEmail,
  ORG_DEFAULTS,
  resolveRole,
  validateAccessRow,
} from "../lib/access.mjs";
import { docState, mutate, read, StoreError } from "../lib/store.mjs";
import { appendEvent } from "./events.mjs";

const NO_STORE = { "Cache-Control": "private, no-store" };
const JSON_HEADERS = Object.freeze({
  "Content-Type": "application/json; charset=utf-8",
  ...NO_STORE,
});

const IDENTITY_KEYS = Object.freeze(["sub", "email", "name", "isOrg"]);
const DOC_ID_PATTERN = /^[0-9a-f]{6}$/;
const INVITATION_HASH_PATTERN = /^[0-9a-f]{32}$/;
const LEASE_ID_PATTERN = /^[0-9a-f]{32}$/;
const MAX_PAGES = 52;
const MAX_KEYS = 50;
const MAX_PAGE_ENTRIES = 1_000;
const MAX_KEY_BYTES = 600;

const MAX_BODY_BYTES = 8_192;
const LEASE_MS = 120_000;
const INVITATION_LIFETIME_MS = 30 * 24 * 60 * 60 * 1000;
const INVITE_WINDOW_MS = 60 * 60 * 1000;
const MAX_LIVE_INVITES = 10;
const MIN_NOW_MS = 1_000_000_000_000;
const MAX_NOW_MS = 9_999_999_999_999;
const IDENTITY_PAGE_SIZE = 100;
const MAX_IDENTITY_PAGES = 100;
const PASSWORD_BYTES = 32;
const LEASE_ID_BYTES = 16;

const BASE_PATH = "/api/access";
const TRANSFER_PATH = "/api/access/transfer";
const BASE_ALLOW = "GET, POST, PATCH, DELETE";
const TRANSFER_ALLOW = "POST";

const RECOVERY_PHASES = Object.freeze([
  "invitation-pending",
  "account-create-requested",
  "recovery-required",
  "recovery-sent",
]);
const TRANSFER_PHASES = Object.freeze([
  "owner-pending",
  "owner-committed",
  "target-grant-removed",
]);

const WRITE_RECORD_KEYS = Object.freeze([
  "v", "docId", "epoch", "lease", "recovery", "transfer",
]);
const LEASE_KEYS = Object.freeze(["id", "holder", "acquiredAt", "expiresAt"]);
const ACTOR_KEYS = Object.freeze(["sub", "name", "email"]);
const RECOVERY_KEYS = Object.freeze([
  "invitationKey", "email", "role", "invitedBy", "invitedAt", "expiresAt",
  "phase", "accountSub",
]);
const TRANSFER_KEYS = Object.freeze([
  "fromOwner", "toOwner", "targetGrant", "at", "phase",
]);
const TRANSFER_TARGET_KEYS = Object.freeze(["sub", "email"]);
const LEASE_OPTION_KEYS = Object.freeze(["store", "doc", "nowMs", "run"]);

const DEPENDENCY_KEYS = Object.freeze([
  "requireOriginFn", "identifyFn", "resolveRoleFn", "storeFn", "appendEventFn",
  "listUsersFn", "createUserFn", "requestPasswordRecoveryFn", "randomBytesFn",
  "nowFn",
]);

/** The closed request-body variants, keyed by `<METHOD> <pathname>`. */
const BODY_VARIANTS = Object.freeze({
  "POST /api/access": Object.freeze([Object.freeze(["doc", "email", "role"])]),
  "PATCH /api/access": Object.freeze([
    Object.freeze(["doc", "sub", "role"]),
    Object.freeze(["doc", "email", "role"]),
    Object.freeze(["doc", "orgDefault"]),
  ]),
  "DELETE /api/access": Object.freeze([
    Object.freeze(["doc", "sub"]),
    Object.freeze(["doc", "email"]),
  ]),
  "POST /api/access/transfer": Object.freeze([Object.freeze(["doc", "sub"])]),
});

const BASE64URL_ALPHABET =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/* ------------------------------------------------------------------ *
 * Shared descriptor helpers (P3-H).
 * ------------------------------------------------------------------ */

function ownDataDescriptor(object, key) {
  const descriptor = Object.getOwnPropertyDescriptor(object, key);
  if (descriptor === undefined ||
      !Object.prototype.hasOwnProperty.call(descriptor, "value") ||
      descriptor.enumerable !== true) {
    return null;
  }
  return descriptor;
}

function isExactPlainDataObject(value, keys, requireMutable) {
  if (value === null || typeof value !== "object" || Array.isArray(value) ||
      Object.getPrototypeOf(value) !== Object.prototype ||
      Object.getOwnPropertySymbols(value).length !== 0) {
    return false;
  }
  const names = Object.getOwnPropertyNames(value);
  if (names.length !== keys.length || !keys.every((key, index) => names[index] === key)) {
    return false;
  }
  return keys.every((key) => {
    const descriptor = ownDataDescriptor(value, key);
    return descriptor !== null && (!requireMutable ||
      (descriptor.writable === true && descriptor.configurable === true));
  });
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype &&
    Object.getOwnPropertySymbols(value).length === 0;
}

function dataDescriptorsOnly(value) {
  return isPlainObject(value) && Object.getOwnPropertyNames(value).every((key) => {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    return Object.prototype.hasOwnProperty.call(descriptor, "value");
  });
}

/** An unordered exact-key plain object whose properties are all data slots. */
function isUnorderedPlainDataObject(value, keys) {
  if (!dataDescriptorsOnly(value)) {
    return false;
  }
  const names = Object.getOwnPropertyNames(value);
  return names.length === keys.length && keys.every((key) => names.includes(key));
}

function isDenseArray(value) {
  if (!Array.isArray(value) || Object.getOwnPropertySymbols(value).length !== 0) return false;
  const names = Object.getOwnPropertyNames(value);
  if (names.length !== value.length + 1 || names.at(-1) !== "length") return false;
  for (let index = 0; index < value.length; index += 1) {
    if (names[index] !== String(index) || ownDataDescriptor(value, String(index)) === null) return false;
  }
  return true;
}

function utf8Length(value) {
  let bytes = 0;
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit <= 0x7f) bytes += 1;
    else if (unit <= 0x7ff) bytes += 2;
    else if (unit >= 0xd800 && unit <= 0xdbff && index + 1 < value.length &&
             value.charCodeAt(index + 1) >= 0xdc00 && value.charCodeAt(index + 1) <= 0xdfff) {
      bytes += 4;
      index += 1;
    } else bytes += 3;
  }
  return bytes;
}

function inheritedDataMethod(value, key) {
  if (value === null || (typeof value !== "object" && typeof value !== "function")) return null;
  let cursor = value;
  while (cursor !== null) {
    const descriptor = Object.getOwnPropertyDescriptor(cursor, key);
    if (descriptor !== undefined) {
      return Object.prototype.hasOwnProperty.call(descriptor, "value") &&
        typeof descriptor.value === "function" ? descriptor.value : null;
    }
    cursor = Object.getPrototypeOf(cursor);
  }
  return null;
}

/** A stable canonical serialization used only for exact record comparison. */
function canonical(value) {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value) ?? "null";
  }
  if (Array.isArray(value)) {
    return `[${value.map((entry) => canonical(entry)).join(",")}]`;
  }
  const names = Object.keys(value).sort();
  return `{${names.map((name) => `${JSON.stringify(name)}:${canonical(value[name])}`).join(",")}}`;
}

function isTimestamp(value) {
  if (typeof value !== "string") return false;
  const parsed = Date.parse(value);
  return Number.isSafeInteger(parsed) && new Date(parsed).toISOString() === value;
}

function hexOf(bytes, size) {
  if (!(bytes instanceof Uint8Array) || bytes.length !== size) {
    throw new TypeError("Invalid random bytes");
  }
  let hex = "";
  for (const byte of bytes) {
    hex += byte.toString(16).padStart(2, "0");
  }
  return hex;
}

function base64url(bytes) {
  let out = "";
  for (let index = 0; index < bytes.length; index += 3) {
    const first = bytes[index];
    const second = bytes[index + 1];
    const third = bytes[index + 2];
    out += BASE64URL_ALPHABET[first >> 2];
    if (second === undefined) {
      out += BASE64URL_ALPHABET[(first & 0b11) << 4];
      break;
    }
    out += BASE64URL_ALPHABET[((first & 0b11) << 4) | (second >> 4)];
    if (third === undefined) {
      out += BASE64URL_ALPHABET[(second & 0b1111) << 2];
      break;
    }
    out += BASE64URL_ALPHABET[((second & 0b1111) << 2) | (third >> 6)];
    out += BASE64URL_ALPHABET[third & 0b111111];
  }
  return out;
}

/* ------------------------------------------------------------------ *
 * The public error boundary.
 * ------------------------------------------------------------------ */

/**
 * One mapped public failure. Never carries a rejected value, a provider
 * payload, or a cause that could be serialized into a response.
 */
class AccessHttpError extends Error {
  constructor(status, code, headers = undefined) {
    super("Access request failed");
    this.name = "AccessHttpError";
    this.status = status;
    this.code = code;
    this.extraHeaders = headers;
  }
}

function httpError(status, code, headers) {
  return new AccessHttpError(status, code, headers);
}

const invalidRequest = () => httpError(400, "invalid-request");
const unauthenticated = () => httpError(401, "unauthenticated");
const forbidden = () => httpError(403, "forbidden");
const notFound = () => httpError(404, "not-found");
const conflict = () => httpError(409, "conflict");
const accessBusy = () => httpError(409, "access-busy", { "Retry-After": "2" });
const recoveryPending = () => httpError(409, "recovery-pending");
const memberLimit = () => httpError(409, "member-limit");
const inviteRateLimit = () =>
  httpError(429, "invite-rate-limit", { "Retry-After": "3600" });
const internalError = () => httpError(500, "internal-error");
const unavailable = () => httpError(503, "unavailable");

function isStoreCode(error, code) {
  if (!(error instanceof StoreError)) return false;
  const descriptor = Object.getOwnPropertyDescriptor(error, "code");
  return descriptor !== undefined &&
    Object.prototype.hasOwnProperty.call(descriptor, "value") &&
    descriptor.value === code;
}

function isUnavailable(error) {
  try {
    if (!(error instanceof StoreError)) return false;
    const name = ownDataDescriptor(error, "name");
    const code = ownDataDescriptor(error, "code");
    const status = ownDataDescriptor(error, "status");
    return name !== null && code !== null && status !== null &&
      name.value === "StoreError" && code.value === "unavailable" && status.value === 503;
  } catch {
    return false;
  }
}

/** Map any thrown value to its exact public response. */
function classify(error) {
  if (error instanceof AccessHttpError) {
    return error;
  }
  if (isStoreCode(error, "unavailable")) {
    return unavailable();
  }
  if (isStoreCode(error, "conflict")) {
    return conflict();
  }
  return internalError();
}

function emptyResponse(status, headers = NO_STORE) {
  return new Response(null, { status, headers });
}

function errorResponse(error) {
  const mapped = classify(error);
  const headers = mapped.extraHeaders === undefined
    ? { ...JSON_HEADERS }
    : { ...JSON_HEADERS, ...mapped.extraHeaders };
  return new Response(JSON.stringify({ error: mapped.code }), {
    status: mapped.status,
    headers,
  });
}

function noContentResponse() {
  return new Response(null, { status: 204, headers: { ...NO_STORE } });
}

/* ------------------------------------------------------------------ *
 * P3-H roster reading, shared with every mutation.
 * ------------------------------------------------------------------ */

function validateIdentity(value) {
  if (!isExactPlainDataObject(value, IDENTITY_KEYS, true)) throw new TypeError("Invalid identity");
  const sub = ownDataDescriptor(value, "sub").value;
  const email = ownDataDescriptor(value, "email").value;
  const name = ownDataDescriptor(value, "name").value;
  const isOrg = ownDataDescriptor(value, "isOrg").value;
  if (typeof sub !== "string" || typeof email !== "string" ||
      typeof name !== "string" || typeof isOrg !== "boolean" ||
      isOrg !== isOrgEmail(email) || assertIdentitySub(sub) !== sub) {
    throw new TypeError("Invalid identity");
  }
  return value;
}

/**
 * Both consumers of a resolved access row here -- the P3-H read path and the
 * write path's `authorize()` -- ask the library's shared question rather than
 * a private copy of it. `validateAccessRow()` (#132) is the single definition
 * of "is this row complete, ordinary and internally consistent"; a second copy
 * in this file would be free to drift away from it, which is the defect #125
 * fixed elsewhere in the deploy tree. Only the failure shape is local: an
 * invalid row is a server-side fault here, never a falsy capability.
 */
function validateAccess(value) {
  if (!validateAccessRow(value, capabilitiesFor)) {
    throw new TypeError("Invalid access result");
  }
  return value;
}

function iteratorResult(result) {
  if (!dataDescriptorsOnly(result)) throw new TypeError("Invalid iterator result");
  const done = ownDataDescriptor(result, "done");
  if (done === null || typeof done.value !== "boolean") {
    throw new TypeError("Invalid iterator result");
  }
  if (done.value) return { done: true, value: undefined };
  const value = ownDataDescriptor(result, "value");
  if (value === null) throw new TypeError("Invalid iterator result");
  return { done: false, value: value.value };
}

function pageKeys(page) {
  if (!dataDescriptorsOnly(page)) throw new TypeError("Invalid list page");
  const blobs = ownDataDescriptor(page, "blobs");
  const directories = ownDataDescriptor(page, "directories");
  if (blobs === null || directories === null || !isDenseArray(blobs.value) ||
      blobs.value.length > MAX_PAGE_ENTRIES || !isDenseArray(directories.value) ||
      directories.value.length !== 0) throw new TypeError("Invalid list page");
  return blobs.value.map((entry) => {
    if (!dataDescriptorsOnly(entry)) throw new TypeError("Invalid list entry");
    const key = ownDataDescriptor(entry, "key");
    if (key === null || key.writable !== true || key.configurable !== true ||
        typeof key.value !== "string" || utf8Length(key.value) > MAX_KEY_BYTES) {
      throw new TypeError("Invalid list entry");
    }
    return key.value;
  });
}

async function collectKeys(store, prefixes) {
  const keys = [];
  const seen = new Set();
  let pages = 0;
  for (const prefix of prefixes) {
    const options = Object.fromEntries([["prefix", prefix], ["paginate", true]]);
    const listing = store.list(options);
    const iteratorMethod = inheritedDataMethod(listing, Symbol.asyncIterator);
    if (iteratorMethod === null) throw new TypeError("Invalid list iterator");
    const iterator = iteratorMethod.call(listing);
    const next = inheritedDataMethod(iterator, "next");
    if (next === null) throw new TypeError("Invalid list iterator");
    while (true) {
      const result = iteratorResult(await next.call(iterator));
      if (result.done) break;
      pages += 1;
      if (pages > MAX_PAGES) throw new TypeError("Too many list pages");
      for (const key of pageKeys(result.value)) {
        if (seen.has(key)) throw new TypeError("Duplicate list key");
        seen.add(key);
        keys.push({ key, prefix });
        if (keys.length > MAX_KEYS) throw new TypeError("Too many list keys");
      }
    }
  }
  return keys;
}

function classifyKey(docId, entry, grantPrefix, invitationPrefix) {
  const { key, prefix } = entry;
  if (!key.startsWith(prefix) || !key.endsWith(".json")) throw new TypeError("Invalid child key");
  const middle = key.slice(prefix.length, -5);
  if (prefix === grantPrefix) {
    if (middle.length === 0 || assertIdentitySub(middle) !== middle ||
        accessGrantKey(docId, middle) !== key) throw new TypeError("Invalid grant key");
    return { key, kind: "grant", sub: middle };
  }
  if (prefix !== invitationPrefix || !INVITATION_HASH_PATTERN.test(middle)) {
    throw new TypeError("Invalid invitation key");
  }
  return { key, kind: "invitation" };
}

function readValue(result) {
  if (!isExactPlainDataObject(result, ["value", "etag"], false)) {
    throw new TypeError("Invalid read result");
  }
  const value = ownDataDescriptor(result, "value").value;
  const etag = ownDataDescriptor(result, "etag").value;
  if ((value === null && etag !== null) ||
      (value !== null && (typeof etag !== "string" || etag.length === 0))) {
    throw new TypeError("Invalid read result");
  }
  return value;
}

/**
 * Read and validate the complete access document plus both child prefixes.
 *
 * This is P3-H's exact traversal: one document hit, two prefixes with
 * explicit pagination, at most 52 combined pages and 50 combined child keys,
 * a strong read per present child, and a duplicate-email check across the
 * owner and every non-redundant grant. The redundant owner grant is validated
 * and counted but is never an actionable target.
 */
async function loadRoster(store, docId) {
  const documentValue = readValue(await read(store, accessDocumentKey(docId)));
  if (documentValue === null) throw new TypeError("Missing access document");
  const document = assertAccessDocument(documentValue, docId);
  if (document !== documentValue) throw new TypeError("Invalid document validation result");

  const grantPrefix = accessGrantPrefix(docId);
  const invitationPrefix = accessInvitationPrefix(docId);
  const listed = await collectKeys(store, [grantPrefix, invitationPrefix]);
  const children = listed.map((entry) => classifyKey(docId, entry, grantPrefix, invitationPrefix));
  const results = await Promise.all(children.map(({ key }) => read(store, key)));
  const grants = [];
  const invitations = [];
  for (let index = 0; index < children.length; index += 1) {
    const child = children[index];
    const value = readValue(results[index]);
    if (value === null) continue;
    if (child.kind === "grant") {
      const grant = assertAccessGrant(value, docId, child.sub);
      if (grant !== value) throw new TypeError("Invalid grant validation result");
      grants.push({ key: child.key, record: grant });
    } else {
      const invitation = await assertAccessInvitationAtKey(value, docId, child.key);
      if (invitation !== value) throw new TypeError("Invalid invitation validation result");
      invitations.push({ key: child.key, record: invitation });
    }
  }

  const members = grants.filter(({ record }) => record.sub !== document.ownerSub);
  const emails = new Set([document.ownerEmail]);
  for (const member of members) {
    if (emails.has(member.record.email)) throw new TypeError("Duplicate member email");
    emails.add(member.record.email);
  }
  return { document, grants, invitations, members, emails };
}

/* ------------------------------------------------------------------ *
 * The write coordinator record.
 * ------------------------------------------------------------------ */

function assertMarkerActor(value) {
  if (!isUnorderedPlainDataObject(value, ACTOR_KEYS) ||
      typeof value.name !== "string" || value.name.length > 200) {
    throw new TypeError("Invalid coordinator actor");
  }
  let sub;
  let email;
  try {
    sub = assertIdentitySub(value.sub);
    email = normalizeEmail(value.email);
  } catch {
    throw new TypeError("Invalid coordinator actor");
  }
  if (email !== value.email) throw new TypeError("Invalid coordinator actor");
  return { sub, name: value.name, email };
}

function assertLease(value) {
  if (!isUnorderedPlainDataObject(value, LEASE_KEYS)) {
    throw new TypeError("Invalid write lease");
  }
  if (typeof value.id !== "string" || !LEASE_ID_PATTERN.test(value.id) ||
      !isTimestamp(value.acquiredAt) || !isTimestamp(value.expiresAt) ||
      Date.parse(value.expiresAt) - Date.parse(value.acquiredAt) !== LEASE_MS) {
    throw new TypeError("Invalid write lease");
  }
  const holder = value.holder;
  let validHolder;
  if (isUnorderedPlainDataObject(holder, ["kind", "sub"]) && holder.kind === "owner") {
    let sub;
    try {
      sub = assertIdentitySub(holder.sub);
    } catch {
      throw new TypeError("Invalid write lease");
    }
    validHolder = { kind: "owner", sub };
  } else if (isUnorderedPlainDataObject(holder, ["kind"]) && holder.kind === "retention") {
    validHolder = { kind: "retention" };
  } else {
    throw new TypeError("Invalid write lease");
  }
  return {
    id: value.id,
    holder: validHolder,
    acquiredAt: value.acquiredAt,
    expiresAt: value.expiresAt,
  };
}

function assertRecoveryMarker(value, docId) {
  if (!isUnorderedPlainDataObject(value, RECOVERY_KEYS)) {
    throw new TypeError("Invalid recovery marker");
  }
  let email;
  try {
    email = normalizeEmail(value.email);
  } catch {
    throw new TypeError("Invalid recovery marker");
  }
  const prefix = `access/${docId}/i/`;
  if (email !== value.email ||
      typeof value.invitationKey !== "string" ||
      !value.invitationKey.startsWith(prefix) ||
      !value.invitationKey.endsWith(".json") ||
      !INVITATION_HASH_PATTERN.test(
        value.invitationKey.slice(prefix.length, -".json".length),
      ) ||
      !GRANTABLE_ROLES.includes(value.role) ||
      !isTimestamp(value.invitedAt) || !isTimestamp(value.expiresAt) ||
      Date.parse(value.expiresAt) - Date.parse(value.invitedAt) !== INVITATION_LIFETIME_MS ||
      !RECOVERY_PHASES.includes(value.phase)) {
    throw new TypeError("Invalid recovery marker");
  }
  const invitedBy = assertMarkerActor(value.invitedBy);
  const early = value.phase === "invitation-pending" ||
    value.phase === "account-create-requested";
  let accountSub = null;
  if (early) {
    if (value.accountSub !== null) throw new TypeError("Invalid recovery marker");
  } else {
    try {
      accountSub = assertIdentitySub(value.accountSub);
    } catch {
      throw new TypeError("Invalid recovery marker");
    }
  }
  return {
    invitationKey: value.invitationKey,
    email,
    role: value.role,
    invitedBy,
    invitedAt: value.invitedAt,
    expiresAt: value.expiresAt,
    phase: value.phase,
    accountSub,
  };
}

function assertTransferMarker(value, docId) {
  if (!isUnorderedPlainDataObject(value, TRANSFER_KEYS) ||
      !isTimestamp(value.at) || !TRANSFER_PHASES.includes(value.phase)) {
    throw new TypeError("Invalid transfer marker");
  }
  const fromOwner = assertMarkerActor(value.fromOwner);
  if (!isUnorderedPlainDataObject(value.toOwner, TRANSFER_TARGET_KEYS)) {
    throw new TypeError("Invalid transfer marker");
  }
  let toSub;
  let toEmail;
  try {
    toSub = assertIdentitySub(value.toOwner.sub);
    toEmail = normalizeEmail(value.toOwner.email);
  } catch {
    throw new TypeError("Invalid transfer marker");
  }
  if (toEmail !== value.toOwner.email || toSub === fromOwner.sub) {
    throw new TypeError("Invalid transfer marker");
  }
  let grant;
  try {
    grant = assertAccessGrant(value.targetGrant, docId, toSub);
  } catch {
    throw new TypeError("Invalid transfer marker");
  }
  if (grant.email !== toEmail) throw new TypeError("Invalid transfer marker");
  return {
    fromOwner,
    toOwner: { sub: toSub, email: toEmail },
    targetGrant: {
      v: grant.v,
      docId: grant.docId,
      sub: grant.sub,
      email: grant.email,
      name: grant.name,
      role: grant.role,
      grantedBy: {
        sub: grant.grantedBy.sub,
        name: grant.grantedBy.name,
        email: grant.grantedBy.email,
      },
      grantedAt: grant.grantedAt,
      fromInvitation: grant.fromInvitation,
    },
    at: value.at,
    phase: value.phase,
  };
}

/**
 * Validate the complete private coordinator record and return a fresh copy.
 *
 * The record is private to this file: it is outside P3-H's `u/` and `i/`
 * prefixes, is neither a person nor a grant nor an invitation, and is
 * excluded from the 50-child count.
 */
function assertAccessWriteRecord(value, docId, key) {
  if (typeof key !== "string" || key !== writeCoordinatorKey(docId)) {
    throw new TypeError("Invalid write record key");
  }
  if (!isUnorderedPlainDataObject(value, WRITE_RECORD_KEYS) ||
      value.v !== 1 || value.docId !== docId ||
      !Number.isSafeInteger(value.epoch) || value.epoch < 0) {
    throw new TypeError("Invalid write record");
  }
  const lease = value.lease === null ? null : assertLease(value.lease);
  const recovery = value.recovery === null
    ? null
    : assertRecoveryMarker(value.recovery, docId);
  const transfer = value.transfer === null
    ? null
    : assertTransferMarker(value.transfer, docId);
  if (recovery !== null && transfer !== null) {
    throw new TypeError("Invalid write record");
  }
  return { v: 1, docId, epoch: value.epoch, lease, recovery, transfer };
}

function writeCoordinatorKey(docId) {
  if (typeof docId !== "string" || !DOC_ID_PATTERN.test(docId)) {
    throw new TypeError("Invalid document id");
  }
  return `access/${docId}/write.json`;
}

function initialWriteRecord(docId) {
  return { v: 1, docId, epoch: 0, lease: null, recovery: null, transfer: null };
}

function withLease(record, lease) {
  return {
    v: 1,
    docId: record.docId,
    epoch: record.epoch,
    lease,
    recovery: record.recovery,
    transfer: record.transfer,
  };
}

/* ------------------------------------------------------------------ *
 * The exported maintenance lease (P4-T only).
 * ------------------------------------------------------------------ */

function assertLeaseStore(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError("Invalid access lease options");
  }
  for (const method of ["getWithMetadata", "setJSON"]) {
    if (inheritedDataMethod(value, method) === null) {
      throw new TypeError("Invalid access lease options");
    }
  }
  return value;
}

/**
 * Run one maintenance callback under this document's write coordinator.
 *
 * The sole non-HTTP boundary, used only by P4-T so its final invitation
 * re-read and delete cannot race a concurrently renewed invitation. No
 * request value can reach it: it is never called from the handler.
 *
 * @param {{ store: object, doc: string, nowMs: number, run: () => unknown }} options
 * @returns {Promise<{ acquired: false } | { acquired: true, value: unknown }>}
 */
export async function withAccessWriteLease(options) {
  if (!isUnorderedPlainDataObject(options, LEASE_OPTION_KEYS)) {
    throw new TypeError("Invalid access lease options");
  }
  const { store: rawStore, doc, nowMs, run } = options;
  if (typeof doc !== "string" || !DOC_ID_PATTERN.test(doc) ||
      !Number.isSafeInteger(nowMs) || nowMs < MIN_NOW_MS || nowMs > MAX_NOW_MS ||
      typeof run !== "function") {
    throw new TypeError("Invalid access lease options");
  }
  const store = assertLeaseStore(rawStore);

  const key = writeCoordinatorKey(doc);
  const leaseId = hexOf(randomBytes(LEASE_ID_BYTES), LEASE_ID_BYTES);
  const acquiredAt = new Date(nowMs).toISOString();
  const expiresAt = new Date(nowMs + LEASE_MS).toISOString();

  const acquired = await mutate(store, key, initialWriteRecord(doc), (draft) => {
    const record = assertAccessWriteRecord(draft, doc, key);
    if (record.lease !== null && record.lease.expiresAt > acquiredAt) {
      return null;
    }
    if (!Number.isSafeInteger(record.epoch + 1)) {
      throw new TypeError("Write coordinator epoch overflow");
    }
    return withLease(
      { ...record, epoch: record.epoch + 1 },
      { id: leaseId, holder: { kind: "retention" }, acquiredAt, expiresAt },
    );
  });
  if (acquired.changed !== true) {
    return { acquired: false };
  }
  const epoch = acquired.value.epoch;

  let value;
  let primary = null;
  try {
    value = await run();
  } catch (error) {
    primary = error;
  }
  try {
    await releaseLease(store, doc, key, leaseId, epoch);
  } catch (error) {
    if (primary === null) {
      throw error;
    }
  }
  if (primary !== null) {
    throw primary;
  }
  return { acquired: true, value };
}

/** Clear only a lease whose ID and epoch match this holder's token. */
function releaseLease(store, doc, key, leaseId, epoch) {
  return mutate(store, key, initialWriteRecord(doc), (draft) => {
    const record = assertAccessWriteRecord(draft, doc, key);
    if (record.lease === null || record.lease.id !== leaseId || record.epoch !== epoch) {
      return null;
    }
    return withLease(record, null);
  });
}

/* ------------------------------------------------------------------ *
 * Request parsing.
 * ------------------------------------------------------------------ */

function mediaTypeIsJson(req) {
  const header = req.headers.get("content-type");
  if (header === null) return false;
  return header.split(";", 1)[0].trim().toLowerCase() === "application/json";
}

/**
 * Read at most 8,192 body bytes through one reader with fatal UTF-8 decoding.
 * Resolves `{ text }` or `{ status }`; the lock is released exactly once and
 * the stream is canceled only on overflow.
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
      } catch {
        return { status: 400 };
      }
      if (result === null || typeof result !== "object") {
        return { status: 400 };
      }
      if (result.done === true) break;
      const chunk = result.value;
      if (!(chunk instanceof Uint8Array)) {
        return { status: 400 };
      }
      total += chunk.byteLength;
      if (total > MAX_BODY_BYTES) {
        try {
          await reader.cancel();
        } catch {
          // The overflow verdict stands even when cancellation rejects.
        }
        return { status: 413 };
      }
      try {
        text += decoder.decode(chunk, { stream: true });
      } catch {
        return { status: 400 };
      }
    }
    try {
      text += decoder.decode();
    } catch {
      return { status: 400 };
    }
    return { text };
  } finally {
    reader.releaseLock();
  }
}

/** Validate exactly one closed body variant for the route and method. */
function parseVariant(routeKey, text) {
  if (text.length === 0) throw invalidRequest();
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw invalidRequest();
  }
  if (!isPlainObject(parsed)) throw invalidRequest();
  const names = Object.getOwnPropertyNames(parsed);
  for (const name of names) {
    const descriptor = Object.getOwnPropertyDescriptor(parsed, name);
    if (!Object.prototype.hasOwnProperty.call(descriptor, "value")) throw invalidRequest();
  }
  const variants = BODY_VARIANTS[routeKey];
  const matched = variants.find((keys) =>
    keys.length === names.length && keys.every((key) => names.includes(key)));
  if (matched === undefined) throw invalidRequest();

  const body = { keys: matched };
  if (typeof parsed.doc !== "string" || !DOC_ID_PATTERN.test(parsed.doc)) {
    throw invalidRequest();
  }
  body.doc = parsed.doc;
  if (matched.includes("sub")) {
    try {
      body.sub = assertIdentitySub(parsed.sub);
    } catch {
      throw invalidRequest();
    }
  }
  if (matched.includes("email")) {
    if (typeof parsed.email !== "string") throw invalidRequest();
    let normalized;
    try {
      normalized = normalizeEmail(parsed.email);
    } catch {
      throw invalidRequest();
    }
    if (normalized !== parsed.email) throw invalidRequest();
    body.email = normalized;
  }
  if (matched.includes("role")) {
    if (!GRANTABLE_ROLES.includes(parsed.role)) throw invalidRequest();
    body.role = parsed.role;
  }
  if (matched.includes("orgDefault")) {
    if (!ORG_DEFAULTS.includes(parsed.orgDefault)) throw invalidRequest();
    body.orgDefault = parsed.orgDefault;
  }
  return body;
}

/* ------------------------------------------------------------------ *
 * The handler factory.
 * ------------------------------------------------------------------ */

function assertDependencies(dependencies) {
  if (!isPlainObject(dependencies)) {
    throw new TypeError("Invalid access dependencies");
  }
  const names = Object.getOwnPropertyNames(dependencies);
  for (const name of names) {
    if (!DEPENDENCY_KEYS.includes(name)) {
      throw new TypeError("Invalid access dependencies");
    }
    const descriptor = Object.getOwnPropertyDescriptor(dependencies, name);
    if (!Object.prototype.hasOwnProperty.call(descriptor, "value") ||
        typeof descriptor.value !== "function") {
      throw new TypeError("Invalid access dependencies");
    }
  }
  return names;
}

/**
 * Build the access handler from a closed dependency object.
 *
 * Only the ten documented callables may be supplied and each result crosses
 * the same predecessor validation as the production import would. Request
 * data can never select a dependency, and injecting a write dependency does
 * not make `GET` touch it.
 *
 * @param {object} [dependencies]
 * @returns {(req: Request) => Promise<Response>}
 */
export function createAccessHandler(dependencies = {}) {
  const names = assertDependencies(dependencies);
  const pick = (name, fallback) =>
    names.includes(name) ? dependencies[name] : fallback;

  const requireOriginFn = pick("requireOriginFn", requireOrigin);
  const identifyFn = pick("identifyFn", identify);
  const resolveRoleFn = pick("resolveRoleFn", resolveRole);
  const storeFn = pick("storeFn", docState);
  const appendEventFn = pick("appendEventFn", (options) => appendEvent(options));
  const listUsersFn = pick("listUsersFn", (options) => admin.listUsers(options));
  const createUserFn = pick("createUserFn", (options) => admin.createUser(options));
  const requestPasswordRecoveryFn = pick(
    "requestPasswordRecoveryFn",
    (email) => requestPasswordRecovery(email),
  );
  const randomBytesFn = pick("randomBytesFn", (size) => randomBytes(size));
  const nowFn = pick("nowFn", () => Date.now());

  function openStore() {
    let store;
    try {
      store = storeFn();
    } catch {
      throw unavailable();
    }
    if (store === null || typeof store !== "object") throw internalError();
    return store;
  }

  /* ---------------- P3-H GET ---------------- */

  async function handleGet(req) {
    try {
      const identified = await identifyFn(req);
      if (identified === null) return emptyResponse(401);
      const user = validateIdentity(identified);
      const documents = new URL(req.url).searchParams.getAll("doc");
      if (documents.length !== 1 || !DOC_ID_PATTERN.test(documents[0])) return emptyResponse(400);
      const docId = documents[0];
      const access = validateAccess(await resolveRoleFn(docId, user));
      if (access.canSeeMembers !== true) return emptyResponse(403);

      const store = storeFn();
      const { document, invitations, members } = await loadRoster(store, docId);
      const now = new Date().toISOString();
      const roster = members.map(({ record }) => record);
      roster.sort((left, right) => left.email < right.email ? -1 : left.email > right.email ? 1 :
        left.sub < right.sub ? -1 : left.sub > right.sub ? 1 : 0);
      const pending = invitations.map(({ record }) => record);
      pending.sort((left, right) => left.email < right.email ? -1 : left.email > right.email ? 1 : 0);
      const body = {
        doc: docId,
        orgDefault: document.orgDefault,
        members: [
          { sub: document.ownerSub, email: document.ownerEmail, name: "", role: "owner" },
          ...roster.map(({ sub, email, name, role }) => ({ sub, email, name, role })),
        ],
        invitations: pending.filter(({ expiresAt }) => expiresAt > now)
          .map(({ email, role, expiresAt }) => ({ email, role, expiresAt })),
      };
      return new Response(JSON.stringify(body), {
        status: 200,
        headers: { "Content-Type": "application/json; charset=utf-8", ...NO_STORE },
      });
    } catch (error) {
      return emptyResponse(isUnavailable(error) ? 503 : 500);
    }
  }

  /* ---------------- mutation prologue ---------------- */

  async function verifyOrigin(req) {
    try {
      requireOriginFn(req);
    } catch (error) {
      if (error instanceof Response) {
        const headers = new Headers(error.headers);
        headers.set("Cache-Control", "private, no-store");
        const text = await error.text();
        return new Response(text, { status: error.status, headers });
      }
      throw internalError();
    }
    return null;
  }

  function requireNoQuery(req) {
    let url;
    try {
      url = new URL(req.url);
    } catch {
      throw invalidRequest();
    }
    let count = 0;
    for (const entry of url.searchParams) {
      void entry;
      count += 1;
    }
    if (count !== 0) throw invalidRequest();
  }

  async function authorize(user, doc) {
    let resolved;
    try {
      resolved = await resolveRoleFn(doc, user);
    } catch (error) {
      throw classifyAccessLibrary(error);
    }
    const access = validateAccess(resolved);
    if (access.role !== "owner" || access.shared !== true || access.canShare !== true) {
      throw forbidden();
    }
    return access;
  }

  function classifyAccessLibrary(error) {
    if (isStoreCode(error, "unavailable")) return unavailable();
    if (error instanceof AccessError) return internalError();
    return classify(error);
  }

  /* ---------------- coordinator ---------------- */

  async function acquireLease(ctx) {
    const key = ctx.writeKey;
    const leaseId = hexOf(randomBytesFn(LEASE_ID_BYTES), LEASE_ID_BYTES);
    const expiresAt = new Date(ctx.nowMs + LEASE_MS).toISOString();
    const result = await mutate(ctx.store, key, initialWriteRecord(ctx.doc), (draft) => {
      const record = assertAccessWriteRecord(draft, ctx.doc, key);
      if (record.lease !== null && record.lease.expiresAt > ctx.now) {
        throw accessBusy();
      }
      if (!Number.isSafeInteger(record.epoch + 1)) {
        throw internalError();
      }
      return withLease(
        { ...record, epoch: record.epoch + 1 },
        {
          id: leaseId,
          holder: { kind: "owner", sub: ctx.actor.sub },
          acquiredAt: ctx.now,
          expiresAt,
        },
      );
    });
    ctx.leaseId = leaseId;
    ctx.epoch = result.value.epoch;
    ctx.coordinator = assertAccessWriteRecord(result.value, ctx.doc, key);
  }

  /** Mutate the coordinator under the captured lease token. */
  async function updateCoordinator(ctx, change) {
    const key = ctx.writeKey;
    const result = await mutate(ctx.store, key, initialWriteRecord(ctx.doc), (draft) => {
      const record = assertAccessWriteRecord(draft, ctx.doc, key);
      if (record.lease === null || record.lease.id !== ctx.leaseId ||
          record.epoch !== ctx.epoch) {
        throw conflict();
      }
      const next = change(record);
      if (next === null) return null;
      return next;
    });
    ctx.coordinator = assertAccessWriteRecord(result.value, ctx.doc, key);
  }

  function setRecovery(ctx, recovery) {
    return updateCoordinator(ctx, (record) => ({
      v: 1,
      docId: record.docId,
      epoch: record.epoch,
      lease: record.lease,
      recovery,
      transfer: record.transfer,
    }));
  }

  function setTransfer(ctx, transfer) {
    return updateCoordinator(ctx, (record) => ({
      v: 1,
      docId: record.docId,
      epoch: record.epoch,
      lease: record.lease,
      recovery: record.recovery,
      transfer,
    }));
  }

  /* ---------------- fences ---------------- */

  function requireLeaseToken(ctx) {
    if (typeof ctx.leaseId !== "string" || !LEASE_ID_PATTERN.test(ctx.leaseId) ||
        !Number.isSafeInteger(ctx.epoch)) {
      throw internalError();
    }
  }

  function freshDocument(document) {
    return {
      v: document.v,
      docId: document.docId,
      ownerSub: document.ownerSub,
      ownerEmail: document.ownerEmail,
      orgDefault: document.orgDefault,
      boundAt: document.boundAt,
      boundFrom: document.boundFrom,
    };
  }

  /**
   * Revalidate the actor's ownership through a conditional rewrite of the
   * byte-equivalent access document immediately before a state commit.
   */
  async function ownerFence(ctx) {
    requireLeaseToken(ctx);
    const key = accessDocumentKey(ctx.doc);
    await mutate(ctx.store, key, null, (draft) => {
      if (draft === null) throw internalError();
      const document = assertAccessDocument(draft, ctx.doc);
      if (document.ownerSub !== ctx.actor.sub) throw forbidden();
      return freshDocument(document);
    });
  }

  /** The post-transfer fence: the document must already name the new owner. */
  async function transferFence(ctx, toOwnerSub) {
    requireLeaseToken(ctx);
    const key = accessDocumentKey(ctx.doc);
    await mutate(ctx.store, key, null, (draft) => {
      if (draft === null) throw internalError();
      const document = assertAccessDocument(draft, ctx.doc);
      if (document.ownerSub !== toOwnerSub) throw conflict();
      return freshDocument(document);
    });
  }

  /* ---------------- events ---------------- */

  async function attemptEvent(ctx, kind, target, summary) {
    try {
      await appendEventFn({
        store: ctx.store,
        docId: ctx.doc,
        actor: ctx.actor,
        kind,
        target,
        docVersion: null,
        summary,
      });
    } catch (error) {
      throw classify(error);
    }
  }

  /* ---------------- inventory ---------------- */

  async function inventory(ctx) {
    let roster;
    try {
      roster = await loadRoster(ctx.store, ctx.doc);
    } catch (error) {
      if (isUnavailable(error)) throw unavailable();
      throw internalError();
    }
    if (roster.document.ownerSub !== ctx.actor.sub) throw forbidden();
    return roster;
  }

  function childCount(roster) {
    return roster.grants.length + roster.invitations.length;
  }

  function liveInvitations(roster, now) {
    return roster.invitations.filter(({ record }) => record.expiresAt > now);
  }

  /* ---------------- compare-and-delete ---------------- */

  /**
   * P2-B exposes no conditional delete and a tombstone would violate P2-G's
   * closed schemas, so a deletion is a fenced read/compare/delete/read-back
   * with no awaited provider operation between the comparison and the delete.
   */
  async function compareAndDelete(ctx, key, snapshot, validateFresh, allowAbsent = false) {
    let current;
    try {
      current = readValue(await read(ctx.store, key));
    } catch (error) {
      if (isUnavailable(error)) throw unavailable();
      throw internalError();
    }
    if (current === null) {
      if (allowAbsent) return "absent";
      throw conflict();
    }
    let fresh;
    try {
      fresh = await validateFresh(current);
    } catch (error) {
      if (error instanceof AccessHttpError) throw error;
      throw internalError();
    }
    if (canonical(fresh) !== canonical(snapshot)) throw conflict();

    try {
      await ctx.store.delete(key);
    } catch {
      throw unavailable();
    }
    let readback;
    try {
      readback = readValue(await read(ctx.store, key));
    } catch (error) {
      if (isUnavailable(error)) throw unavailable();
      throw internalError();
    }
    if (readback !== null) throw unavailable();
    return "deleted";
  }

  /* ---------------- Identity ---------------- */

  function validateProviderUser(value, expectedEmail) {
    if (value === null || typeof value !== "object" || Array.isArray(value) ||
        Object.getOwnPropertySymbols(value).length !== 0) {
      throw internalError();
    }
    for (const name of Object.getOwnPropertyNames(value)) {
      const descriptor = Object.getOwnPropertyDescriptor(value, name);
      if (!Object.prototype.hasOwnProperty.call(descriptor, "value")) throw internalError();
    }
    const id = Object.getOwnPropertyDescriptor(value, "id");
    const email = Object.getOwnPropertyDescriptor(value, "email");
    for (const descriptor of [id, email]) {
      if (descriptor === undefined ||
          !Object.prototype.hasOwnProperty.call(descriptor, "value") ||
          descriptor.enumerable !== true || descriptor.writable !== true ||
          descriptor.configurable !== true || typeof descriptor.value !== "string") {
        throw internalError();
      }
    }
    let sub;
    let normalized;
    try {
      sub = assertIdentitySub(id.value);
      normalized = normalizeEmail(email.value);
    } catch {
      throw internalError();
    }
    if (normalized !== email.value) throw internalError();
    if (expectedEmail !== undefined && normalized !== expectedEmail) throw internalError();
    return { sub, email: normalized };
  }

  function validateUserPage(value) {
    if (!isDenseArray(value) || Object.getPrototypeOf(value) !== Array.prototype ||
        value.length > IDENTITY_PAGE_SIZE) {
      throw internalError();
    }
    return value;
  }

  /**
   * Determine whether exactly one canonical account exists for one address.
   *
   * Scanning continues past a match so a duplicate normalized email is proved
   * malformed provider state rather than silently accepted. Reaching the page
   * ceiling without a short terminating page is `unavailable`, because
   * completeness is unproven. No user is logged or returned to the client.
   */
  async function findAccount(email) {
    const subjects = new Set();
    const emails = new Set();
    let match = null;
    for (let page = 1; page <= MAX_IDENTITY_PAGES; page += 1) {
      let users;
      try {
        users = await listUsersFn({ page, perPage: IDENTITY_PAGE_SIZE });
      } catch {
        throw unavailable();
      }
      const list = validateUserPage(users);
      for (const entry of list) {
        const user = validateProviderUser(entry);
        if (subjects.has(user.sub) || emails.has(user.email)) throw internalError();
        subjects.add(user.sub);
        emails.add(user.email);
        if (user.email === email) match = user.sub;
      }
      if (list.length < IDENTITY_PAGE_SIZE) {
        return match;
      }
    }
    throw unavailable();
  }

  async function createAccount(email) {
    const password = base64url(assertRandomBytes(randomBytesFn(PASSWORD_BYTES), PASSWORD_BYTES));
    let created;
    try {
      created = await createUserFn({ email, password, data: { role: "guest" } });
    } catch {
      throw unavailable();
    }
    return validateProviderUser(created, email).sub;
  }

  async function requestRecovery(email) {
    try {
      await requestPasswordRecoveryFn(email);
    } catch {
      throw unavailable();
    }
  }

  /* ---------------- invitation creation ---------------- */

  function buildInvitation(docId, marker) {
    return {
      v: 1,
      docId,
      email: marker.email,
      role: marker.role,
      invitedBy: {
        sub: marker.invitedBy.sub,
        name: marker.invitedBy.name,
        email: marker.invitedBy.email,
      },
      invitedAt: marker.invitedAt,
      expiresAt: marker.expiresAt,
      accountCreated: false,
    };
  }

  /**
   * Make the exact phase-derived invitation present, or report that P2-G has
   * already consumed it. Only `invitation-pending` may create an absent key.
   */
  async function ensureInvitation(ctx, marker, expected) {
    const key = marker.invitationKey;
    let current;
    try {
      current = readValue(await read(ctx.store, key));
    } catch (error) {
      if (isUnavailable(error)) throw unavailable();
      throw internalError();
    }
    if (current !== null) {
      let existing;
      try {
        existing = await assertAccessInvitationAtKey(current, ctx.doc, key, marker.email);
      } catch {
        throw internalError();
      }
      const allowTrue = marker.phase === "recovery-sent";
      const candidates = allowTrue
        ? [{ ...expected, accountCreated: false }, { ...expected, accountCreated: true }]
        : [{ ...expected, accountCreated: false }];
      if (!candidates.some((candidate) => canonical(candidate) === canonical(existing))) {
        throw conflict();
      }
      return { state: "present", record: existing };
    }
    if (marker.phase === "recovery-sent") {
      return { state: "absent" };
    }
    if (marker.phase !== "invitation-pending") {
      throw conflict();
    }
    await ownerFence(ctx);
    let result;
    try {
      result = await ctx.store.setJSON(key, expected, { onlyIfNew: true });
    } catch {
      throw unavailable();
    }
    const modified = modifiedOf(result);
    if (modified === null) throw unavailable();
    if (modified === false) throw conflict();
    return { state: "created", record: expected };
  }

  function modifiedOf(result) {
    if (result === null || typeof result !== "object" || Array.isArray(result)) {
      return null;
    }
    const descriptor = Object.getOwnPropertyDescriptor(result, "modified");
    if (descriptor === undefined ||
        !Object.prototype.hasOwnProperty.call(descriptor, "value") ||
        typeof descriptor.value !== "boolean") {
      return null;
    }
    return descriptor.value;
  }

  /** Prove that P2-G already converted this invitation into its exact grant. */
  async function assertConsumedGrant(ctx, marker) {
    if (marker.accountSub === null) throw conflict();
    const key = accessGrantKey(ctx.doc, marker.accountSub);
    let current;
    try {
      current = readValue(await read(ctx.store, key));
    } catch (error) {
      if (isUnavailable(error)) throw unavailable();
      throw internalError();
    }
    if (current === null) throw conflict();
    let grant;
    try {
      grant = assertAccessGrant(current, ctx.doc, marker.accountSub);
    } catch {
      throw internalError();
    }
    if (grant.email !== marker.email || grant.role !== marker.role ||
        grant.fromInvitation === null) {
      throw conflict();
    }
  }

  /**
   * Resume or run the account-bootstrap saga for one absent invitation.
   *
   * Every crash point before the event is resumable from the durable marker,
   * and an identical owner POST never creates a second account. Recovery mail
   * is explicitly at-least-once: an ambiguous request may be repeated rather
   * than strand an account nobody can sign in to.
   */
  async function runBootstrap(ctx, marker) {
    const expected = buildInvitation(ctx.doc, marker);
    const presence = await ensureInvitation(ctx, marker, expected);
    let phase = marker.phase;
    let accountSub = marker.accountSub;

    if (phase === "invitation-pending" || phase === "account-create-requested") {
      const found = await findAccount(marker.email);
      if (phase === "invitation-pending" && found !== null) {
        await ownerFence(ctx);
        await setRecovery(ctx, null);
        await ownerFence(ctx);
        await attemptEvent(ctx, "access.invite", { email: marker.email },
          `invited a reviewer as ${marker.role}`);
        return noContentResponse();
      }
      if (found === null) {
        if (phase === "invitation-pending") {
          await ownerFence(ctx);
          await setRecovery(ctx, { ...marker, phase: "account-create-requested" });
          phase = "account-create-requested";
        }
        accountSub = await createAccount(marker.email);
      } else {
        accountSub = found;
      }
      await ownerFence(ctx);
      await setRecovery(ctx, { ...marker, phase: "recovery-required", accountSub });
      phase = "recovery-required";
    }

    if (phase === "recovery-required") {
      await requestRecovery(marker.email);
      await ownerFence(ctx);
      await setRecovery(ctx, { ...marker, phase: "recovery-sent", accountSub });
      phase = "recovery-sent";
    }

    if (presence.state === "absent") {
      await assertConsumedGrant(ctx, { ...marker, accountSub });
    } else if (presence.record.accountCreated !== true) {
      await ownerFence(ctx);
      const snapshot = { ...expected, accountCreated: false };
      await mutate(ctx.store, marker.invitationKey, null, (draft) => {
        if (draft === null) throw conflict();
        if (canonical(draft) === canonical({ ...expected, accountCreated: true })) return null;
        if (canonical(draft) !== canonical(snapshot)) throw conflict();
        return { ...snapshot, accountCreated: true };
      });
    }

    await ownerFence(ctx);
    await setRecovery(ctx, null);
    await ownerFence(ctx);
    await attemptEvent(ctx, "access.invite", { email: marker.email },
      `invited a reviewer as ${marker.role}`);
    return noContentResponse();
  }

  /* ---------------- operations ---------------- */

  async function createInvitation(ctx, body, roster, resumedMarker) {
    if (resumedMarker !== null) {
      return runBootstrap(ctx, resumedMarker);
    }
    const invitationKey = await accessInvitationKey(ctx.doc, body.email);
    if (body.email === ctx.actor.email || body.email === roster.document.ownerEmail) {
      throw conflict();
    }
    if (roster.grants.some(({ record }) => record.email === body.email)) {
      throw conflict();
    }

    const existing = roster.invitations.find(({ key }) => key === invitationKey);
    if (existing !== undefined) {
      if (existing.record.expiresAt > ctx.now) {
        if (existing.record.role !== body.role) throw conflict();
        return reissueRecovery(ctx, existing.record);
      }
      return renewInvitation(ctx, body, existing, roster);
    }

    if (childCount(roster) >= MAX_KEYS) throw memberLimit();
    assertInviteRate(ctx, roster);

    const marker = {
      invitationKey,
      email: body.email,
      role: body.role,
      invitedBy: {
        sub: ctx.actor.sub,
        name: ctx.actor.name,
        email: ctx.actor.email,
      },
      invitedAt: ctx.now,
      expiresAt: new Date(ctx.nowMs + INVITATION_LIFETIME_MS).toISOString(),
      phase: "invitation-pending",
      accountSub: null,
    };
    await ownerFence(ctx);
    await setRecovery(ctx, marker);
    return runBootstrap(ctx, marker);
  }

  function assertInviteRate(ctx, roster) {
    const windowStart = new Date(ctx.nowMs - INVITE_WINDOW_MS).toISOString();
    const recent = liveInvitations(roster, ctx.now)
      .filter(({ record }) => record.invitedAt > windowStart);
    if (recent.length >= MAX_LIVE_INVITES) throw inviteRateLimit();
  }

  /**
   * Reissue the setup message for a live same-role invitation.
   *
   * Deliberately changes no record, extends no expiry, and appends no event.
   * This is at-least-once mail, which is safe precisely because it can create
   * neither an account nor access.
   */
  async function reissueRecovery(ctx, invitation) {
    const found = await findAccount(invitation.email);
    if (found === null) throw conflict();
    await ownerFence(ctx);
    await requestRecovery(invitation.email);
    return noContentResponse();
  }

  /** Replace an expired same-key invitation in place under the lease. */
  async function renewInvitation(ctx, body, existing, roster) {
    assertInviteRate(ctx, roster);
    const snapshot = existing.record;
    const renewed = {
      v: 1,
      docId: ctx.doc,
      email: snapshot.email,
      role: body.role,
      invitedBy: {
        sub: ctx.actor.sub,
        name: ctx.actor.name,
        email: ctx.actor.email,
      },
      invitedAt: ctx.now,
      expiresAt: new Date(ctx.nowMs + INVITATION_LIFETIME_MS).toISOString(),
      accountCreated: snapshot.accountCreated,
    };
    await ownerFence(ctx);
    await mutate(ctx.store, existing.key, null, (draft) => {
      if (draft === null) throw conflict();
      if (canonical(draft) !== canonical(snapshot)) throw conflict();
      return renewed;
    });
    if (snapshot.accountCreated === true) {
      const found = await findAccount(snapshot.email);
      if (found === null) throw conflict();
      await requestRecovery(snapshot.email);
    }
    await ownerFence(ctx);
    await attemptEvent(ctx, "access.invite", { email: snapshot.email },
      `invited a reviewer as ${body.role}`);
    return noContentResponse();
  }

  async function changeGrantRole(ctx, body, roster) {
    if (body.sub === roster.document.ownerSub) throw conflict();
    const target = roster.grants.find(({ record }) => record.sub === body.sub);
    if (target === undefined) throw notFound();
    const snapshot = target.record;
    await ownerFence(ctx);
    const result = await mutate(ctx.store, target.key, null, (draft) => {
      if (draft === null) throw conflict();
      let fresh;
      try {
        fresh = assertAccessGrant(draft, ctx.doc, body.sub);
      } catch {
        throw internalError();
      }
      if (canonical(fresh) !== canonical(snapshot)) throw conflict();
      if (fresh.role === body.role) return null;
      return {
        v: fresh.v,
        docId: fresh.docId,
        sub: fresh.sub,
        email: fresh.email,
        name: fresh.name,
        role: body.role,
        grantedBy: {
          sub: ctx.actor.sub,
          name: ctx.actor.name,
          email: ctx.actor.email,
        },
        grantedAt: ctx.now,
        fromInvitation: fresh.fromInvitation,
      };
    });
    if (result.changed !== true) return noContentResponse();
    await ownerFence(ctx);
    await attemptEvent(ctx, "access.change", { sub: body.sub },
      `changed access role to ${body.role}`);
    return noContentResponse();
  }

  async function changeInvitationRole(ctx, body, roster) {
    const key = await accessInvitationKey(ctx.doc, body.email);
    const target = roster.invitations.find((entry) => entry.key === key);
    if (target === undefined || target.record.expiresAt <= ctx.now) throw notFound();
    const snapshot = target.record;
    await ownerFence(ctx);
    const result = await mutate(ctx.store, key, null, (draft) => {
      if (draft === null) throw conflict();
      if (canonical(draft) !== canonical(snapshot)) throw conflict();
      if (snapshot.role === body.role) return null;
      return {
        v: snapshot.v,
        docId: snapshot.docId,
        email: snapshot.email,
        role: body.role,
        invitedBy: {
          sub: ctx.actor.sub,
          name: ctx.actor.name,
          email: ctx.actor.email,
        },
        invitedAt: ctx.now,
        expiresAt: new Date(ctx.nowMs + INVITATION_LIFETIME_MS).toISOString(),
        accountCreated: snapshot.accountCreated,
      };
    });
    if (result.changed !== true) return noContentResponse();
    await ownerFence(ctx);
    await attemptEvent(ctx, "access.change", { email: body.email },
      `changed access role to ${body.role}`);
    return noContentResponse();
  }

  async function changeOrgDefault(ctx, body) {
    const key = accessDocumentKey(ctx.doc);
    const result = await mutate(ctx.store, key, null, (draft) => {
      if (draft === null) throw internalError();
      const document = assertAccessDocument(draft, ctx.doc);
      if (document.ownerSub !== ctx.actor.sub) throw forbidden();
      if (document.orgDefault === body.orgDefault) return null;
      return { ...freshDocument(document), orgDefault: body.orgDefault };
    });
    if (result.changed !== true) return noContentResponse();
    await ownerFence(ctx);
    await attemptEvent(ctx, "access.change", { sub: ctx.actor.sub },
      `changed organization default to ${body.orgDefault}`);
    return noContentResponse();
  }

  async function revokeGrant(ctx, body, roster) {
    if (body.sub === roster.document.ownerSub) throw conflict();
    const target = roster.grants.find(({ record }) => record.sub === body.sub);
    if (target === undefined) throw notFound();
    await ownerFence(ctx);
    await compareAndDelete(ctx, target.key, target.record, (value) => {
      try {
        return assertAccessGrant(value, ctx.doc, body.sub);
      } catch {
        throw internalError();
      }
    });
    await ownerFence(ctx);
    await attemptEvent(ctx, "access.revoke", { sub: body.sub }, "revoked document access");
    return noContentResponse();
  }

  async function cancelInvitation(ctx, body, roster) {
    const key = await accessInvitationKey(ctx.doc, body.email);
    const target = roster.invitations.find((entry) => entry.key === key);
    if (target === undefined || target.record.expiresAt <= ctx.now) throw notFound();
    await ownerFence(ctx);
    await compareAndDelete(ctx, key, target.record, (value) =>
      assertAccessInvitationAtKey(value, ctx.doc, key, body.email));

    // P2-G invitation acceptance is the one non-lease writer: it creates the
    // grant before deleting the invitation, so a grant that exists now means
    // cancellation lost the race and the accepted grant must stand.
    const after = await inventory(ctx);
    if (after.grants.some(({ record }) => record.email === body.email)) {
      throw conflict();
    }
    await ownerFence(ctx);
    await attemptEvent(ctx, "access.revoke", { email: body.email }, "revoked document access");
    return noContentResponse();
  }

  /* ---------------- ownership transfer ---------------- */

  async function startTransfer(ctx, body, roster) {
    if (body.sub === ctx.actor.sub || body.sub === roster.document.ownerSub) {
      throw conflict();
    }
    const target = roster.grants.find(({ record }) => record.sub === body.sub);
    if (target === undefined) throw notFound();
    const marker = {
      fromOwner: {
        sub: ctx.actor.sub,
        name: ctx.actor.name,
        email: ctx.actor.email,
      },
      toOwner: { sub: target.record.sub, email: target.record.email },
      targetGrant: {
        v: target.record.v,
        docId: target.record.docId,
        sub: target.record.sub,
        email: target.record.email,
        name: target.record.name,
        role: target.record.role,
        grantedBy: {
          sub: target.record.grantedBy.sub,
          name: target.record.grantedBy.name,
          email: target.record.grantedBy.email,
        },
        grantedAt: target.record.grantedAt,
        fromInvitation: target.record.fromInvitation,
      },
      at: ctx.now,
      phase: "owner-pending",
    };
    await ownerFence(ctx);
    await setTransfer(ctx, marker);
    await runTransfer(ctx, marker);
    return noContentResponse();
  }

  /**
   * Drive the durable transfer saga to completion.
   *
   * Ordering is exact: authority CAS, redundant target-grant deletion, then
   * former-owner grant reuse or creation. Starting from `N <= 50` the child
   * count moves `N -> N - 1 -> N` at worst, so a 51st child is never
   * materialized. Every phase transition is a coordinator CAS under the
   * captured lease, so repair is idempotent from either side of the authority
   * commit.
   */
  async function runTransfer(ctx, marker) {
    let phase = marker.phase;
    const { fromOwner, toOwner, targetGrant, at } = marker;

    if (phase === "owner-pending") {
      const key = accessDocumentKey(ctx.doc);
      await mutate(ctx.store, key, null, (draft) => {
        if (draft === null) throw internalError();
        const document = assertAccessDocument(draft, ctx.doc);
        if (document.ownerSub === fromOwner.sub) {
          return {
            ...freshDocument(document),
            ownerSub: toOwner.sub,
            ownerEmail: toOwner.email,
          };
        }
        if (document.ownerSub === toOwner.sub) {
          return freshDocument(document);
        }
        throw conflict();
      });
      await setTransfer(ctx, { ...marker, phase: "owner-committed" });
      phase = "owner-committed";
    }

    if (phase === "owner-committed") {
      await transferFence(ctx, toOwner.sub);
      await compareAndDelete(ctx, accessGrantKey(ctx.doc, toOwner.sub), targetGrant, (value) => {
        try {
          return assertAccessGrant(value, ctx.doc, toOwner.sub);
        } catch {
          throw internalError();
        }
      }, true);
      await setTransfer(ctx, { ...marker, phase: "target-grant-removed" });
      phase = "target-grant-removed";
    }

    await transferFence(ctx, toOwner.sub);
    const formerKey = accessGrantKey(ctx.doc, fromOwner.sub);
    const formerGrant = {
      v: 1,
      docId: ctx.doc,
      sub: fromOwner.sub,
      email: fromOwner.email,
      name: fromOwner.name,
      role: "editor",
      grantedBy: {
        sub: fromOwner.sub,
        name: fromOwner.name,
        email: fromOwner.email,
      },
      grantedAt: at,
      fromInvitation: null,
    };
    await mutate(ctx.store, formerKey, null, (draft) => {
      if (draft !== null) {
        let fresh;
        try {
          fresh = assertAccessGrant(draft, ctx.doc, fromOwner.sub);
        } catch {
          throw internalError();
        }
        if (canonical(fresh) === canonical(formerGrant)) return null;
      }
      return formerGrant;
    });

    await transferFence(ctx, toOwner.sub);
    await setTransfer(ctx, null);
    await transferFence(ctx, toOwner.sub);
    await attemptEvent(ctx, "access.transfer",
      { fromSub: fromOwner.sub, toSub: toOwner.sub }, "transferred document ownership");
  }

  /* ---------------- mutation dispatch ---------------- */

  async function dispatch(ctx, routeKey, body, resumedMarker) {
    if (routeKey === "PATCH /api/access" && body.keys.includes("orgDefault")) {
      return changeOrgDefault(ctx, body);
    }
    const roster = await inventory(ctx);
    if (routeKey === "POST /api/access") {
      return createInvitation(ctx, body, roster, resumedMarker);
    }
    if (routeKey === "PATCH /api/access") {
      return body.keys.includes("sub")
        ? changeGrantRole(ctx, body, roster)
        : changeInvitationRole(ctx, body, roster);
    }
    if (routeKey === "DELETE /api/access") {
      return body.keys.includes("sub")
        ? revokeGrant(ctx, body, roster)
        : cancelInvitation(ctx, body, roster);
    }
    return startTransfer(ctx, body, roster);
  }

  /**
   * Reconcile a stored marker before the requested operation.
   *
   * A pending recovery marker admits only the identical resuming POST; a
   * pending transfer marker admits only the old owner's identical transfer
   * POST before the authority CAS, or the new owner afterwards, who must
   * finish the repair and its one event attempt first.
   */
  async function reconcileMarkers(ctx, routeKey, body) {
    const recovery = ctx.coordinator.recovery;
    const transfer = ctx.coordinator.transfer;
    if (transfer !== null) {
      if (transfer.fromOwner.sub === ctx.actor.sub) {
        const identical = routeKey === "POST /api/access/transfer" &&
          body.sub === transfer.toOwner.sub && transfer.phase === "owner-pending";
        if (!identical) throw conflict();
        await runTransfer(ctx, transfer);
        return { completed: true, marker: null };
      }
      if (transfer.toOwner.sub === ctx.actor.sub) {
        await runTransfer(ctx, transfer);
        return { completed: false, marker: null };
      }
      throw conflict();
    }
    if (recovery !== null) {
      const key = await accessInvitationKey(ctx.doc, recovery.email);
      if (key !== recovery.invitationKey) throw internalError();
      const identical = routeKey === "POST /api/access" &&
        body.email === recovery.email && body.role === recovery.role;
      if (!identical) throw recoveryPending();
      return { completed: false, marker: recovery };
    }
    return { completed: false, marker: null };
  }

  async function runMutation(req, routeKey) {
    const originResponse = await verifyOrigin(req);
    if (originResponse !== null) return originResponse;

    requireNoQuery(req);

    const identified = await identifyFn(req);
    if (identified === null) throw unauthenticated();
    let user;
    try {
      user = validateIdentity(identified);
    } catch {
      throw internalError();
    }

    if (!mediaTypeIsJson(req)) throw httpError(415, "unsupported-media-type");
    const bodyRead = await readBoundedBody(req);
    if (bodyRead.status !== undefined) {
      throw bodyRead.status === 413
        ? httpError(413, "payload-too-large")
        : invalidRequest();
    }
    const body = parseVariant(routeKey, bodyRead.text);

    await authorize(user, body.doc);

    const store = openStore();
    let actorEmail;
    try {
      actorEmail = normalizeEmail(user.email);
    } catch {
      throw internalError();
    }
    const actor = { sub: user.sub, name: user.name, email: actorEmail };
    const nowMs = nowFn();
    if (!Number.isSafeInteger(nowMs) || nowMs < MIN_NOW_MS || nowMs > MAX_NOW_MS) {
      throw internalError();
    }
    const ctx = {
      store,
      doc: body.doc,
      actor,
      nowMs,
      now: new Date(nowMs).toISOString(),
      writeKey: writeCoordinatorKey(body.doc),
      leaseId: null,
      epoch: null,
      coordinator: null,
    };

    await acquireLease(ctx);
    let primary = null;
    let failure = null;
    try {
      const reconciled = await reconcileMarkers(ctx, routeKey, body);
      primary = reconciled.completed
        ? noContentResponse()
        : await dispatch(ctx, routeKey, body, reconciled.marker);
    } catch (error) {
      failure = error;
    }
    try {
      await releaseLease(ctx.store, ctx.doc, ctx.writeKey, ctx.leaseId, ctx.epoch);
    } catch (error) {
      // A release failure downgrades an otherwise successful 204; a primary
      // 4xx/5xx verdict is preserved and the release failure is discarded.
      if (failure === null) {
        void error;
        failure = unavailable();
      }
    }
    if (failure !== null) throw failure;
    return primary;
  }

  return async function accessHandler(req) {
    let pathname;
    try {
      pathname = new URL(req.url).pathname;
    } catch {
      return errorResponse(invalidRequest());
    }
    const method = req.method;
    if (pathname === BASE_PATH) {
      if (method === "GET") return handleGet(req);
      if (method !== "POST" && method !== "PATCH" && method !== "DELETE") {
        return errorResponse(httpError(405, "method-not-allowed", { Allow: BASE_ALLOW }));
      }
    } else if (pathname === TRANSFER_PATH) {
      if (method !== "POST") {
        return errorResponse(httpError(405, "method-not-allowed", { Allow: TRANSFER_ALLOW }));
      }
    } else {
      return errorResponse(notFound());
    }
    try {
      return await runMutation(req, `${method} ${pathname}`);
    } catch (error) {
      return errorResponse(error);
    }
  };
}

/** Require exactly `size` bytes from an injected or production `randomBytes`. */
function assertRandomBytes(bytes, size) {
  if (!(bytes instanceof Uint8Array) || bytes.length !== size) {
    throw new TypeError("Invalid random bytes");
  }
  return bytes;
}

const productionHandler = createAccessHandler();

/**
 * The production Functions v2 handler.
 * @param {Request} req
 * @param {object} [context]
 * @returns {Promise<Response>}
 */
export default async function handler(req, context) {
  void context;
  return productionHandler(req);
}

export const config = { path: [BASE_PATH, TRANSFER_PATH] };
