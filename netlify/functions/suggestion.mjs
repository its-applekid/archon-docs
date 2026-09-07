import { identify, requireOrigin } from "../lib/identity.mjs";
import { capabilitiesFor, resolveRole, validateAccessRow } from "../lib/access.mjs";
import { StoreError, docState, read, suggestionKey } from "../lib/store.mjs";
import {
  ApplyError,
  applyText,
  assertApplyReceipt,
  readApplyReceipt,
} from "../lib/gitedit.mjs";
import { toHtml } from "../lib/inline-md.mjs";
import { notify } from "../lib/notify.mjs";
import { appendEvent } from "./events.mjs";
import { assertSuggestionAtKey } from "./suggestions.mjs";
import { createHash } from "node:crypto";

const NO_STORE = "private, no-store";
const JSON_TYPE = "application/json; charset=utf-8";
const MAX_REQUEST_BYTES = 16_384;
const MAX_TEXT_UNITS = 4_000;
const MAX_NAME_UNITS = 200;
const MAX_REASON_UNITS = 280;

const DOC_ID_PATTERN = /^[0-9a-f]{6}$/;
const AID_PATTERN = /^a[0-9a-f]{8}$/;
const SUGGESTION_ID_PATTERN = /^s_[a-z0-9]{1,48}_[0-9a-f]{8}$/;
const HASH_PATTERN = /^[0-9a-f]{64}$/;
const SUBJECT_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._~-]{0,127}$/;
const TIMESTAMP_PATTERN =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const EMAIL_LOCAL_PATTERN =
  /^[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*$/;
const DNS_LABEL_PATTERN = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const EMAIL_EDGE_WHITESPACE = /^[ \t\n\r\f]+|[ \t\n\r\f]+$/g;
const NON_ASCII_PATTERN = /[^\x00-\x7f]/;
const CONTROL_PATTERN = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/;
const CANONICAL_INTEGER_PATTERN = /^(?:0|[1-9][0-9]*)$/;
const MEDIA_TYPE_PATTERN =
  /^[ \t]*([!#$%&'*+.^_`|~0-9A-Za-z-]+)\/([!#$%&'*+.^_`|~0-9A-Za-z-]+)[ \t]*(?:;[ \t]*[!#$%&'*+.^_`|~0-9A-Za-z-]+=(?:[!#$%&'*+.^_`|~0-9A-Za-z-]+|"(?:[^"\\\x00-\x1f\x7f]|\\[\x00-\x7f])*")[ \t]*)*$/;

const DEPENDENCY_KEYS = Object.freeze([
  "requireOriginFn",
  "identifyFn",
  "resolveRoleFn",
  "capabilitiesForFn",
  "storeFn",
  "assertApplyReceiptFn",
  "readApplyReceiptFn",
  "applyTextFn",
  "appendEventFn",
  "notifyFn",
  "sha256Fn",
  "toHtmlFn",
]);
const BODY_KEYS = Object.freeze(["docId", "aid", "sugId", "action", "reason"]);
const IDENTITY_KEYS = Object.freeze(["sub", "email", "name", "isOrg"]);
const RESULT_KEYS = Object.freeze(["receipt", "pr"]);
const ACTOR_KEYS = Object.freeze(["sub", "name", "email"]);
const SUGGESTION_RECEIPT_KEYS = Object.freeze([
  "v", "aid", "text", "by", "at", "baseHash", "pr", "via", "sugId",
  "acceptedBy", "acceptedAt",
]);

const PUBLIC_ERRORS = Object.freeze({
  "invalid-request": [400, "Invalid request"],
  "invalid-body": [400, "Invalid request body"],
  unauthenticated: [401, "Authentication required"],
  forbidden: [403, "Suggestion access denied"],
  "not-found": [404, "Suggestion or block not found"],
  "method-not-allowed": [405, "Method not allowed"],
  conflict: [409, "The block changed since this document was built"],
  "event-id-collision": [409, "Generated event identifier collision"],
  "payload-too-large": [413, "Request body exceeds 16384 bytes"],
  "unsupported-media-type": [415, "Content-Type must be application/json"],
  "invalid-state": [500, "Invalid suggestion state"],
  "repository-unavailable": [502, "Repository write unavailable"],
  unavailable: [503, "Suggestion state unavailable"],
});

class Failure extends Error {
  constructor(code, current = null) {
    super("suggestion");
    this.code = Object.hasOwn(PUBLIC_ERRORS, code) ? code : "invalid-state";
    this.current = current;
  }
}

const fail = (code) => new Failure(code);
const conflict = (hash, text) =>
  new Failure("conflict", { hash, text: typeof text === "string" ? text : null });
const hasOwn = (value, key) => Object.prototype.hasOwnProperty.call(value, key);
const rawCompare = (left, right) => left < right ? -1 : left > right ? 1 : 0;

function jsonResponse(status, body, extraHeaders = null) {
  const headers = { "Cache-Control": NO_STORE, "Content-Type": JSON_TYPE };
  if (extraHeaders !== null) Object.assign(headers, extraHeaders);
  return new Response(JSON.stringify(body), { status, headers });
}

function errorResponse(error) {
  const failure = error instanceof Failure ? error : fail("invalid-state");
  const [status, message] = PUBLIC_ERRORS[failure.code];
  const body = { error: { code: failure.code, message } };
  if (failure.code === "conflict") body.current = failure.current;
  const headers = failure.code === "method-not-allowed" ? { Allow: "POST" } : null;
  return jsonResponse(status, body, headers);
}

function isDataProperty(object, key) {
  const descriptor = Object.getOwnPropertyDescriptor(object, key);
  return descriptor !== undefined && hasOwn(descriptor, "value") && descriptor.enumerable === true;
}

function isPlainRecord(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) return false;
  if (Object.getOwnPropertySymbols(value).length !== 0) return false;
  return Object.getOwnPropertyNames(value).every((key) => isDataProperty(value, key));
}

function sameKeys(value, expected) {
  if (!isPlainRecord(value)) return false;
  const names = Object.getOwnPropertyNames(value);
  if (names.length !== expected.length) return false;
  const sorted = names.sort(rawCompare);
  const wanted = [...expected].sort(rawCompare);
  return sorted.every((key, index) => key === wanted[index]);
}

function exactOrdered(value, expected) {
  if (!isPlainRecord(value) || Object.getPrototypeOf(value) !== Object.prototype) return false;
  const keys = Reflect.ownKeys(value);
  return keys.length === expected.length &&
    expected.every((key, index) => keys[index] === key && isDataProperty(value, key));
}

function captureDependencies(dependencies) {
  if (dependencies === null || typeof dependencies !== "object" || Array.isArray(dependencies) ||
      Object.getPrototypeOf(dependencies) !== Object.prototype ||
      Object.getOwnPropertySymbols(dependencies).length !== 0) {
    throw new TypeError("Invalid suggestion dependencies");
  }
  const names = Object.getOwnPropertyNames(dependencies);
  const defaults = {
    requireOriginFn: requireOrigin,
    identifyFn: identify,
    resolveRoleFn: resolveRole,
    capabilitiesForFn: capabilitiesFor,
    storeFn: docState,
    assertApplyReceiptFn: assertApplyReceipt,
    readApplyReceiptFn: readApplyReceipt,
    applyTextFn: applyText,
    appendEventFn: appendEvent,
    notifyFn: notify,
    sha256Fn: (value) => createHash("sha256").update(value, "utf8").digest("hex"),
    toHtmlFn: toHtml,
  };
  for (const name of names) {
    if (!DEPENDENCY_KEYS.includes(name) || !isDataProperty(dependencies, name) ||
        typeof dependencies[name] !== "function") {
      throw new TypeError("Invalid suggestion dependencies");
    }
  }
  const captured = {};
  for (const name of DEPENDENCY_KEYS) {
    captured[name] = names.includes(name) ? dependencies[name] : defaults[name];
  }
  return Object.freeze(captured);
}

function isNormalizedEmail(value) {
  if (typeof value !== "string" || value.length === 0 || value.length > 254) return false;
  if (value.replace(EMAIL_EDGE_WHITESPACE, "") !== value || NON_ASCII_PATTERN.test(value) ||
      value.toLowerCase() !== value) return false;
  const at = value.indexOf("@");
  if (at === -1 || value.indexOf("@", at + 1) !== -1 ||
      !EMAIL_LOCAL_PATTERN.test(value.slice(0, at))) return false;
  const labels = value.slice(at + 1).split(".");
  return labels.length >= 2 && labels.every((label) => DNS_LABEL_PATTERN.test(label));
}

function isActor(actor) {
  if (!exactOrdered(actor, ACTOR_KEYS)) return false;
  return typeof actor.sub === "string" && SUBJECT_PATTERN.test(actor.sub) &&
    actor.sub !== "system" && typeof actor.name === "string" &&
    actor.name.length <= MAX_NAME_UNITS && typeof actor.email === "string" &&
    (actor.email === "" || isNormalizedEmail(actor.email));
}

function requireIdentity(value) {
  if (!sameKeys(value, IDENTITY_KEYS) || typeof value.isOrg !== "boolean") {
    throw fail("invalid-state");
  }
  const actor = { sub: value.sub, name: value.name, email: value.email };
  if (!isActor(actor)) throw fail("invalid-state");
  return actor;
}

function ownData(value, key) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return null;
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  if (descriptor === undefined || !hasOwn(descriptor, "value") || descriptor.enumerable !== true) {
    return null;
  }
  return descriptor.value;
}

function isAccessUnavailable(error) {
  return ownData(error, "name") === "StoreError" && ownData(error, "code") === "unavailable" &&
    ownData(error, "status") === 503;
}

async function resolveAccess(deps, docId, identity) {
  let access;
  try {
    access = await deps.resolveRoleFn(docId, identity, { consumeInvitation: false });
  } catch (error) {
    throw fail(isAccessUnavailable(error) ? "unavailable" : "invalid-state");
  }
  if (!validateAccessRow(access, (role) => deps.capabilitiesForFn(role))) {
    throw fail("invalid-state");
  }
  return access;
}

function isSafeScalar(value, minimum, maximum) {
  return typeof value === "string" && value.length >= minimum && value.length <= maximum &&
    value.isWellFormed() && !CONTROL_PATTERN.test(value);
}

function parseUrl(req) {
  try {
    const raw = req.url;
    const url = new URL(raw);
    if (url.search !== "" || typeof raw !== "string" || raw.includes("?")) {
      throw fail("invalid-request");
    }
  } catch {
    throw fail("invalid-request");
  }
}

function isJsonMediaType(value) {
  if (typeof value !== "string") return false;
  const match = value.match(MEDIA_TYPE_PATTERN);
  return match !== null && `${match[1]}/${match[2]}`.toLowerCase() === "application/json";
}

async function readBoundedBody(req) {
  const body = req.body;
  if (body === null || body === undefined || typeof body.getReader !== "function" ||
      body.locked === true) throw fail("invalid-body");
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
      if (result === null || typeof result !== "object" || typeof result.done !== "boolean") {
        failure = "invalid-body";
        break;
      }
      if (result.done) break;
      if (!(result.value instanceof Uint8Array)) {
        failure = "invalid-body";
        break;
      }
      if (total + result.value.byteLength > MAX_REQUEST_BYTES) {
        failure = "payload-too-large";
        break;
      }
      chunks.push(result.value);
      total += result.value.byteLength;
    }
  } catch {
    failure = "invalid-body";
  }
  if (failure !== null) {
    try { await reader.cancel(); } catch { /* the failure stands */ }
  }
  try { reader.releaseLock(); } catch { /* best effort */ }
  if (failure !== null) throw fail(failure);
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return bytes;
}

async function readJsonObject(req) {
  if (!isJsonMediaType(req.headers.get("content-type"))) {
    throw fail("unsupported-media-type");
  }
  const declared = req.headers.get("content-length");
  if (declared !== null) {
    if (!CANONICAL_INTEGER_PATTERN.test(declared) || !Number.isSafeInteger(Number(declared))) {
      throw fail("invalid-body");
    }
    if (Number(declared) > MAX_REQUEST_BYTES) throw fail("payload-too-large");
  }
  const bytes = await readBoundedBody(req);
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
  if (!sameKeys(parsed, BODY_KEYS)) throw fail("invalid-body");
  return parsed;
}

function parseBody(value) {
  const { docId, aid, sugId, action, reason } = value;
  if (typeof docId !== "string" || !DOC_ID_PATTERN.test(docId) ||
      typeof aid !== "string" || !AID_PATTERN.test(aid) ||
      typeof sugId !== "string" || !SUGGESTION_ID_PATTERN.test(sugId) ||
      !["accept", "reject", "withdraw"].includes(action)) {
    throw fail("invalid-body");
  }
  if ((action === "reject" && !isSafeScalar(reason, 1, MAX_REASON_UNITS)) ||
      (action !== "reject" && reason !== "")) {
    throw fail("invalid-body");
  }
  return { docId, aid, sugId, action, reason };
}

function openStore(deps) {
  let store;
  try {
    store = deps.storeFn();
  } catch {
    throw fail("unavailable");
  }
  if (store === null || typeof store !== "object" ||
      typeof store.getWithMetadata !== "function" || typeof store.setJSON !== "function" ||
      typeof store.delete !== "function") throw fail("invalid-state");
  return store;
}

function mapStoreError(error, collision = false) {
  if (!(error instanceof StoreError)) return fail("invalid-state");
  if (error.code === "unavailable" && error.status === 503) return fail("unavailable");
  if (collision && error.code === "conflict" && error.status === 409) {
    return fail("event-id-collision");
  }
  return fail("invalid-state");
}

function mapApplyError(error) {
  if (!(error instanceof ApplyError)) return fail("invalid-state");
  const expected = {
    "invalid-body": 400,
    "not-found": 404,
    conflict: 409,
    "invalid-state": 500,
    "repository-unavailable": 502,
    unavailable: 503,
  };
  if (!Object.hasOwn(expected, error.code) || error.status !== expected[error.code]) {
    return fail("invalid-state");
  }
  if (error.code === "conflict") {
    if (typeof error.currentHash !== "string" || !HASH_PATTERN.test(error.currentHash) ||
        !(error.current === null || (typeof error.current === "string" &&
          error.current.length <= MAX_TEXT_UNITS && error.current.isWellFormed()))) {
      return fail("invalid-state");
    }
    return conflict(error.currentHash, error.current);
  }
  return fail(error.code);
}

async function strongSuggestion(deps, store, docId, aid, sugId) {
  const key = suggestionKey(docId, aid, sugId);
  let found;
  try {
    found = await read(store, key, null);
  } catch (error) {
    throw mapStoreError(error);
  }
  if (found.value === null) return { key, record: null };
  let record;
  try {
    record = assertSuggestionAtKey(found.value, docId, key);
  } catch {
    throw fail("invalid-state");
  }
  return { key, record };
}

async function deleteSuggestion(store, key) {
  if (typeof store.delete !== "function") throw fail("unavailable");
  try {
    await store.delete(key);
  } catch {
    throw fail("unavailable");
  }
}

function sameActor(left, right) {
  return exactOrdered(left, ACTOR_KEYS) && exactOrdered(right, ACTOR_KEYS) &&
    left.sub === right.sub && left.name === right.name && left.email === right.email;
}

function isTimestamp(value) {
  if (typeof value !== "string" || !TIMESTAMP_PATTERN.test(value)) return false;
  try {
    return new Date(value).toISOString() === value;
  } catch {
    return false;
  }
}

function isSuggestionReceipt(value) {
  return exactOrdered(value, SUGGESTION_RECEIPT_KEYS) && value.v === 1 &&
    typeof value.aid === "string" && AID_PATTERN.test(value.aid) &&
    typeof value.text === "string" && value.text.length <= MAX_TEXT_UNITS &&
    value.text.isWellFormed() && isActor(value.by) && isTimestamp(value.at) &&
    typeof value.baseHash === "string" && HASH_PATTERN.test(value.baseHash) &&
    (value.pr === null || (Number.isSafeInteger(value.pr) && value.pr > 0)) &&
    value.via === "suggestion" && typeof value.sugId === "string" &&
    SUGGESTION_ID_PATTERN.test(value.sugId) && isActor(value.acceptedBy) &&
    isTimestamp(value.acceptedAt);
}

function validateApplyResult(deps, value, record) {
  if (!sameKeys(value, RESULT_KEYS)) throw fail("invalid-state");
  let receipt;
  try {
    receipt = deps.assertApplyReceiptFn(value.receipt, record.aid);
  } catch {
    throw fail("invalid-state");
  }
  if (!isSuggestionReceipt(receipt) || receipt.sugId !== record.id ||
      receipt.aid !== record.aid || receipt.text !== record.text ||
      !sameActor(receipt.by, record.by) || value.pr !== receipt.pr) {
    throw fail("invalid-state");
  }
  return { receipt, pr: receipt.pr };
}

async function appendRequired(deps, store, record, actor, kind, verb) {
  try {
    await deps.appendEventFn({
      store,
      docId: record.docId,
      actor: { sub: actor.sub, name: actor.name, email: actor.email },
      kind,
      target: { suggestionId: record.id, aid: record.aid },
      docVersion: record.docVersion,
      summary: `${verb} suggestion in ${record.section}`,
    });
  } catch (error) {
    throw mapStoreError(error, true);
  }
}

async function appendBestEffort(deps, store, record, actor) {
  try {
    await deps.appendEventFn({
      store,
      docId: record.docId,
      actor: { sub: actor.sub, name: actor.name, email: actor.email },
      kind: "suggest.accept",
      target: { suggestionId: record.id, aid: record.aid },
      docVersion: record.docVersion,
      summary: `accepted suggestion in ${record.section}`,
    });
  } catch {
    // Acceptance is already durable and the suggestion is already deleted.
  }
}

async function acceptSuggestion(deps, store, record, key, identity, context) {
  let applied;
  try {
    applied = await deps.applyTextFn({
      docId: record.docId,
      aid: record.aid,
      text: record.text,
      author: { sub: record.by.sub, name: record.by.name, email: record.by.email },
      acceptedBy: { sub: identity.sub, name: identity.name, email: identity.email },
      sugId: record.id,
      via: "suggestion",
      expectBase: record.baseHash,
    });
  } catch (error) {
    throw mapApplyError(error);
  }
  const result = validateApplyResult(deps, applied, record);
  await deleteSuggestion(store, key);
  await appendBestEffort(deps, store, record, result.receipt.acceptedBy);

  try {
    deps.notifyFn(context, {
      t: "suggest.decided",
      docId: record.docId,
      suggestionId: record.id,
      aid: record.aid,
      authorName: record.by.name,
      deciderName: result.receipt.acceptedBy.name,
      outcome: "accepted",
    });
  } catch { /* best effort */ }
  try {
    const html = deps.toHtmlFn(result.receipt.text);
    const hash = deps.sha256Fn(html);
    if (typeof html !== "string" || typeof hash !== "string" || !HASH_PATTERN.test(hash)) {
      throw new TypeError("invalid hash");
    }
    deps.notifyFn(context, {
      t: "edit.saved",
      docId: record.docId,
      aid: record.aid,
      hash,
    });
  } catch { /* independently best effort */ }
  return result;
}

async function replayAcceptance(deps, docId, aid, sugId) {
  let value;
  try {
    value = await deps.readApplyReceiptFn(docId, aid);
  } catch (error) {
    throw mapApplyError(error);
  }
  if (value === null) throw fail("not-found");
  let receipt;
  try {
    receipt = deps.assertApplyReceiptFn(value, aid);
  } catch {
    throw fail("invalid-state");
  }
  if (receipt.via !== "suggestion") throw fail("not-found");
  if (!isSuggestionReceipt(receipt)) throw fail("invalid-state");
  if (receipt.sugId !== sugId) throw fail("not-found");
  return { receipt, pr: receipt.pr };
}

export function createSuggestionHandler(dependencies = {}) {
  const deps = captureDependencies(dependencies);

  return async function handleSuggestion(req, context) {
    if (req.method !== "POST") return errorResponse(fail("method-not-allowed"));
    try {
      try {
        deps.requireOriginFn(req);
      } catch (error) {
        if (error instanceof Response) return error;
        throw fail("invalid-state");
      }

      parseUrl(req);
      let identified;
      try {
        identified = await deps.identifyFn(req);
      } catch {
        throw fail("invalid-state");
      }
      if (identified === null) throw fail("unauthenticated");
      const identity = requireIdentity(identified);
      const input = parseBody(await readJsonObject(req));
      const access = await resolveAccess(deps, input.docId, identified);

      if ((input.action === "accept" || input.action === "reject") &&
          access.canAccept !== true) {
        throw fail("forbidden");
      }

      const store = openStore(deps);
      const found = await strongSuggestion(
        deps, store, input.docId, input.aid, input.sugId,
      );

      if (found.record === null) {
        if (input.action === "accept") {
          return jsonResponse(200, await replayAcceptance(
            deps, input.docId, input.aid, input.sugId,
          ));
        }
        throw fail("not-found");
      }
      const record = found.record;

      if (input.action === "withdraw") {
        if (record.by.sub !== identity.sub) {
          throw fail(access.canRead === true ? "forbidden" : "not-found");
        }
        await appendRequired(deps, store, record, identity, "suggest.withdraw", "withdrew");
        await deleteSuggestion(store, found.key);
        return jsonResponse(200, { ok: true });
      }

      if (input.action === "reject") {
        await appendRequired(deps, store, record, identity, "suggest.reject", "rejected");
        await deleteSuggestion(store, found.key);
        try {
          deps.notifyFn(context, {
            t: "suggest.decided",
            docId: record.docId,
            suggestionId: record.id,
            aid: record.aid,
            authorName: record.by.name,
            deciderName: identity.name,
            outcome: "rejected",
          });
        } catch { /* best effort */ }
        return jsonResponse(200, { ok: true });
      }

      return jsonResponse(200, await acceptSuggestion(
        deps, store, record, found.key, identity, context,
      ));
    } catch (error) {
      return errorResponse(error instanceof Failure ? error : fail("invalid-state"));
    }
  };
}

const productionHandler = createSuggestionHandler();

/** @param {Request} req @param {object} context @returns {Promise<Response>} */
export default async function handler(req, context) {
  return productionHandler(req, context);
}

export const config = { path: "/api/suggestion" };
