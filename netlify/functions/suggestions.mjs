import { identify, requireOrigin } from "../lib/identity.mjs";
import {
  capabilitiesFor,
  normalizeEmail,
  resolveRole,
  validateAccessRow,
} from "../lib/access.mjs";
import {
  StoreError,
  assertDocId,
  docState,
  read,
  suggestionKey,
  suggestionPrefix,
} from "../lib/store.mjs";
import { appendEvent } from "./events.mjs";
import { ApplyError, readEffectiveBase } from "../lib/gitedit.mjs";
import { notify } from "../lib/notify.mjs";
import { toHtml, toMd } from "../lib/inline-md.mjs";
import { createHash, randomBytes } from "node:crypto";

const JSON_TYPE = "application/json; charset=utf-8";
const NO_STORE = "private, no-store";
const MAX_BODY_BYTES = 16_384;
const MAX_LIST_PAGES = 10;
const MAX_LIST_KEYS = 10_000;
const MAX_PAGE_ENTRIES = 1_000;
const MAX_LISTED_KEY_BYTES = 96;
const MAX_RESPONSE_BYTES = 67_108_864;
const MIN_NOW_MS = 1_000_000_000_000;
const MAX_NOW_MS = 9_999_999_999_999;
const REAP_AGE_MS = 14 * 24 * 60 * 60 * 1_000;

const DOC_ID = /^[0-9a-f]{6}$/;
const AID = /^a[0-9a-f]{8}$/;
const SUGGESTION_ID = /^s_[a-z0-9]{1,48}_[0-9a-f]{8}$/;
const SECTION = /^[a-z0-9][a-z0-9._-]*$/;
const HASH = /^[0-9a-f]{64}$/;
const DOC_VERSION = /^[0-9a-f]{7,64}$/;
const SUBJECT = /^[A-Za-z0-9][A-Za-z0-9._~-]{0,127}$/;
const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const MEDIA_TYPE =
  /^[ \t]*([!#$%&'*+.^_`|~0-9A-Za-z-]+)\/([!#$%&'*+.^_`|~0-9A-Za-z-]+)[ \t]*(?:;[ \t]*[!#$%&'*+.^_`|~0-9A-Za-z-]+=(?:[!#$%&'*+.^_`|~0-9A-Za-z-]+|"(?:[^"\\\x00-\x1f\x7f]|\\[\x00-\x7f])*")[ \t]*)*$/;
const INTEGER = /^(?:0|[1-9][0-9]*)$/;
const BARRED_SCALAR = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/;
const LONE_SURROGATE =
  /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

const RECORD_KEYS = Object.freeze([
  "v", "id", "docId", "aid", "section", "text", "note", "by", "at",
  "baseHash", "baseText", "docVersion",
]);
const ACTOR_KEYS = Object.freeze(["sub", "name", "email"]);
const EFFECTIVE_KEYS = Object.freeze([
  "mode", "docId", "aid", "section", "tag", "docVersion", "manifestHash",
  "hash", "text", "pending",
]);
const ACCESS_KEYS = Object.freeze([
  "role", "shared", "canRead", "canComment", "threadControl", "canSuggest",
  "canEdit", "canAccept", "canShare", "canSeeMembers",
]);
const CREATE_BODY_KEYS = Object.freeze([
  "docId", "aid", "text", "note", "baseHash", "baseText",
]);
const DEPENDENCY_KEYS = Object.freeze([
  "requireOriginFn", "identifyFn", "resolveRoleFn", "capabilitiesForFn", "storeFn",
  "readEffectiveBaseFn", "appendEventFn", "notifyFn", "nowFn", "randomBytesFn",
  "sha256Fn", "toHtmlFn", "toMdFn",
]);

const PUBLIC_ERRORS = Object.freeze({
  "invalid-request": [400, "Invalid request"],
  "invalid-body": [400, "Invalid request body"],
  unauthenticated: [401, "Authentication required"],
  forbidden: [403, "Suggestion access denied"],
  "not-found": [404, "Suggestion or block not found"],
  "method-not-allowed": [405, "Method not allowed"],
  conflict: [409, "The block changed since this document was built"],
  "suggestion-limit": [409, "Decide the open suggestions first"],
  "suggestion-id-collision": [409, "Generated suggestion identifier collision"],
  "event-id-collision": [409, "Generated event identifier collision"],
  "payload-too-large": [413, "Request body exceeds 16384 bytes"],
  "unsupported-media-type": [415, "Content-Type must be application/json"],
  "invalid-state": [500, "Invalid suggestion state"],
  "repository-unavailable": [502, "Repository write unavailable"],
  unavailable: [503, "Suggestion state unavailable"],
  "resource-limit": [503, "Suggestion response exceeds 67108864 bytes"],
});

class Failure extends Error {
  constructor(code, current = undefined) {
    super(code);
    this.code = code;
    this.current = current;
  }
}

const fail = (code, current) => new Failure(code, current);
const hasOwn = (value, key) => Object.prototype.hasOwnProperty.call(value, key);
const rawCompare = (left, right) => left < right ? -1 : left > right ? 1 : 0;

function dataDescriptor(value, key) {
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  return descriptor !== undefined && hasOwn(descriptor, "value") && descriptor.enumerable === true;
}

function ownDataNames(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value) ||
      Object.getPrototypeOf(value) !== Object.prototype ||
      Object.getOwnPropertySymbols(value).length !== 0) return null;
  const names = Object.getOwnPropertyNames(value);
  return names.every((name) => dataDescriptor(value, name)) ? names : null;
}

function exactObject(value, keys, ordered = false) {
  let names;
  try {
    names = ownDataNames(value);
  } catch {
    return false;
  }
  if (names === null || names.length !== keys.length) return false;
  return ordered
    ? keys.every((key, index) => names[index] === key)
    : keys.every((key) => names.includes(key));
}

function denseArray(value) {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype ||
      Object.getOwnPropertySymbols(value).length !== 0) return false;
  const names = Object.getOwnPropertyNames(value);
  if (names.length !== value.length + 1 || names.at(-1) !== "length") return false;
  return Array.from({ length: value.length }, (_, index) => String(index))
    .every((name, index) => names[index] === name && dataDescriptor(value, name));
}

function cleanText(value, maximum) {
  return typeof value === "string" && value.length <= maximum &&
    !BARRED_SCALAR.test(value) && !LONE_SURROGATE.test(value);
}

function timestamp(value) {
  if (typeof value !== "string" || !TIMESTAMP.test(value)) return false;
  try {
    return new Date(value).toISOString() === value;
  } catch {
    return false;
  }
}

function normalizedEmail(value) {
  if (value === "") return true;
  try {
    return typeof value === "string" && normalizeEmail(value) === value;
  } catch {
    return false;
  }
}

function actorOf(value) {
  if (!exactObject(value, ACTOR_KEYS, true)) return null;
  if (typeof value.sub !== "string" || !SUBJECT.test(value.sub) ||
      typeof value.name !== "string" || value.name.length > 200 ||
      !normalizedEmail(value.email)) return null;
  if (value.sub === "system" && (value.name !== "Build" || value.email !== "")) return null;
  return { sub: value.sub, name: value.name, email: value.email };
}

function editable(deps, value) {
  if (!cleanText(value, 4_000)) return false;
  try {
    const html = deps.toHtmlFn(value);
    return typeof html === "string" && deps.toMdFn(html) === value;
  } catch {
    return false;
  }
}

function suggestionAtKey(value, docId, fullKey, deps) {
  if (typeof docId !== "string" || !DOC_ID.test(docId) ||
      typeof fullKey !== "string" || !exactObject(value, RECORD_KEYS, true)) {
    throw new TypeError("Invalid suggestion");
  }
  const by = actorOf(value.by);
  if (value.v !== 1 || typeof value.id !== "string" || !SUGGESTION_ID.test(value.id) ||
      value.docId !== docId || typeof value.aid !== "string" || !AID.test(value.aid) ||
      typeof value.section !== "string" || !SECTION.test(value.section) ||
      !editable(deps, value.text) || !cleanText(value.note, 280) ||
      !editable(deps, value.baseText) || by === null || !timestamp(value.at) ||
      typeof value.baseHash !== "string" || !HASH.test(value.baseHash) ||
      typeof value.docVersion !== "string" || !DOC_VERSION.test(value.docVersion)) {
    throw new TypeError("Invalid suggestion");
  }
  let canonical;
  try {
    canonical = suggestionKey(docId, value.aid, value.id);
  } catch {
    throw new TypeError("Invalid suggestion");
  }
  if (fullKey !== canonical) throw new TypeError("Invalid suggestion");
  return {
    v: 1,
    id: value.id,
    docId,
    aid: value.aid,
    section: value.section,
    text: value.text,
    note: value.note,
    by,
    at: value.at,
    baseHash: value.baseHash,
    baseText: value.baseText,
    docVersion: value.docVersion,
  };
}

/** Validate and freshly clone one immutable suggestion at its exact P2-B key. */
export function assertSuggestionAtKey(value, docId, fullKey) {
  return suggestionAtKey(value, docId, fullKey, {
    toHtmlFn: toHtml,
    toMdFn: toMd,
  });
}

function response(status, body, extra = {}) {
  return new Response(typeof body === "string" ? body : JSON.stringify(body), {
    status,
    headers: { "Cache-Control": NO_STORE, "Content-Type": JSON_TYPE, ...extra },
  });
}

function errorResponse(error) {
  const code = hasOwn(PUBLIC_ERRORS, error.code) ? error.code : "invalid-state";
  const [status, message] = PUBLIC_ERRORS[code];
  const body = { error: { code, message } };
  if (code === "conflict") body.current = error.current;
  return response(status, body, code === "method-not-allowed" ? { Allow: "GET, POST" } : {});
}

function safeOwnValue(value, key) {
  if (value === null || typeof value !== "object") return undefined;
  try {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    return descriptor !== undefined && hasOwn(descriptor, "value") && descriptor.enumerable === true
      ? descriptor.value
      : undefined;
  } catch {
    return undefined;
  }
}

function accessUnavailable(error) {
  return safeOwnValue(error, "name") === "StoreError" &&
    safeOwnValue(error, "code") === "unavailable" && safeOwnValue(error, "status") === 503;
}

function storeFailure(error) {
  if (!(error instanceof StoreError)) return fail("invalid-state");
  const code = safeOwnValue(error, "code");
  const status = safeOwnValue(error, "status");
  return fail(code === "unavailable" && status === 503 ? "unavailable" : "invalid-state");
}

function applyFailure(error) {
  if (!(error instanceof ApplyError)) return fail("invalid-state");
  const code = safeOwnValue(error, "code");
  const status = safeOwnValue(error, "status");
  if (!hasOwn(PUBLIC_ERRORS, code) || PUBLIC_ERRORS[code][0] !== status) return fail("invalid-state");
  if (code === "conflict") {
    const hash = safeOwnValue(error, "currentHash");
    const text = safeOwnValue(error, "current");
    if (typeof hash !== "string" || !HASH.test(hash) || !(text === null || typeof text === "string")) {
      return fail("invalid-state");
    }
    return fail("conflict", { hash, text });
  }
  return fail(code);
}

function captureDependencies(dependencies) {
  let names;
  try {
    names = Object.getOwnPropertyNames(dependencies);
  } catch {
    throw new TypeError("Invalid suggestion dependencies");
  }
  if (!exactObject(dependencies, names)) throw new TypeError("Invalid suggestion dependencies");
  if (names.some((name) => !DEPENDENCY_KEYS.includes(name) || typeof dependencies[name] !== "function")) {
    throw new TypeError("Invalid suggestion dependencies");
  }
  return Object.freeze({
    requireOriginFn: dependencies.requireOriginFn ?? requireOrigin,
    identifyFn: dependencies.identifyFn ?? identify,
    resolveRoleFn: dependencies.resolveRoleFn ?? resolveRole,
    capabilitiesForFn: dependencies.capabilitiesForFn ?? capabilitiesFor,
    storeFn: dependencies.storeFn ?? docState,
    readEffectiveBaseFn: dependencies.readEffectiveBaseFn ?? readEffectiveBase,
    appendEventFn: dependencies.appendEventFn ?? appendEvent,
    notifyFn: dependencies.notifyFn ?? notify,
    nowFn: dependencies.nowFn ?? Date.now,
    randomBytesFn: dependencies.randomBytesFn ?? randomBytes,
    sha256Fn: dependencies.sha256Fn ??
      ((value) => createHash("sha256").update(value, "utf8").digest("hex")),
    toHtmlFn: dependencies.toHtmlFn ?? toHtml,
    toMdFn: dependencies.toMdFn ?? toMd,
  });
}

function query(req, create) {
  let url;
  try {
    url = new URL(req.url);
  } catch {
    throw fail("invalid-request");
  }
  const entries = [...url.searchParams];
  if (create) {
    if (url.search !== "" || req.url.includes("?")) throw fail("invalid-request");
    return null;
  }
  if (entries.length !== 1 || entries[0][0] !== "doc") {
    throw fail("invalid-request");
  }
  try {
    return assertDocId(entries[0][1]);
  } catch {
    throw fail("invalid-request");
  }
}

function jsonMediaType(req) {
  let header;
  try {
    header = req.headers.get("content-type");
  } catch {
    return false;
  }
  if (typeof header !== "string") return false;
  const match = header.match(MEDIA_TYPE);
  return match !== null && `${match[1]}/${match[2]}`.toLowerCase() === "application/json";
}

async function readBody(req) {
  if (!jsonMediaType(req)) throw fail("unsupported-media-type");
  let declared;
  try {
    declared = req.headers.get("content-length");
  } catch {
    throw fail("invalid-body");
  }
  if (declared !== null) {
    if (!INTEGER.test(declared) || !Number.isSafeInteger(Number(declared))) throw fail("invalid-body");
    if (Number(declared) > MAX_BODY_BYTES) throw fail("payload-too-large");
  }
  const body = req.body;
  if (body === null || typeof body?.getReader !== "function" || body.locked === true) {
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
      const item = await reader.read();
      if (item.done === true) break;
      if (!(item.value instanceof Uint8Array)) { failure = "invalid-body"; break; }
      if (total + item.value.byteLength > MAX_BODY_BYTES) {
        failure = "payload-too-large";
        break;
      }
      chunks.push(item.value);
      total += item.value.byteLength;
    }
  } catch {
    failure = "invalid-body";
  }
  if (failure !== null) {
    try { await reader.cancel(); } catch {}
  }
  try { reader.releaseLock(); } catch {}
  if (failure !== null) throw fail(failure);
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  let parsed;
  try {
    parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes));
  } catch {
    throw fail("invalid-body");
  }
  if (!exactObject(parsed, CREATE_BODY_KEYS)) throw fail("invalid-body");
  return parsed;
}

function identityActor(value) {
  if (!exactObject(value, ["sub", "email", "name", "isOrg"])) throw fail("invalid-state");
  const actor = actorOf({ sub: value.sub, name: value.name, email: value.email });
  if (actor === null || actor.sub === "system" || typeof value.isOrg !== "boolean") {
    throw fail("invalid-state");
  }
  return actor;
}

async function authorize(deps, docId, identity, capability) {
  let access;
  try {
    access = await deps.resolveRoleFn(docId, identity, { consumeInvitation: false });
  } catch (error) {
    throw fail(accessUnavailable(error) ? "unavailable" : "invalid-state");
  }
  if (!validateAccessRow(access, deps.capabilitiesForFn) || !exactObject(access, ACCESS_KEYS, true)) {
    throw fail("invalid-state");
  }
  if (access[capability] !== true) throw fail("forbidden");
}

function sha256(deps, value) {
  let digest;
  try { digest = deps.sha256Fn(value); } catch { throw fail("invalid-state"); }
  if (typeof digest !== "string" || !HASH.test(digest)) throw fail("invalid-state");
  return digest;
}

function htmlOf(deps, value) {
  let html;
  try { html = deps.toHtmlFn(value); } catch { throw fail("invalid-state"); }
  if (typeof html !== "string") throw fail("invalid-state");
  return html;
}

function effectiveOf(deps, value, docId, aid) {
  if (!exactObject(value, EFFECTIVE_KEYS, true) ||
      (value.mode !== "standalone" && value.mode !== "repository") ||
      value.docId !== docId || value.aid !== aid ||
      typeof value.section !== "string" || !SECTION.test(value.section) ||
      !["p", "h2", "h3", "h4"].includes(value.tag) ||
      typeof value.docVersion !== "string" || !DOC_VERSION.test(value.docVersion) ||
      (value.mode === "standalone" && value.docVersion.length !== 7) ||
      typeof value.manifestHash !== "string" || !HASH.test(value.manifestHash) ||
      typeof value.hash !== "string" || !HASH.test(value.hash) ||
      typeof value.pending !== "boolean") throw fail("invalid-state");
  if (value.pending === false) {
    if (value.text !== null || value.hash !== value.manifestHash) throw fail("invalid-state");
  } else if (!editable(deps, value.text) || sha256(deps, htmlOf(deps, value.text)) !== value.hash) {
    throw fail("invalid-state");
  }
  return {
    mode: value.mode, docId, aid, section: value.section, tag: value.tag,
    docVersion: value.docVersion, manifestHash: value.manifestHash, hash: value.hash,
    text: value.text, pending: value.pending,
  };
}

async function effectiveRead(deps, docId, aid) {
  let value;
  try { value = await deps.readEffectiveBaseFn(docId, aid); }
  catch (error) { throw applyFailure(error); }
  return effectiveOf(deps, value, docId, aid);
}

function pageKeys(page) {
  const names = ownDataNames(page);
  if (names === null || !names.includes("blobs") || !names.includes("directories") ||
      !denseArray(page.directories) || page.directories.length !== 0 ||
      !denseArray(page.blobs) || page.blobs.length > MAX_PAGE_ENTRIES) throw fail("unavailable");
  return page.blobs.map((entry) => {
    const entryNames = ownDataNames(entry);
    if (entryNames === null || !entryNames.includes("key") || typeof entry.key !== "string" ||
        Buffer.byteLength(entry.key, "utf8") > MAX_LISTED_KEY_BYTES) throw fail("unavailable");
    return entry.key;
  });
}

async function listedKeys(store, prefix, stopAtFive = false) {
  let listing;
  try { listing = store.list({ prefix, paginate: true }); }
  catch { throw fail("unavailable"); }
  if (listing === null || typeof listing !== "object") throw fail("unavailable");
  let iterator;
  try {
    const factory = listing[Symbol.asyncIterator];
    iterator = typeof factory === "function" ? factory.call(listing) : null;
  } catch { throw fail("unavailable"); }
  if (iterator === null || typeof iterator !== "object" || typeof iterator.next !== "function") {
    throw fail("unavailable");
  }
  const keys = [];
  const seen = new Set();
  const prefixDepth = prefix.split("/").length;
  for (let pull = 0; pull <= MAX_LIST_PAGES; pull += 1) {
    let result;
    try { result = await iterator.next(); } catch { throw fail("unavailable"); }
    if (!exactObject(result, ["done", "value"]) || typeof result.done !== "boolean") {
      throw fail("unavailable");
    }
    if (result.done === true) {
      if (result.value !== undefined) throw fail("unavailable");
      return keys;
    }
    if (pull === MAX_LIST_PAGES) throw fail("unavailable");
    for (const key of pageKeys(result.value)) {
      if (!key.startsWith(prefix) || !key.endsWith(".json") || seen.has(key)) {
        throw fail("invalid-state");
      }
      const tail = key.slice(prefix.length, -5);
      const parts = tail.split("/");
      if ((prefixDepth === 4 && parts.length !== 1) ||
          (prefixDepth === 3 && parts.length !== 2) ||
          !SUGGESTION_ID.test(parts.at(-1)) || (parts.length === 2 && !AID.test(parts[0]))) {
        throw fail("invalid-state");
      }
      seen.add(key);
      keys.push(key);
      if (keys.length > MAX_LIST_KEYS) throw fail("unavailable");
      if (stopAtFive && keys.length === 5) return keys;
    }
  }
  throw fail("unavailable");
}

function openStore(deps) {
  let store;
  try { store = deps.storeFn(); } catch (error) { throw storeFailure(error); }
  if (store === null || typeof store !== "object" || typeof store.list !== "function" ||
      typeof store.getWithMetadata !== "function" || typeof store.setJSON !== "function" ||
      typeof store.delete !== "function") throw fail("invalid-state");
  return store;
}

async function readSuggestion(deps, store, key, docId) {
  let found;
  try { found = await read(store, key, null); } catch (error) { throw storeFailure(error); }
  if (found.value === null) return null;
  try { return suggestionAtKey(found.value, docId, key, deps); }
  catch { throw fail("invalid-state"); }
}

function sampleNow(deps) {
  let now;
  try { now = deps.nowFn(); } catch { throw fail("invalid-state"); }
  if (!Number.isSafeInteger(now) || now < MIN_NOW_MS || now > MAX_NOW_MS) {
    throw fail("invalid-state");
  }
  try { new Date(now).toISOString(); } catch { throw fail("invalid-state"); }
  return now;
}

function randomHex(deps) {
  let bytes;
  try { bytes = deps.randomBytesFn(4); } catch { throw fail("invalid-state"); }
  if (!(bytes instanceof Uint8Array) || bytes.length !== 4) throw fail("invalid-state");
  return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function listSuggestions(deps, req) {
  const docId = query(req, false);
  let identity;
  try { identity = await deps.identifyFn(req); } catch { throw fail("invalid-state"); }
  if (identity === null) throw fail("unauthenticated");
  identityActor(identity);
  await authorize(deps, docId, identity, "canRead");
  const store = openStore(deps);
  const prefix = suggestionPrefix(docId);
  const keys = (await listedKeys(store, prefix)).sort(rawCompare);
  const records = [];
  for (const key of keys) {
    const record = await readSuggestion(deps, store, key, docId);
    if (record !== null) records.push({ record, key });
  }
  records.sort((left, right) => rawCompare(left.record.at, right.record.at) ||
    rawCompare(left.record.id, right.record.id) || rawCompare(left.record.aid, right.record.aid));
  const bases = new Map();
  const classified = [];
  for (const item of records) {
    let base = bases.get(item.record.aid);
    if (base === undefined) {
      try { base = await effectiveRead(deps, docId, item.record.aid); }
      catch (error) {
        if (error instanceof Failure && error.code === "not-found") base = null;
        else throw error;
      }
      bases.set(item.record.aid, base);
    }
    classified.push({ ...item, state: base !== null && item.record.baseHash === base.hash
      ? "open" : "superseded", deleted: false });
  }
  const now = sampleNow(deps);
  let attempted = 0;
  for (const item of classified) {
    if (attempted === 10) break;
    if (item.state !== "superseded" || Date.parse(item.record.at) + REAP_AGE_MS > now) continue;
    attempted += 1;
    try {
      await deps.appendEventFn({
        store, docId, actor: { sub: "system", name: "Build", email: "" },
        kind: "suggest.supersede",
        target: { suggestionId: item.record.id, aid: item.record.aid },
        docVersion: item.record.docVersion,
        summary: `superseded suggestion in ${item.record.section}`,
      });
      await store.delete(item.key);
      item.deleted = true;
    } catch {}
  }
  const perAid = new Map();
  const projection = [];
  for (const item of classified) {
    if (item.deleted) continue;
    const count = perAid.get(item.record.aid) ?? 0;
    if (count >= 5) continue;
    perAid.set(item.record.aid, count + 1);
    projection.push({ ...item.record, state: item.state });
  }
  const body = JSON.stringify(projection);
  if (Buffer.byteLength(body, "utf8") > MAX_RESPONSE_BYTES) throw fail("resource-limit");
  return response(200, body);
}

function parseCreate(deps, body) {
  const { docId, aid, text, note, baseHash, baseText } = body;
  if (typeof docId !== "string" || !DOC_ID.test(docId) || typeof aid !== "string" || !AID.test(aid) ||
      !editable(deps, text) || !cleanText(note, 280) ||
      !editable(deps, baseText) || typeof baseHash !== "string" || !HASH.test(baseHash)) {
    throw fail("invalid-body");
  }
  return { docId, aid, text, note, baseHash, baseText };
}

async function createSuggestion(deps, req, context) {
  try { deps.requireOriginFn(req); }
  catch (error) { if (error instanceof Response) return error; throw fail("invalid-state"); }
  query(req, true);
  let identity;
  try { identity = await deps.identifyFn(req); } catch { throw fail("invalid-state"); }
  if (identity === null) throw fail("unauthenticated");
  const actor = identityActor(identity);
  const input = parseCreate(deps, await readBody(req));
  await authorize(deps, input.docId, identity, "canSuggest");
  const effective = await effectiveRead(deps, input.docId, input.aid);
  if (input.baseHash !== effective.hash) {
    throw fail("conflict", { hash: effective.hash, text: effective.text });
  }
  if (sha256(deps, htmlOf(deps, input.baseText)) !== input.baseHash) throw fail("invalid-body");
  if (sha256(deps, htmlOf(deps, input.text)) === input.baseHash) throw fail("invalid-body");
  if (effective.mode === "repository" && actor.email === "") throw fail("invalid-state");
  const store = openStore(deps);
  const prefix = suggestionPrefix(input.docId, input.aid);
  if ((await listedKeys(store, prefix, true)).length === 5) throw fail("suggestion-limit");
  const now = sampleNow(deps);
  const id = `s_${now.toString(36)}_${randomHex(deps)}`;
  const record = {
    v: 1, id, docId: input.docId, aid: input.aid, section: effective.section,
    text: input.text, note: input.note, by: actor, at: new Date(now).toISOString(),
    baseHash: input.baseHash, baseText: input.baseText, docVersion: effective.docVersion,
  };
  const key = suggestionKey(input.docId, input.aid, id);
  let valid;
  try { valid = suggestionAtKey(record, input.docId, key, deps); }
  catch { throw fail("invalid-state"); }
  let result;
  try { result = await store.setJSON(key, valid, { onlyIfNew: true }); }
  catch { throw fail("unavailable"); }
  const modified = safeOwnValue(result, "modified");
  if (modified === false) throw fail("suggestion-id-collision");
  if (modified !== true) throw fail("unavailable");
  try {
    await deps.appendEventFn({
      store, docId: input.docId, actor: { ...actor }, kind: "suggest.create",
      target: { suggestionId: id, aid: input.aid }, docVersion: effective.docVersion,
      summary: `suggested ${effective.section}`,
    });
  } catch {}
  try {
    deps.notifyFn(context, {
      t: "suggest.created", docId: input.docId, suggestionId: id, aid: input.aid,
      actorName: actor.name, text: input.text,
    });
  } catch {}
  return response(201, valid);
}

export function createSuggestionsHandler(dependencies = {}) {
  const deps = captureDependencies(dependencies);
  return async function handleSuggestions(req, context) {
    if (req.method !== "GET" && req.method !== "POST") {
      return errorResponse(fail("method-not-allowed"));
    }
    try {
      return req.method === "GET"
        ? await listSuggestions(deps, req)
        : await createSuggestion(deps, req, context);
    } catch (error) {
      if (error instanceof Response) return error;
      return errorResponse(error instanceof Failure ? error : fail("invalid-state"));
    }
  };
}

const production = createSuggestionsHandler();

export default async function handler(req, context) {
  return production(req, context);
}

export const config = { path: "/api/suggestions" };
