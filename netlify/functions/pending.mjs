import { identify } from "../lib/identity.mjs";
import {
  assertIdentitySub, capabilitiesFor, normalizeEmail, resolveRole, validateAccessRow,
} from "../lib/access.mjs";
import { StoreError, docState, editKey, editPrefix, read, upgrade } from "../lib/store.mjs";
import { ApplyError, readApplyManifest } from "../lib/gitedit.mjs";

// GET /api/pending?doc=<docId> — the read-only pending-edit overlay (P3-E).
//
// The handler authenticates through identify(), authorizes through the
// complete default resolveRole() result, binds the request to the one
// authoritative edit manifest for that permanent document ID, lists and
// strongly reads the receipts under edits/<docId>/, omits receipts whose block
// has landed or disappeared, and projects the fresh ones in manifest order. It
// never writes.
//
// The manifest is selected by exactly one call into the shared apply library,
// so a standalone overlay and a repository overlay are read against the very
// same row hashes the apply path wrote against. This handler owns no manifest
// algorithm, no configuration, no filesystem root, and no request-selected
// path of its own.

const NO_STORE = "private, no-store";
const JSON_TYPE = "application/json; charset=utf-8";

const DEPENDENCY_KEYS = Object.freeze([
  "identify", "resolveRole", "capabilitiesFor", "assertIdentitySub", "normalizeEmail",
  "docState", "editPrefix", "editKey", "read", "upgrade", "readApplyManifestFn",
]);
const MANIFEST_KEYS = Object.freeze(["docId", "instance", "commit", "blocks"]);
const ROW_KEYS = Object.freeze(["file", "section", "tag", "hash"]);
const SELECTION_KEYS = Object.freeze(["mode", "manifest"]);
const MODES = Object.freeze(["repository", "standalone"]);
const TAGS = Object.freeze(["p", "h2", "h3", "h4"]);
const PAGE_KEYS = Object.freeze(["blobs", "directories"]);
const ENVELOPE_KEYS = Object.freeze(["value", "etag"]);
const ACTOR_KEYS = Object.freeze(["sub", "name", "email"]);
const RECEIPT_KEYS = Object.freeze(["v", "aid", "text", "by", "at", "baseHash", "pr"]);
const DIRECT_KEYS = Object.freeze([...RECEIPT_KEYS, "via"]);
const SUGGESTION_KEYS = Object.freeze([...DIRECT_KEYS, "sugId", "acceptedBy", "acceptedAt"]);
const QUERY_PATTERN = /^\?doc=([0-9a-f]{6})$/;
const DOC_ID_PATTERN = /^[0-9a-f]{6}$/;
const INSTANCE_PATTERN = /^[A-Za-z0-9]+(?:[._-][A-Za-z0-9]+)*$/;
const COMMIT_PATTERN = /^(?:[0-9a-f]{7,64})?$/;
const AID_PATTERN = /^a[0-9a-f]{8}$/;
const FILE_PATTERN = /^sections\/[a-z0-9]+(?:[._-][a-z0-9]+)*\.html$/;
const HASH_PATTERN = /^[0-9a-f]{64}$/;
const KEY_SUFFIX_PATTERN = /^(a[0-9a-f]{8})\.json$/;
const TIMESTAMP_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const SUGGESTION_ID_PATTERN = /^s_[a-z0-9]{1,48}_[0-9a-f]{8}$/;

const MAX_MANIFEST_BLOCKS = 5_000;
const MAX_PAGES = 8;
const MAX_PAGE_BLOBS = 1_000;
const MAX_LISTED = 5_000;
const MAX_TEXT = 4_000;
const MAX_NAME = 200;

/** A private control-flow error carrying only an HTTP status. */
class Failure extends Error {
  constructor(status) {
    super("pending");
    this.status = status;
  }
}

const fail = (status) => new Failure(status);

/** Thrown list/read provider failures are 503 unless P2-B classified them. */
function providerStatus(error) {
  if (error instanceof Failure) return error.status;
  if (error instanceof StoreError) return error.code === "unavailable" ? 503 : 500;
  return 503;
}

function statusOf(error) {
  if (error instanceof Failure) return error.status;
  return 500;
}

function respond(status, body = null, extra = null) {
  const headers = { "Cache-Control": NO_STORE };
  if (extra !== null) Object.assign(headers, extra);
  return new Response(body, { status, headers });
}

const rawCompare = (a, b) => (a < b ? -1 : a > b ? 1 : 0);

function sameSet(actual, expected) {
  if (actual.length !== expected.length) return false;
  const sorted = [...actual].sort(rawCompare);
  const wanted = [...expected].sort(rawCompare);
  return wanted.every((key, index) => sorted[index] === key);
}

function isDataDescriptor(object, key) {
  const descriptor = Object.getOwnPropertyDescriptor(object, key);
  return descriptor !== undefined &&
    Object.prototype.hasOwnProperty.call(descriptor, "value") &&
    descriptor.enumerable === true;
}

/** Ordinary object whose own keys are exactly `keys` in that order, all
 * enumerable data properties. This checks the manifest, selection and row
 * boundaries this handler owns; the access row is checked by the shared
 * `validateAccessRow()` instead. */
function isExactOrderedObject(value, keys) {
  if (value === null || typeof value !== "object" || Array.isArray(value) ||
      Object.getPrototypeOf(value) !== Object.prototype) {
    return false;
  }
  const own = Reflect.ownKeys(value);
  if (own.length !== keys.length || !keys.every((key, index) => own[index] === key)) {
    return false;
  }
  return keys.every((key) => isDataDescriptor(value, key));
}

/** Plain JSON-style object: Object.prototype (or null) prototype, no symbols,
 * every own property an enumerable data property. */
function isPlainRecord(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null) return false;
  if (Object.getOwnPropertySymbols(value).length !== 0) return false;
  return Object.getOwnPropertyNames(value).every((key) => isDataDescriptor(value, key));
}

/** Plain record whose own keys equal `keys` as a set. */
function isExactRecord(value, keys) {
  return isPlainRecord(value) && sameSet(Object.getOwnPropertyNames(value), keys);
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

// --- Dependencies -----------------------------------------------------------

function captureDependencies(dependencies) {
  if (dependencies === null || typeof dependencies !== "object" || Array.isArray(dependencies) ||
      Object.getPrototypeOf(dependencies) !== Object.prototype ||
      Object.getOwnPropertySymbols(dependencies).length !== 0 ||
      !sameSet(Object.getOwnPropertyNames(dependencies), DEPENDENCY_KEYS)) {
    throw new TypeError("Invalid pending dependencies");
  }
  const captured = {};
  for (const key of DEPENDENCY_KEYS) {
    const descriptor = Object.getOwnPropertyDescriptor(dependencies, key);
    if (descriptor === undefined ||
        !Object.prototype.hasOwnProperty.call(descriptor, "value") ||
        descriptor.enumerable !== true || descriptor.writable !== true ||
        descriptor.configurable !== true || typeof descriptor.value !== "function") {
      throw new TypeError("Invalid pending dependencies");
    }
    captured[key] = descriptor.value;
  }
  return Object.freeze(captured);
}

// --- Query and access -------------------------------------------------------

function parseDocId(url) {
  let search;
  try {
    search = new URL(url).search;
  } catch {
    throw fail(400);
  }
  const match = QUERY_PATTERN.exec(search);
  if (match === null) throw fail(400);
  return match[1];
}

/** Validate the complete resolved access against the canonical capability
 * row and return the exact boolean canRead. Anything else is 500.
 *
 * The check itself is the shared one, run against the injected capability
 * table rather than the module's own import, so a handler built by
 * `createPendingHandler()` validates against the table it was actually given. */
function validateAccess(access, deps) {
  if (!validateAccessRow(access, deps.capabilitiesFor)) throw fail(500);
  return access.canRead;
}

// --- Manifest selection -----------------------------------------------------

/**
 * Validate the exact `{mode, manifest}` boundary the apply library returns and
 * project it into the ordered rows this handler lists against.
 *
 * The boundary is validated rather than trusted: a test double, a future
 * library, or a drifted deployment cannot widen what this read-only route
 * accepts. This handler still performs no manifest algorithm of its own — it
 * neither discovers files, nor inspects configuration, nor reads a document's
 * built HTML, nor lets a request choose a path.
 */
function projectSelection(value, docId) {
  if (!isExactOrderedObject(value, SELECTION_KEYS)) throw fail(500);
  if (typeof value.mode !== "string" || !MODES.includes(value.mode)) throw fail(500);
  const manifest = value.manifest;
  if (!isExactOrderedObject(manifest, MANIFEST_KEYS)) throw fail(500);
  if (manifest.docId !== docId || !DOC_ID_PATTERN.test(manifest.docId)) throw fail(500);
  if (typeof manifest.instance !== "string" || !INSTANCE_PATTERN.test(manifest.instance)) {
    throw fail(500);
  }
  if (typeof manifest.commit !== "string" || !COMMIT_PATTERN.test(manifest.commit)) {
    throw fail(500);
  }
  const blocks = manifest.blocks;
  if (!isPlainRecord(blocks) || Object.getPrototypeOf(blocks) !== Object.prototype) {
    throw fail(500);
  }
  const aids = Reflect.ownKeys(blocks);
  if (aids.length > MAX_MANIFEST_BLOCKS) throw fail(503);
  const order = [];
  const hashes = new Map();
  for (const aid of aids) {
    if (typeof aid !== "string" || !AID_PATTERN.test(aid)) throw fail(500);
    const row = blocks[aid];
    if (!isExactOrderedObject(row, ROW_KEYS)) throw fail(500);
    if (typeof row.file !== "string" || !FILE_PATTERN.test(row.file) ||
        typeof row.section !== "string" || row.section.length === 0 ||
        typeof row.tag !== "string" || !TAGS.includes(row.tag) ||
        typeof row.hash !== "string" || !HASH_PATTERN.test(row.hash)) {
      throw fail(500);
    }
    order.push(aid);
    hashes.set(aid, row.hash);
  }
  return Object.freeze({ docId: manifest.docId, order: Object.freeze(order), hashes });
}

/**
 * Select the one authoritative manifest through the shared apply library.
 *
 * Only an `ApplyError` this module imported may steer the public status, and
 * only its 404 and 503 map to this route's existing empty bodies. Every other
 * instance, value, or throw is this route's empty 500: a manifest selection
 * that failed for an unexplained reason is not a missing document.
 */
async function selectManifest(deps, docId) {
  let selection;
  try {
    selection = await deps.readApplyManifestFn(docId);
  } catch (error) {
    if (error instanceof ApplyError && error.status === 404) throw fail(404);
    if (error instanceof ApplyError && error.status === 503) throw fail(503);
    throw fail(500);
  }
  return projectSelection(selection, docId);
}

// --- Receipts ---------------------------------------------------------------

function validatePage(page) {
  if (!isPlainRecord(page) || Object.getPrototypeOf(page) !== Object.prototype ||
      !sameSet(Object.getOwnPropertyNames(page), PAGE_KEYS)) {
    throw fail(500);
  }
  const { blobs, directories } = page;
  if (!isDenseArray(blobs) || blobs.length > MAX_PAGE_BLOBS ||
      !isDenseArray(directories) || directories.length !== 0) {
    throw fail(500);
  }
  return blobs;
}

function validateBlob(blob, prefix, docId, deps) {
  if (blob === null || typeof blob !== "object" || Array.isArray(blob) ||
      Object.getPrototypeOf(blob) !== Object.prototype ||
      Object.getOwnPropertySymbols(blob).length !== 0 ||
      !isDataDescriptor(blob, "key") || !isDataDescriptor(blob, "etag")) {
    throw fail(500);
  }
  const { key, etag } = blob;
  if (typeof key !== "string" || key.length === 0 ||
      typeof etag !== "string" || etag.length === 0) {
    throw fail(500);
  }
  if (!key.startsWith(prefix)) throw fail(500);
  const match = KEY_SUFFIX_PATTERN.exec(key.slice(prefix.length));
  if (match === null) throw fail(500);
  let expected;
  try {
    expected = deps.editKey(docId, match[1]);
  } catch {
    throw fail(500);
  }
  if (expected !== key) throw fail(500);
  return { key, aid: match[1] };
}

async function listReceiptKeys(store, prefix, docId, deps) {
  let listing;
  try {
    listing = store.list({ prefix, paginate: true });
  } catch (error) {
    throw fail(providerStatus(error));
  }
  if (listing === null || (typeof listing !== "object" && typeof listing !== "function") ||
      typeof listing[Symbol.asyncIterator] !== "function") {
    throw fail(500);
  }
  const listed = new Map();
  let pages = 0;
  let entries = 0;
  try {
    for await (const page of listing) {
      pages += 1;
      if (pages > MAX_PAGES) throw fail(503);
      const blobs = validatePage(page);
      entries += blobs.length;
      if (entries > MAX_LISTED) throw fail(503);
      for (const blob of blobs) {
        const { key, aid } = validateBlob(blob, prefix, docId, deps);
        if (listed.has(key)) throw fail(500);
        listed.set(key, aid);
      }
    }
  } catch (error) {
    throw fail(providerStatus(error));
  }
  return [...listed.entries()]
    .map(([key, aid]) => ({ key, aid }))
    .sort((a, b) => rawCompare(a.key, b.key));
}

function validateActor(value, deps) {
  if (!isExactRecord(value, ACTOR_KEYS)) return false;
  const { sub, name, email } = value;
  if (typeof sub !== "string" || typeof name !== "string" || typeof email !== "string") return false;
  if (name.length > MAX_NAME) return false;
  try {
    if (deps.assertIdentitySub(sub) !== sub) return false;
    if (email.length !== 0 && deps.normalizeEmail(email) !== email) return false;
  } catch {
    return false;
  }
  return true;
}

function validateReceipt(value, deps) {
  if (!isPlainRecord(value)) throw fail(500);
  const names = Object.getOwnPropertyNames(value);
  const via = Object.prototype.hasOwnProperty.call(value, "via") ? value.via : undefined;
  let keys;
  if (via === undefined) keys = RECEIPT_KEYS;
  else if (via === "edit") keys = DIRECT_KEYS;
  else if (via === "suggestion") keys = SUGGESTION_KEYS;
  else throw fail(500);
  if (!sameSet(names, keys)) throw fail(500);
  const { v, aid, text, by, at, baseHash, pr } = value;
  if (v !== 1 ||
      typeof aid !== "string" || !AID_PATTERN.test(aid) ||
      typeof text !== "string" || text.length > MAX_TEXT ||
      !validateActor(by, deps) ||
      !isTimestamp(at) ||
      typeof baseHash !== "string" || !HASH_PATTERN.test(baseHash) ||
      !(pr === null || (Number.isSafeInteger(pr) && pr > 0))) {
    throw fail(500);
  }
  if (via === "suggestion") {
    const { sugId, acceptedBy, acceptedAt } = value;
    if (typeof sugId !== "string" || !SUGGESTION_ID_PATTERN.test(sugId) ||
        !validateActor(acceptedBy, deps) || !isTimestamp(acceptedAt)) {
      throw fail(500);
    }
  }
  return value;
}

async function readReceipts(store, listed, deps) {
  const hits = new Map();
  for (const { key, aid } of listed) {
    let found;
    try {
      found = await deps.read(store, key);
    } catch (error) {
      throw fail(providerStatus(error));
    }
    if (!isExactRecord(found, ENVELOPE_KEYS)) throw fail(500);
    const { value, etag } = found;
    if (value === null) {
      if (etag !== null) throw fail(500);
      continue;
    }
    if (typeof etag !== "string" || etag.length === 0) throw fail(500);
    let record;
    try {
      record = deps.upgrade(value);
    } catch {
      throw fail(500);
    }
    const receipt = validateReceipt(record, deps);
    if (receipt.aid !== aid) throw fail(500);
    hits.set(aid, receipt);
  }
  return hits;
}

function projectActor(actor) {
  return { sub: actor.sub, name: actor.name, email: actor.email };
}

function project(manifest, hits) {
  const overlay = {};
  for (const aid of manifest.order) {
    const receipt = hits.get(aid);
    if (receipt === undefined || manifest.hashes.get(aid) !== receipt.baseHash) continue;
    const entry = {
      text: receipt.text,
      by: projectActor(receipt.by),
      at: receipt.at,
      pr: receipt.pr,
    };
    if (Object.prototype.hasOwnProperty.call(receipt, "via")) entry.via = receipt.via;
    if (receipt.via === "suggestion") {
      entry.sugId = receipt.sugId;
      entry.acceptedBy = projectActor(receipt.acceptedBy);
      entry.acceptedAt = receipt.acceptedAt;
    }
    overlay[aid] = entry;
  }
  return JSON.stringify(overlay);
}

// --- Factory ----------------------------------------------------------------

/**
 * Create the pending handler from one exact dependency object. Throws
 * `TypeError("Invalid pending dependencies")` synchronously on any invalid
 * dependency. Manifest selection, including whichever caching that selection
 * warrants, belongs entirely to the shared apply library.
 *
 * @param {object} dependencies
 * @returns {(req: Request) => Promise<Response>}
 */
export function createPendingHandler(dependencies) {
  const deps = captureDependencies(dependencies);

  return async function handle(req) {
    if (req.method !== "GET") return respond(405, null, { Allow: "GET" });
    try {
      const user = await deps.identify(req);
      if (user === null) return respond(401);
      const docId = parseDocId(req.url);
      const access = await deps.resolveRole(docId, user);
      if (validateAccess(access, deps) === false) return respond(403);
      const manifest = await selectManifest(deps, docId);
      let store;
      try {
        store = deps.docState();
      } catch (error) {
        throw fail(providerStatus(error));
      }
      let prefix;
      try {
        prefix = deps.editPrefix(docId);
      } catch {
        throw fail(500);
      }
      const listed = await listReceiptKeys(store, prefix, docId, deps);
      const hits = await readReceipts(store, listed, deps);
      return respond(200, project(manifest, hits), { "Content-Type": JSON_TYPE });
    } catch (error) {
      return respond(statusOf(error));
    }
  };
}

const production = createPendingHandler({
  identify,
  resolveRole,
  capabilitiesFor,
  assertIdentitySub,
  normalizeEmail,
  docState,
  editPrefix,
  editKey,
  read,
  upgrade,
  readApplyManifestFn: readApplyManifest,
});

/** @param {Request} req @returns {Promise<Response>} */
export default async function handler(req) {
  return production(req);
}

export const config = { path: "/api/pending" };
