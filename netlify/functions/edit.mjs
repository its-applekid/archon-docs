import { identify, requireOrigin } from "../lib/identity.mjs";
import { capabilitiesFor, resolveRole, validateAccessRow } from "../lib/access.mjs";
import { ApplyError, applyText, readEffectiveBase } from "../lib/gitedit.mjs";
import { notify } from "../lib/notify.mjs";
import { toHtml, toMd } from "../lib/inline-md.mjs";
import { createHash } from "node:crypto";

// POST /api/edit — the direct-edit write path.
//
// This handler owns three things and nothing else: it proves who the caller
// is, it proves that caller may write this document, and it schedules the one
// notification fan-out after the write has completed. Every manifest, source,
// repository, and receipt decision belongs to the one apply path in
// `../lib/gitedit.mjs`, which both this route and an accepted suggestion call.
//
// Amendment chain: P4-B (the initial apply path) -> P4-M (document-role
// capabilities replace the temporary organization gate) -> P4-N (the one apply
// path, the optional explicit base, and the edit fan-out). P4-M's access
// check stays in this module by design, because
// `gitedit.mjs` is not an authorization oracle: it is never reached until
// both capability checks have passed.

const NO_STORE = "private, no-store";
const JSON_TYPE = "application/json; charset=utf-8";

const DEPENDENCY_KEYS = Object.freeze([
  "requireOrigin", "identify", "resolveRole", "capabilitiesFor",
  "readEffectiveBase", "applyText", "notify", "toMd", "toHtml", "sha256Hex",
]);

const BODY_KEYS = Object.freeze(["docId", "aid", "text"]);
const OPTIONAL_BODY_KEYS = Object.freeze(["baseHash"]);
const IGNORED_BODY_KEYS = Object.freeze(["author", "email", "name"]);

const IDENTITY_KEYS = Object.freeze(["sub", "email", "name", "isOrg"]);
const RECEIPT_KEYS = Object.freeze(["v", "aid", "text", "by", "at", "baseHash", "pr"]);
const DIRECT_KEYS = Object.freeze([...RECEIPT_KEYS, "via"]);
const SUGGESTION_KEYS = Object.freeze([...DIRECT_KEYS, "sugId", "acceptedBy", "acceptedAt"]);
const ACTOR_KEYS = Object.freeze(["sub", "name", "email"]);
const RESULT_KEYS = Object.freeze(["receipt", "pr"]);
const BASE_KEYS = Object.freeze([
  "mode", "docId", "aid", "section", "tag", "docVersion", "manifestHash", "hash", "text",
  "pending",
]);

const DOC_ID_PATTERN = /^[0-9a-f]{6}$/;
const AID_PATTERN = /^a[0-9a-f]{8}$/;
const HASH_PATTERN = /^[0-9a-f]{64}$/;
const SUBJECT_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._~-]{0,127}$/;
const EMAIL_LOCAL_PATTERN =
  /^[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*$/;
const DNS_LABEL_PATTERN = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const EMAIL_EDGE_WHITESPACE = /^[ \t\n\r\f]+|[ \t\n\r\f]+$/g;
const NON_ASCII_PATTERN = /[^\x00-\x7f]/;
const CANONICAL_INTEGER_PATTERN = /^(?:0|[1-9][0-9]*)$/;
const MEDIA_TYPE_PATTERN =
  /^[ \t]*([!#$%&'*+.^_`|~0-9A-Za-z-]+)\/([!#$%&'*+.^_`|~0-9A-Za-z-]+)[ \t]*(?:;[ \t]*[!#$%&'*+.^_`|~0-9A-Za-z-]+=(?:[!#$%&'*+.^_`|~0-9A-Za-z-]+|"(?:[^"\\\x00-\x1f\x7f]|\\[\x00-\x7f])*")[ \t]*)*$/;

const MAX_REQUEST_BYTES = 65_536;
const MAX_TEXT_UNITS = 4_000;
const MAX_NAME_UNITS = 200;
const MAX_EMAIL_UNITS = 254;

/** The complete public error table: code -> [status, message]. */
const PUBLIC_ERRORS = Object.freeze({
  "invalid-body": [400, "Invalid request body"],
  unauthenticated: [401, "Authentication required"],
  forbidden: [403, "Document edit denied"],
  "not-found": [404, "Document or block not found"],
  "method-not-allowed": [405, "Method not allowed"],
  conflict: [409, "The block changed since this document was built"],
  "payload-too-large": [413, "Request body exceeds 65536 bytes"],
  "unsupported-media-type": [415, "Content-Type must be application/json"],
  "invalid-state": [500, "Invalid edit state"],
  "repository-unavailable": [502, "Repository write unavailable"],
  unavailable: [503, "Edit state unavailable"],
});

/** A private control-flow error carrying only a public code and, for 409, the
 * one bounded `current` field. It never carries a cause, a provider body, a
 * path, a ref, a SHA, or an actor. */
class Failure extends Error {
  constructor(code, current = null) {
    super("edit");
    this.code = code;
    this.current = current;
  }
}

const fail = (code) => new Failure(code);
const conflict = (current) =>
  new Failure("conflict", typeof current === "string" ? current : null);

function jsonResponse(status, body, extra = null) {
  const headers = { "Cache-Control": NO_STORE, "Content-Type": JSON_TYPE };
  if (extra !== null) Object.assign(headers, extra);
  return new Response(JSON.stringify(body), { status, headers });
}

function errorResponse(failure) {
  const code = failure instanceof Failure ? failure.code : "invalid-state";
  const [status, message] = PUBLIC_ERRORS[code] ?? PUBLIC_ERRORS["invalid-state"];
  const body = { error: { code, message } };
  if (code === "conflict") body.current = failure.current;
  const extra = code === "method-not-allowed" ? { Allow: "POST" } : null;
  return jsonResponse(status, body, extra);
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

/** P2-G's canonical mailbox grammar, duplicated deliberately: this module
 * validates what it received and never normalizes on the caller's behalf. */
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

/* ------------------------------------------------------------- dependencies */

function captureDependencies(dependencies) {
  if (dependencies === null || typeof dependencies !== "object" || Array.isArray(dependencies) ||
      Object.getPrototypeOf(dependencies) !== Object.prototype ||
      Object.getOwnPropertySymbols(dependencies).length !== 0 ||
      !sameSet(Object.getOwnPropertyNames(dependencies), DEPENDENCY_KEYS)) {
    throw new TypeError("Invalid edit dependencies");
  }
  const captured = {};
  for (const key of DEPENDENCY_KEYS) {
    const descriptor = Object.getOwnPropertyDescriptor(dependencies, key);
    if (descriptor === undefined || !hasOwn(descriptor, "value") ||
        descriptor.enumerable !== true || descriptor.writable !== true ||
        descriptor.configurable !== true || typeof descriptor.value !== "function") {
      throw new TypeError("Invalid edit dependencies");
    }
    captured[key] = descriptor.value;
  }
  return Object.freeze(captured);
}

/* ---------------------------------------------------------------- identity */

/**
 * The exact P2-H identity.
 *
 * The mailbox requirement is deliberately widened here relative to the first
 * repository-only version of this route: an empty canonical address and an
 * empty canonical name are both admissible, because standalone mode writes
 * only a receipt and P3-E accepts that actor verbatim. Repository mode alone
 * refuses an empty address, and it does so inside the apply path, after the
 * mode has actually been selected.
 */
function requireIdentity(user) {
  if (!isExactRecord(user, IDENTITY_KEYS)) throw fail("invalid-state");
  const { sub, email, name, isOrg } = user;
  if (typeof sub !== "string" || !SUBJECT_PATTERN.test(sub)) throw fail("invalid-state");
  if (typeof name !== "string" || name.length > MAX_NAME_UNITS) throw fail("invalid-state");
  if (typeof email !== "string") throw fail("invalid-state");
  if (email.length !== 0 && !isNormalizedEmail(email)) throw fail("invalid-state");
  if (typeof isOrg !== "boolean") throw fail("invalid-state");
  return user;
}

/* ----------------------------------------------------------- authorization */

/** Own enumerable data property `key` of `object` as `{ value }`, or `null`.
 * Never invokes an accessor. */
function ownData(object, key) {
  if (object === null || typeof object !== "object") return null;
  const descriptor = Object.getOwnPropertyDescriptor(object, key);
  if (descriptor === undefined || !hasOwn(descriptor, "value") ||
      descriptor.enumerable !== true) {
    return null;
  }
  return { value: descriptor.value };
}

/** The exact descriptor-safe P2-G unavailable shape. */
function isAccessUnavailable(error) {
  if (error === null || typeof error !== "object" || Array.isArray(error)) return false;
  const name = ownData(error, "name");
  const code = ownData(error, "code");
  const status = ownData(error, "status");
  return name !== null && code !== null && status !== null &&
    name.value === "StoreError" && code.value === "unavailable" && status.value === 503;
}

/**
 * The one complete capability lookup. The resolved row is validated by
 * `validateAccessRow()` — the single shared definition of a well-formed access
 * row (#132) — against the canonical row for its own role, so a drifted or
 * forged access object is an invalid state rather than a quiet grant. A direct
 * edit requires both `canSuggest` and `canEdit`.
 */
async function authorize(deps, docId, identity) {
  let access;
  try {
    access = await deps.resolveRole(docId, identity, { consumeInvitation: false });
  } catch (error) {
    // Only the exact P2-G unavailable shape is an outage. An arbitrary throw, a
    // hostile object, or a different store code is an invalid state, so a
    // capability lookup can never be turned into a 503 by a forged error.
    throw fail(isAccessUnavailable(error) ? "unavailable" : "invalid-state");
  }
  // The capability table is the injected dependency, not the module's own, so
  // the row is checked against the table this handler was actually given.
  if (!validateAccessRow(access, (role) => deps.capabilitiesFor(role))) {
    throw fail("invalid-state");
  }
  if (access.canSuggest !== true || access.canEdit !== true) throw fail("forbidden");
}

/* ------------------------------------------------------------- request body */

function isJsonMediaType(header) {
  if (typeof header !== "string") return false;
  const match = header.match(MEDIA_TYPE_PATTERN);
  return match !== null && `${match[1]}/${match[2]}`.toLowerCase() === "application/json";
}

/** Stream at most 65,536 bytes through exactly one reader, then cancel and
 * release it exactly once. */
async function readBoundedBody(req) {
  const body = req.body;
  if (body === null || body === undefined || typeof body.getReader !== "function" ||
      body.locked === true) {
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
      if (result.done === true) break;
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
  if (failure !== null) throw fail(failure);
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return bytes;
}

/** Media type, canonical Content-Length, bounded stream, one fatal UTF-8
 * decode, and exactly one JSON parse into an ordinary object. */
async function readJsonObject(req) {
  if (!isJsonMediaType(req.headers.get("content-type"))) throw fail("unsupported-media-type");
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
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw fail("invalid-body");
  }
  return parsed;
}

/** The round-trip admission gate: text is editable only when both converter
 * twins reproduce it exactly. The original text is submitted, never a
 * normalised copy. */
function isEditableText(deps, value) {
  if (typeof value !== "string" || value.length > MAX_TEXT_UNITS) return false;
  try {
    const html = deps.toHtml(value);
    if (typeof html !== "string" || deps.toMd(html) !== value) return false;
    return deps.toHtml(deps.toMd(html)) === html;
  } catch {
    return false;
  }
}

/**
 * The exact request grammar. `baseHash` is the optional explicit effective
 * base; the reserved `author`, `email`, and `name` keys are tolerated but
 * never read, because the server identity is the only author.
 */
function parseEditBody(deps, parsed) {
  for (const key of Object.getOwnPropertyNames(parsed)) {
    if (!BODY_KEYS.includes(key) && !OPTIONAL_BODY_KEYS.includes(key) &&
        !IGNORED_BODY_KEYS.includes(key)) {
      throw fail("invalid-body");
    }
  }
  for (const key of BODY_KEYS) {
    if (!hasOwn(parsed, key)) throw fail("invalid-body");
  }
  const { docId, aid, text } = parsed;
  if (typeof docId !== "string" || !DOC_ID_PATTERN.test(docId)) throw fail("invalid-body");
  if (typeof aid !== "string" || !AID_PATTERN.test(aid)) throw fail("invalid-body");
  if (!isEditableText(deps, text)) throw fail("invalid-body");
  let baseHash = null;
  if (hasOwn(parsed, "baseHash")) {
    if (typeof parsed.baseHash !== "string" || !HASH_PATTERN.test(parsed.baseHash)) {
      throw fail("invalid-body");
    }
    baseHash = parsed.baseHash;
  }
  return { docId, aid, text, baseHash };
}

/* --------------------------------------------------------------- responses */

function projectActor(actor) {
  if (!isExactOrderedObject(actor, ACTOR_KEYS)) throw fail("invalid-state");
  return { sub: actor.sub, name: actor.name, email: actor.email };
}

/**
 * The public direct projection, in exactly this order. The stored `v`,
 * `baseHash`, and suggestion fields are never serialized, and neither is the
 * apply result's sibling pull-request number.
 */
function projectReceipt(receipt, aid) {
  const via = hasOwn(receipt, "via") ? receipt.via : undefined;
  let keys;
  if (via === undefined) keys = RECEIPT_KEYS;
  else if (via === "edit") keys = DIRECT_KEYS;
  else if (via === "suggestion") keys = SUGGESTION_KEYS;
  else throw fail("invalid-state");
  if (!isExactOrderedObject(receipt, keys)) throw fail("invalid-state");
  if (receipt.aid !== aid) throw fail("invalid-state");
  if (typeof receipt.text !== "string" || receipt.text.length > MAX_TEXT_UNITS) {
    throw fail("invalid-state");
  }
  return {
    aid: receipt.aid,
    text: receipt.text,
    by: projectActor(receipt.by),
    at: receipt.at,
    pr: receipt.pr,
    via: receipt.via,
  };
}

/** Only an `ApplyError` this module imported may steer the public status. A
 * forged status, code, or current field on any other value is an invalid
 * state, never a 404 or a 409 the caller chose. */
function mapApplyError(error) {
  if (!(error instanceof ApplyError)) return fail("invalid-state");
  const code = error.code;
  if (!hasOwn(PUBLIC_ERRORS, code)) return fail("invalid-state");
  if (code === "conflict") return conflict(error.current);
  return fail(code);
}

/* -------------------------------------------------------------- the factory */

/**
 * Create the edit handler from one exact dependency object. Throws
 * `TypeError("Invalid edit dependencies")` synchronously on any invalid
 * dependency, so no request field can ever replace a dependency.
 *
 * @param {object} dependencies
 * @returns {(req: Request, context: object) => Promise<Response>}
 */
export function createEditHandler(dependencies) {
  const deps = captureDependencies(dependencies);

  return async function handleEdit(req, context) {
    if (req.method !== "POST") return errorResponse(fail("method-not-allowed"));
    try {
      try {
        deps.requireOrigin(req);
      } catch (error) {
        if (error instanceof Response) return error;
        throw fail("invalid-state");
      }

      let user;
      try {
        user = await deps.identify(req);
      } catch {
        throw fail("invalid-state");
      }
      if (user === null) throw fail("unauthenticated");
      const identity = requireIdentity(user);

      let search;
      try {
        search = new URL(req.url).search;
      } catch {
        throw fail("invalid-body");
      }
      if (search !== "") throw fail("invalid-body");

      const { docId, aid, text, baseHash } = parseEditBody(deps, await readJsonObject(req));

      await authorize(deps, docId, identity);

      // Without an explicit base the caller is a client built before explicit
      // bases existed. It is safe only while nothing is pending: it proved it
      // saw the built text, not somebody else's unmerged overlay.
      let expectBase = baseHash;
      if (expectBase === null) {
        let base;
        try {
          base = await deps.readEffectiveBase(docId, aid);
        } catch (error) {
          throw mapApplyError(error);
        }
        if (!isExactOrderedObject(base, BASE_KEYS)) throw fail("invalid-state");
        if (typeof base.manifestHash !== "string" || !HASH_PATTERN.test(base.manifestHash)) {
          throw fail("invalid-state");
        }
        if (base.pending !== false) throw conflict(typeof base.text === "string" ? base.text : null);
        expectBase = base.manifestHash;
      }

      let result;
      try {
        result = await deps.applyText({
          docId,
          aid,
          text,
          author: { sub: identity.sub, name: identity.name, email: identity.email },
          acceptedBy: null,
          sugId: null,
          via: "edit",
          expectBase,
        });
      } catch (error) {
        throw mapApplyError(error);
      }
      if (!isExactRecord(result, RESULT_KEYS)) throw fail("invalid-state");
      const receipt = projectReceipt(result.receipt, aid);

      // The write and its audit are already complete. Fan-out is best effort
      // and strictly downstream: a rejected schedule, a false result, or a
      // throw from the sole helper can never turn a durable success into a
      // failure for the caller.
      try {
        const hash = deps.sha256Hex(deps.toHtml(receipt.text));
        deps.notify(context, { t: "edit.saved", docId, aid, hash });
      } catch {
        // Deliberately ignored.
      }

      return jsonResponse(200, { receipt });
    } catch (error) {
      return errorResponse(error instanceof Failure ? error : fail("invalid-state"));
    }
  };
}

const production = createEditHandler({
  requireOrigin,
  identify,
  resolveRole,
  capabilitiesFor,
  readEffectiveBase,
  applyText,
  notify,
  toMd,
  toHtml,
  sha256Hex: (value) => createHash("sha256").update(value, "utf8").digest("hex"),
});

/** @param {Request} req @param {object} context @returns {Promise<Response>} */
export default async function handler(req, context) {
  return production(req, context);
}

export const config = { path: "/api/edit" };
