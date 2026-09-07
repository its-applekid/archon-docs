import { AuthError, MissingIdentityError, recoverPassword } from "@netlify/identity";
import { requireOrigin } from "../lib/identity.mjs";
import { normalizeEmail } from "../lib/access.mjs";

/**
 * P4-K — `POST /api/accept`, the single acceptance surface.
 *
 * P4-J bootstraps an invited person's Identity account and asks the provider
 * to send its recovery mail. That mail carries `#recovery_token=…`, which
 * `/invite/` reads out of the URL fragment and posts here exactly once. This
 * handler validates the request against a frozen two-field contract and then
 * calls the pinned package's `recoverPassword()` a single time. That call
 * redeems the token, sets the new password, and logs the user in; the package
 * and the Functions v2 runtime own the session headers on the way out, so
 * nothing below constructs, reads, copies or removes any of them.
 *
 * The recovery token is an Identity credential, never document authority.
 * Success proves an account email inside a runtime session and nothing more:
 * P3-J still decides whether that email may read the document, and P3-H still
 * converts the matching live invitation. No access state is read or written
 * here.
 *
 * Every failure is deliberately uninformative. Whether the token was never
 * valid, expired, already redeemed, or belongs to no account is a single 400,
 * and a provider or runtime that cannot answer is a single quiet 503.
 */

const NO_STORE = "private, no-store";
const JSON_MEDIA = "application/json";
const JSON_CONTENT_TYPE = "application/json; charset=utf-8";

/** The exact fragment grammar `/invite/` matches, re-applied authoritatively. */
const TOKEN_PATTERN = /^[A-Za-z0-9._~-]{20,4096}$/;
/** P2-G's identity subject grammar, applied to the returned user's `id`. */
const IDENTITY_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._~-]{0,127}$/;

const MAX_BODY_BYTES = 8_192;
const MAX_BODY_READS = 1_024;
const MIN_PASSWORD_POINTS = 12;
const MAX_PASSWORD_POINTS = 128;
const MIN_PASSWORD_BYTES = 12;
const MAX_PASSWORD_BYTES = 512;

/**
 * One code for every rejection the caller could otherwise use as an oracle.
 * A malformed request, an oversized body, an unsupported media type and a
 * dead token are all the same sentence to the page, which renders one fixed
 * message for all of them.
 */
const INVALID = "invalid-invitation";
const UNAVAILABLE = "unavailable";
const INTERNAL = "internal-error";

const DEPENDENCY_KEYS = ["requireOriginFn", "recoverPasswordFn"];

/** A JSON error with no trailing newline and no caching, ever. */
function jsonError(status, code) {
  return new Response(`{"error":"${code}"}`, {
    status,
    headers: {
      "Content-Type": JSON_CONTENT_TYPE,
      "Cache-Control": NO_STORE,
    },
  });
}

/** The only success: zero application bytes and no application media type. */
function accepted() {
  return new Response(null, {
    status: 204,
    headers: {
      "Cache-Control": NO_STORE,
      "Content-Length": "0",
    },
  });
}

/** True for an ASCII C0 control, DEL, or a C1 control. */
function hasControl(value) {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code <= 0x1f || code === 0x7f || (code >= 0x80 && code <= 0x9f)) {
      return true;
    }
  }
  return false;
}

/** True when any UTF-16 surrogate in the string is unpaired. */
function hasLoneSurrogate(value) {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = index + 1 < value.length ? value.charCodeAt(index + 1) : 0;
      if (next < 0xdc00 || next > 0xdfff) return true;
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      return true;
    }
  }
  return false;
}

/**
 * The authoritative password boundary. `/invite/` applies the same rules for
 * the caller's convenience, but this copy is the one that decides. Nothing is
 * trimmed, normalized or case-folded: the value the person typed is the value
 * the provider stores.
 *
 * @param {string} value
 * @returns {boolean}
 */
function passwordAllowed(value) {
  if (hasLoneSurrogate(value) || hasControl(value)) return false;
  // Unicode code points, not UTF-16 units: one astral character is one
  // character to the person who typed it.
  const points = [...value].length;
  if (points < MIN_PASSWORD_POINTS || points > MAX_PASSWORD_POINTS) return false;
  const bytes = new TextEncoder().encode(value).length;
  return bytes >= MIN_PASSWORD_BYTES && bytes <= MAX_PASSWORD_BYTES;
}

/**
 * The status the provider actually answered with, or `null`.
 *
 * The pinned package wraps every rejection from the recovery call in
 * `AuthError.from(error)`, and that constructor is called with an `undefined`
 * status: the transport error carrying GoTrue's real HTTP status is put in
 * `cause` instead. Reading only `error.status` would therefore classify every
 * dead, expired or already-redeemed token as a provider outage, which is the
 * one distinction this endpoint has to get right. Recognition of the error
 * class itself is still by identity against the pinned import; this only reads
 * the status that class was constructed with, following a bounded `cause`
 * chain, and treats any hostile shape as no status at all.
 *
 * @param {unknown} error
 * @returns {number | null}
 */
function providerStatus(error) {
  let current = error;
  for (let depth = 0; depth < 4; depth += 1) {
    if (current === null || typeof current !== "object") return null;
    let status;
    try {
      status = current.status;
    } catch {
      return null;
    }
    if (Number.isInteger(status)) return status;
    try {
      current = current.cause;
    } catch {
      return null;
    }
  }
  return null;
}

/** True when `value` is a plain object with `Object.prototype` and no symbols. */
function ordinaryObject(value) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype &&
    Object.getOwnPropertySymbols(value).length === 0
  );
}

/** The parsed media type, lowercased, with any parameters discarded. */
function mediaType(header) {
  if (typeof header !== "string") return null;
  const semicolon = header.indexOf(";");
  const base = semicolon === -1 ? header : header.slice(0, semicolon);
  return base.trim().toLowerCase();
}

/**
 * Read at most `MAX_BODY_BYTES` from the request stream by hand.
 *
 * The convenience readers are all forbidden here: each one is happy to buffer
 * an unbounded body before this handler ever sees a length. The reader is
 * acquired exactly once and released exactly once, including on overflow and
 * on a stream that rejects mid-read.
 *
 * @param {Request} req
 * @returns {Promise<{ ok: true, bytes: Uint8Array } | { ok: false, status: number }>}
 */
async function readBounded(req) {
  const body = req.body;
  if (body === null || body === undefined || typeof body.getReader !== "function") {
    return { ok: false, status: 400 };
  }

  let reader;
  try {
    reader = body.getReader();
  } catch {
    return { ok: false, status: 400 };
  }

  const chunks = [];
  let total = 0;
  let reads = 0;
  let outcome = null;
  try {
    for (;;) {
      /* Bytes alone do not bound this loop: a stream that yields empty chunks
         forever never trips the byte ceiling. */
      reads += 1;
      if (reads > MAX_BODY_READS) {
        outcome = { ok: false, status: 413 };
        try {
          await reader.cancel();
        } catch {
          // A stream that refuses cancellation still yields the same answer.
        }
        break;
      }
      const step = await reader.read();
      if (step === null || typeof step !== "object") {
        outcome = { ok: false, status: 400 };
        break;
      }
      if (step.done === true) {
        outcome = { ok: true, bytes: null };
        break;
      }
      const chunk = step.value;
      if (!(chunk instanceof Uint8Array)) {
        outcome = { ok: false, status: 400 };
        break;
      }
      total += chunk.byteLength;
      if (total > MAX_BODY_BYTES) {
        try {
          await reader.cancel();
        } catch {
          // A stream that refuses cancellation still yields the same answer.
        }
        outcome = { ok: false, status: 413 };
        break;
      }
      chunks.push(chunk);
    }
  } catch {
    outcome = { ok: false, status: 400 };
  } finally {
    try {
      reader.releaseLock();
    } catch {
      // Releasing a lock the runtime already dropped is not a failure.
    }
  }

  if (outcome === null || outcome.ok !== true) {
    return outcome === null ? { ok: false, status: 400 } : outcome;
  }

  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return { ok: true, bytes };
}

/**
 * Require the returned value to be a normal user record carrying exactly the
 * two properties this handler is allowed to look at. An accessor, a getter
 * with a side effect, or a shape the package never emits is an internal
 * failure rather than a success, and neither value leaves this function.
 *
 * @param {unknown} user
 * @returns {boolean}
 */
function returnedUserValid(user) {
  if (user === null || typeof user !== "object" || Array.isArray(user)) return false;

  const id = Object.getOwnPropertyDescriptor(user, "id");
  const email = Object.getOwnPropertyDescriptor(user, "email");
  for (const descriptor of [id, email]) {
    if (descriptor === undefined) return false;
    if (typeof descriptor.get === "function" || typeof descriptor.set === "function") {
      return false;
    }
    if (descriptor.enumerable !== true || descriptor.writable !== true ||
        descriptor.configurable !== true) {
      return false;
    }
    if (typeof descriptor.value !== "string") return false;
  }

  if (!IDENTITY_ID_PATTERN.test(id.value)) return false;

  let normalized;
  try {
    normalized = normalizeEmail(email.value);
  } catch {
    return false;
  }
  return normalized === email.value;
}

/**
 * Build an acceptance handler over an exact dependency surface.
 *
 * Only the origin guard and the recovery call are replaceable, and only by a
 * caller holding this function — request data can never select either one. An
 * unknown key, an accessor, a symbol, an array, a null, a foreign prototype or
 * a non-function is a synchronous programming error, not a runtime fallback.
 *
 * @param {{ requireOriginFn?: Function, recoverPasswordFn?: Function }} [dependencies]
 * @returns {(req: Request) => Promise<Response>}
 */
export function createAcceptHandler(dependencies = {}) {
  if (!ordinaryObject(dependencies)) {
    throw new TypeError("createAcceptHandler requires an ordinary dependency object");
  }
  /* `Reflect.ownKeys` sees non-enumerable and symbol keys too. `Object.keys`
     would miss a non-enumerable `recoverPasswordFn`, which the `??` reads
     below would then happily pick up unvalidated. */
  for (const key of Reflect.ownKeys(dependencies)) {
    if (typeof key !== "string" || !DEPENDENCY_KEYS.includes(key)) {
      throw new TypeError("createAcceptHandler received an unknown dependency");
    }
    const descriptor = Object.getOwnPropertyDescriptor(dependencies, key);
    if (typeof descriptor.get === "function" || typeof descriptor.set === "function") {
      throw new TypeError(`createAcceptHandler dependency ${key} must be a data property`);
    }
    if (typeof descriptor.value !== "function") {
      throw new TypeError(`createAcceptHandler dependency ${key} must be callable`);
    }
  }

  const requireOriginFn = dependencies.requireOriginFn ?? requireOrigin;
  const recoverPasswordFn = dependencies.recoverPasswordFn ?? recoverPassword;

  return async function accept(req) {
    if (req.method !== "POST") {
      return new Response(null, {
        status: 405,
        headers: { Allow: "POST", "Cache-Control": NO_STORE },
      });
    }

    try {
      await requireOriginFn(req);
    } catch (error) {
      if (error instanceof Response) {
        error.headers.set("Cache-Control", NO_STORE);
        return error;
      }
      return jsonError(500, INTERNAL);
    }

    if (mediaType(req.headers.get("Content-Type")) !== JSON_MEDIA) {
      return jsonError(415, INVALID);
    }

    const read = await readBounded(req);
    if (read.ok !== true) {
      return jsonError(read.status, INVALID);
    }

    let parsed;
    try {
      const text = new TextDecoder("utf-8", { fatal: true }).decode(read.bytes);
      if (text === "") {
        return jsonError(400, INVALID);
      }
      parsed = JSON.parse(text);
    } catch {
      return jsonError(400, INVALID);
    }

    if (!ordinaryObject(parsed)) {
      return jsonError(400, INVALID);
    }
    const fields = Object.keys(parsed).sort();
    if (fields.length !== 2 || fields[0] !== "password" || fields[1] !== "token") {
      return jsonError(400, INVALID);
    }

    const token = parsed.token;
    const password = parsed.password;
    if (typeof token !== "string" || typeof password !== "string") {
      return jsonError(400, INVALID);
    }
    if (!TOKEN_PATTERN.test(token) || !passwordAllowed(password)) {
      return jsonError(400, INVALID);
    }

    let user;
    try {
      user = await recoverPasswordFn(token, password);
    } catch (error) {
      // The two provider error classes are recognized only by identity
      // against the pinned package's own exports. A rejection that merely
      // names itself `AuthError`, or carries an attacker-chosen `status`, is
      // not one, and falls through to the outage answer below.
      if (error instanceof AuthError) {
        const status = providerStatus(error);
        if (status !== null && status >= 400 && status <= 499) {
          return jsonError(400, INVALID);
        }
        return jsonError(503, UNAVAILABLE);
      }
      if (error instanceof MissingIdentityError) {
        return jsonError(503, UNAVAILABLE);
      }
      // Any other provider, runtime or network rejection is the same outage.
      return jsonError(503, UNAVAILABLE);
    }

    if (!returnedUserValid(user)) {
      return jsonError(500, INTERNAL);
    }

    return accepted();
  };
}

/** The production handler, bound once to the pinned package's own functions. */
const acceptHandler = createAcceptHandler();

/**
 * @param {Request} req
 * @returns {Promise<Response>}
 */
export default async function handler(req) {
  return acceptHandler(req);
}

export const config = { path: "/api/accept" };
