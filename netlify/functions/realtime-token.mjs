import { isProxy } from "node:util/types";
import { identify } from "../lib/identity.mjs";
import { capabilitiesFor, resolveRole, validateAccessRow } from "../lib/access.mjs";
import { mintToken } from "../lib/realtime.mjs";

const DOC_ID_RE = /^[0-9a-f]{6}$/;
const NO_STORE = { "Cache-Control": "private, no-store" };

function empty(status, extraHeaders = {}) {
  return new Response(null, { status, headers: { ...extraHeaders, ...NO_STORE } });
}

function ordinaryDataDescriptor(descriptor) {
  return (
    descriptor !== undefined &&
    Object.prototype.hasOwnProperty.call(descriptor, "value") &&
    descriptor.enumerable === true &&
    descriptor.writable === true &&
    descriptor.configurable === true
  );
}

function isUnavailableStoreError(thrown) {
  if (thrown === null || typeof thrown !== "object" || isProxy(thrown)) return false;
  try {
    const name = Object.getOwnPropertyDescriptor(thrown, "name");
    const code = Object.getOwnPropertyDescriptor(thrown, "code");
    const status = Object.getOwnPropertyDescriptor(thrown, "status");
    return (
      ordinaryDataDescriptor(name) &&
      ordinaryDataDescriptor(code) &&
      ordinaryDataDescriptor(status) &&
      name.value === "StoreError" &&
      code.value === "unavailable" &&
      status.value === 503
    );
  } catch {
    return false;
  }
}

function realtimeUnavailable(error) {
  if (error === null || typeof error !== "object" || isProxy(error)) return false;
  try {
    const message = Object.getOwnPropertyDescriptor(error, "message");
    return (
      message !== undefined &&
      Object.prototype.hasOwnProperty.call(message, "value") &&
      message.value === "Realtime provider unavailable"
    );
  } catch {
    return false;
  }
}

/**
 * GET /api/realtime-token — authorize one document before minting its narrow,
 * short-lived Ably credential.
 *
 * @param {Request} req
 * @returns {Promise<Response>}
 */
export default async function handler(req) {
  if (req.method !== "GET") {
    return empty(405, { Allow: "GET" });
  }

  const key = process.env.ABLY_API_KEY;
  if (typeof key !== "string" || key.trim() === "") {
    return empty(204);
  }

  let session;
  try {
    session = await identify(req);
  } catch {
    return empty(500);
  }
  if (session === null) return empty(401);

  let docValues;
  try {
    docValues = new URL(req.url).searchParams.getAll("doc");
  } catch {
    return empty(400);
  }
  if (docValues.length !== 1 || !DOC_ID_RE.test(docValues[0])) {
    return empty(400);
  }
  const docId = docValues[0];

  let access;
  try {
    access = await resolveRole(docId, session);
  } catch (error) {
    return empty(isUnavailableStoreError(error) ? 503 : 500);
  }
  // The role is only half the answer. Until #135 this path read `canRead` off
  // whatever `resolveRole()` returned and never checked the row against the
  // capability matrix, so a row claiming `role: "none", canRead: true` minted a
  // token. `validateAccessRow()` is the one definition of a well-formed row
  // (#132); a proxy is refused before it reaches the validator, because a
  // trapped row can answer one way while being checked and another way when
  // the capability is finally read.
  if (access === null || typeof access !== "object" || isProxy(access)) {
    return empty(500);
  }
  if (!validateAccessRow(access, capabilitiesFor)) return empty(500);
  if (access.canRead !== true) return empty(403);

  let token;
  try {
    token = await mintToken(session, docId);
  } catch (error) {
    return empty(realtimeUnavailable(error) ? 502 : 500);
  }
  if (token === null) return empty(204);

  return Response.json(token, { headers: NO_STORE });
}

export const config = { path: "/api/realtime-token" };
