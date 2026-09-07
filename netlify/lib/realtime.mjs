import { randomBytes } from "node:crypto";
import { isProxy } from "node:util/types";

const ABLY_ORIGIN = "https://main.realtime.ably.net";
const ABLY_VERSION = "1.2";
const TOKEN_TTL_MS = 3_600_000;
const PROVIDER_TIMEOUT_MS = 5_000;
const PROVIDER_CLOCK_SKEW_MS = 60_000;
const DOC_ID_RE = /^[0-9a-f]{6}$/;
const IDENTITY_SUB_RE = /^[A-Za-z0-9][A-Za-z0-9._~-]{0,127}$/;
const THREAD_ID_RE = /^t_[0-9a-z]+_[0-9a-f]{8}$/;
const AID_RE = /^a[0-9a-f]{8}$/;
const HASH_RE = /^[0-9a-f]{64}$/;

function configuredKey() {
  const value = process.env.ABLY_API_KEY;
  return typeof value === "string" && value.trim() !== "" ? value : null;
}

function parseKey(value) {
  if (value !== value.trim()) throw new Error();
  const separator = value.indexOf(":");
  if (
    separator <= 0 ||
    separator === value.length - 1 ||
    value.indexOf(":", separator + 1) !== -1
  ) {
    throw new Error();
  }
  return { full: value, keyName: value.slice(0, separator) };
}

function hasOrdinaryDescriptor(descriptor, enumerable = true) {
  return (
    descriptor !== undefined &&
    Object.prototype.hasOwnProperty.call(descriptor, "value") &&
    descriptor.enumerable === enumerable &&
    descriptor.writable === true &&
    descriptor.configurable === true
  );
}

/**
 * Return a descriptor map for an ordinary closed object, or null. Proxy
 * detection precedes every reflective operation and the complete reflection
 * sequence is contained by one defensive boundary.
 */
function plainDataDescriptors(value) {
  if (value === null || typeof value !== "object" || isProxy(value)) return null;
  try {
    if (Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) {
      return null;
    }
    const keys = Reflect.ownKeys(value);
    const descriptors = Object.create(null);
    for (const key of keys) {
      if (typeof key !== "string") return null;
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!hasOrdinaryDescriptor(descriptor)) return null;
      descriptors[key] = descriptor;
    }
    return { keys, descriptors };
  } catch {
    return null;
  }
}

function exactKeys(actual, expected) {
  return (
    actual.length === expected.length &&
    expected.every((key) => actual.includes(key))
  );
}

function matches(pattern, value) {
  return typeof value === "string" && pattern.test(value);
}

function validOperationArray(value, operations) {
  if (value === null || typeof value !== "object" || isProxy(value)) return false;
  try {
    if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) {
      return false;
    }
    const expectedKeys = operations.map((_, index) => String(index)).concat("length");
    const keys = Reflect.ownKeys(value);
    if (!exactKeys(keys, expectedKeys)) return false;

    const found = [];
    for (let index = 0; index < operations.length; index += 1) {
      const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
      if (!hasOrdinaryDescriptor(descriptor)) return false;
      found.push(descriptor.value);
    }
    const length = Object.getOwnPropertyDescriptor(value, "length");
    if (
      length === undefined ||
      !Object.prototype.hasOwnProperty.call(length, "value") ||
      length.value !== operations.length ||
      length.enumerable !== false ||
      length.writable !== true ||
      length.configurable !== false
    ) {
      return false;
    }
    return operations.every(
      (operation) => found.filter((value) => value === operation).length === 1,
    );
  } catch {
    return false;
  }
}

function validCapability(value, serverChannel, clientChannel) {
  if (typeof value !== "string") return false;
  let parsed;
  try {
    parsed = JSON.parse(value);
  } catch {
    return false;
  }
  const inspected = plainDataDescriptors(parsed);
  if (inspected === null || !exactKeys(inspected.keys, [serverChannel, clientChannel])) {
    return false;
  }
  return (
    validOperationArray(inspected.descriptors[serverChannel].value, ["subscribe"]) &&
    validOperationArray(inspected.descriptors[clientChannel].value, ["publish", "subscribe"])
  );
}

function validTokenDetails(
  value,
  { requestTimestamp, responseTimestamp, serverChannel, clientChannel, clientId },
) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const { token, issued, expires, capability, clientId: returnedClientId } = value;
  return (
    typeof token === "string" &&
    token !== "" &&
    Number.isFinite(issued) &&
    Number.isInteger(issued) &&
    Number.isFinite(expires) &&
    Number.isInteger(expires) &&
    issued >= requestTimestamp - PROVIDER_CLOCK_SKEW_MS &&
    issued <= responseTimestamp + PROVIDER_CLOCK_SKEW_MS &&
    expires > responseTimestamp &&
    expires > issued &&
    expires - issued <= TOKEN_TTL_MS &&
    expires <= responseTimestamp + TOKEN_TTL_MS + PROVIDER_CLOCK_SKEW_MS &&
    returnedClientId === clientId &&
    validCapability(capability, serverChannel, clientChannel)
  );
}

function providerHeaders(key) {
  return {
    Authorization: `Basic ${Buffer.from(key).toString("base64")}`,
    Accept: "application/json",
    "Content-Type": "application/json",
    "X-Ably-Version": ABLY_VERSION,
  };
}

/**
 * @param {{sub: string, isOrg: boolean}} session
 * @param {string} docId
 * @returns {Promise<null | {
 *   token: string,
 *   issued: number,
 *   expires: number,
 *   capability: string,
 *   clientId: string
 * }>}
 */
export async function mintToken(session, docId) {
  const key = configuredKey();
  if (key === null) return null;
  if (typeof docId !== "string" || !DOC_ID_RE.test(docId)) {
    throw new TypeError("Invalid document id");
  }
  if (
    session === null ||
    typeof session !== "object" ||
    typeof session.sub !== "string" ||
    !IDENTITY_SUB_RE.test(session.sub) ||
    typeof session.isOrg !== "boolean"
  ) {
    throw new TypeError("Invalid realtime session");
  }

  try {
    const { full, keyName } = parseKey(key);
    const serverChannel = `doc:${docId}:server`;
    const clientChannel = `doc:${docId}:client`;
    const capability = JSON.stringify({
      [serverChannel]: ["subscribe"],
      [clientChannel]: ["publish", "subscribe"],
    });
    const clientId = session.isOrg
      ? session.sub
      : `g_${randomBytes(6).toString("hex")}`;
    const requestTimestamp = Date.now();
    const response = await fetch(
      `${ABLY_ORIGIN}/keys/${encodeURIComponent(keyName)}/requestToken`,
      {
        method: "POST",
        headers: providerHeaders(full),
        body: JSON.stringify({
          keyName,
          ttl: TOKEN_TTL_MS,
          capability,
          clientId,
          timestamp: requestTimestamp,
          nonce: randomBytes(16).toString("hex"),
        }),
        signal: AbortSignal.timeout(PROVIDER_TIMEOUT_MS),
        redirect: "error",
      },
    );
    if (!response.ok) {
      await response.body?.cancel();
      throw new Error();
    }
    const details = await response.json();
    const responseTimestamp = Date.now();
    if (
      !validTokenDetails(details, {
        requestTimestamp,
        responseTimestamp,
        serverChannel,
        clientChannel,
        clientId,
      })
    ) {
      throw new Error();
    }
    return {
      token: details.token,
      issued: details.issued,
      expires: details.expires,
      capability: details.capability,
      clientId: details.clientId,
    };
  } catch {
    throw new Error("Realtime provider unavailable");
  }
}

function messageFor(event) {
  const inspected = plainDataDescriptors(event);
  if (inspected === null) return null;
  const t = inspected.descriptors.t?.value;
  if (
    t === "thread.changed" &&
    exactKeys(inspected.keys, ["t", "threadId"]) &&
    matches(THREAD_ID_RE, inspected.descriptors.threadId.value)
  ) {
    return { name: "thread.changed", data: { threadId: inspected.descriptors.threadId.value } };
  }
  if (
    t === "edit.saved" &&
    exactKeys(inspected.keys, ["t", "aid", "hash"]) &&
    matches(AID_RE, inspected.descriptors.aid.value) &&
    matches(HASH_RE, inspected.descriptors.hash.value)
  ) {
    return {
      name: "edit.saved",
      data: {
        aid: inspected.descriptors.aid.value,
        hash: inspected.descriptors.hash.value,
      },
    };
  }
  return null;
}

/**
 * @param {string} docId
 * @param {
 *   | {t: "thread.changed", threadId: string}
 *   | {t: "edit.saved", aid: string, hash: string}
 * } event
 * @returns {Promise<null | {channel: string, messageId: string}>}
 */
export async function publish(docId, event) {
  const key = configuredKey();
  if (key === null) return null;
  if (typeof docId !== "string" || !DOC_ID_RE.test(docId)) {
    throw new TypeError("Invalid document id");
  }
  const message = messageFor(event);
  if (message === null) throw new TypeError("Invalid realtime event");

  try {
    const { full } = parseKey(key);
    const channel = `doc:${docId}:server`;
    const response = await fetch(
      `${ABLY_ORIGIN}/channels/${encodeURIComponent(channel)}/messages`,
      {
        method: "POST",
        headers: providerHeaders(full),
        body: JSON.stringify(message),
        signal: AbortSignal.timeout(PROVIDER_TIMEOUT_MS),
        redirect: "error",
      },
    );
    if (response.status !== 201) {
      await response.body?.cancel();
      return null;
    }
    const acknowledgement = await response.json();
    if (
      acknowledgement === null ||
      typeof acknowledgement !== "object" ||
      acknowledgement.channel !== channel ||
      typeof acknowledgement.messageId !== "string" ||
      acknowledgement.messageId === ""
    ) {
      return null;
    }
    return { channel: acknowledgement.channel, messageId: acknowledgement.messageId };
  } catch {
    return null;
  }
}
