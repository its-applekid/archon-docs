import { requireOrigin } from "../lib/identity.mjs";
import { login } from "@netlify/identity";

const PLAIN_TEXT = "text/plain; charset=utf-8";
const NO_STORE = { "Cache-Control": "private, no-store" };
const FIXED_ORIGIN = "https://docs.example.invalid";

/** True when a string begins with exactly one leading slash and nothing else. */
function singleLeadingSlash(value) {
  return typeof value === "string" && value.startsWith("/") && !value.startsWith("//");
}

/** True when the string contains an ASCII C0 control (0x00-0x1f) or DEL (0x7f). */
function hasControlOrDel(value) {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code <= 0x1f || code === 0x7f) return true;
  }
  return false;
}

/** True when the once-decoded pathname names a reserved same-site surface. */
function isReservedDestination(decodedPathname) {
  return (
    decodedPathname === "/login" ||
    decodedPathname.startsWith("/login/") ||
    decodedPathname === "/api" ||
    decodedPathname.startsWith("/api/") ||
    decodedPathname === "/_assets" ||
    decodedPathname.startsWith("/_assets/") ||
    decodedPathname === "/.netlify" ||
    decodedPathname.startsWith("/.netlify/")
  );
}

/**
 * Restrict a post-login destination to a safe same-site path.
 *
 * @param {FormDataEntryValue | null | undefined} value
 */
export function safeNext(value) {
  if (typeof value !== "string") {
    return "/";
  }

  // Reject raw ASCII C0 controls and DEL before trimming so leading or
  // trailing tabs/newlines cannot be silently removed.
  if (hasControlOrDel(value)) {
    return "/";
  }

  const trimmed = value.trim();
  if (trimmed === "") {
    return "/";
  }

  // A scheme or scheme-relative URL, or any value that does not start with
  // exactly one literal slash, is rejected before parsing.
  if (!singleLeadingSlash(trimmed) || trimmed.includes("\\")) {
    return "/";
  }

  let url;
  try {
    url = new URL(trimmed, FIXED_ORIGIN);
  } catch {
    return "/";
  }

  // Revalidate the parser-normalized URL rather than trusting the pre-parse
  // spelling: same origin, no credentials, and an exact-one-leading-slash
  // pathname free of literal backslashes and raw controls.
  if (
    url.protocol !== "https:" ||
    url.username !== "" ||
    url.password !== "" ||
    url.host !== "docs.example.invalid" ||
    url.origin !== FIXED_ORIGIN ||
    !singleLeadingSlash(url.pathname) ||
    url.pathname.includes("\\") ||
    hasControlOrDel(url.pathname)
  ) {
    return "/";
  }

  // Decode the pathname exactly once for validation only; an encoded leading
  // slash or encoded backslash must not survive the single decode.
  let decoded;
  try {
    decoded = decodeURIComponent(url.pathname);
  } catch {
    return "/";
  }
  if (
    !singleLeadingSlash(decoded) ||
    hasControlOrDel(decoded) ||
    decoded.includes("\\")
  ) {
    return "/";
  }

  // Reserved login/api/assets/netlify surfaces are loop or bypass targets;
  // percent-encoding does not dodge the comparison.
  if (isReservedDestination(decoded)) {
    return "/";
  }

  const destination = url.pathname + url.search;
  if (!singleLeadingSlash(destination)) {
    return "/";
  }
  return destination;
}

function failureRedirect(next) {
  return new Response(null, {
    status: 302,
    headers: {
      Location: `/login/?next=${encodeURIComponent(safeNext(next))}&error=1`,
      ...NO_STORE,
    },
  });
}

/**
 * POST /api/login — the only login surface. Origin is verified before the
 * form is parsed or Identity is invoked, and every credential failure maps to
 * the same non-disclosing redirect.
 *
 * @param {Request} req
 * @returns {Promise<Response>}
 */
export default async function handler(req) {
  if (req.method !== "POST") {
    return new Response(null, {
      status: 405,
      headers: { Allow: "POST", ...NO_STORE },
    });
  }

  try {
    requireOrigin(req);
  } catch (error) {
    if (error instanceof Response) {
      error.headers.set("Cache-Control", "private, no-store");
      return error;
    }
    throw error;
  }

  let form;
  try {
    form = await req.formData();
  } catch {
    return new Response("Invalid form", {
      status: 400,
      headers: { "Content-Type": PLAIN_TEXT, ...NO_STORE },
    });
  }

  const nextEntries = form.getAll("next");
  const next =
    nextEntries.length === 1 && typeof nextEntries[0] === "string"
      ? nextEntries[0]
      : safeNext(null);

  const emailEntries = form.getAll("email");
  const passwordEntries = form.getAll("password");
  const emailValid =
    emailEntries.length === 1 && typeof emailEntries[0] === "string";
  const passwordValid =
    passwordEntries.length === 1 && typeof passwordEntries[0] === "string";
  if (!emailValid || !passwordValid) {
    return failureRedirect(next);
  }

  const email = emailEntries[0].trim().toLowerCase();
  const password = passwordEntries[0];
  if (email === "" || password === "") {
    return failureRedirect(next);
  }

  try {
    await login(email, password);
  } catch {
    return failureRedirect(next);
  }

  return new Response(null, {
    status: 302,
    headers: { Location: safeNext(next), ...NO_STORE },
  });
}

export const config = { path: "/api/login" };
