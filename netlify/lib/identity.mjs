import { getUser, verifyRequestOrigin } from "@netlify/identity";

const DOMAIN_LABEL = "[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?";
const ORG_EMAIL_DOMAIN_PATTERN = new RegExp(`^@${DOMAIN_LABEL}(?:\\.${DOMAIN_LABEL})+$`, "i");

/** Read the site setting through the runtime-native narrow environment API. */
function runtimeOrgEmailDomain() {
  try {
    const env = globalThis.Netlify?.env;
    if (env !== undefined && env !== null && typeof env.get === "function") {
      return env.get("ORG_EMAIL_DOMAIN");
    }
    return globalThis.process?.env?.ORG_EMAIL_DOMAIN;
  } catch {
    return undefined;
  }
}

/**
 * Classify an email against the configured organization-domain suffix.
 * Invalid or unavailable configuration returns false without exposing the
 * setting. P2-G's resolveRole() remains the final capability decision.
 *
 * @param {unknown} email
 * @returns {boolean}
 */
export function isOrgEmail(email) {
  const configured = runtimeOrgEmailDomain();
  if (
    typeof configured !== "string" ||
    configured.length > 254 ||
    !ORG_EMAIL_DOMAIN_PATTERN.test(configured)
  ) {
    return false;
  }
  return typeof email === "string" && email.toLowerCase().endsWith(configured.toLowerCase());
}

/**
 * @param {Request} req
 * @returns {Promise<null | {
 *   sub: string,
 *   email: string,
 *   name: string,
 *   isOrg: boolean
 * }>}
 */
export async function identify(req) {
  const user = await getUser();
  if (user === null) {
    return null;
  }

  const email = (user.email ?? "").toLowerCase();
  const name = user.name ?? email.split("@")[0];
  const isOrg = isOrgEmail(email);

  return { sub: user.id, email, name, isOrg };
}

/**
 * @param {Request} req
 * @returns {void}
 * @throws {Response} A normalized 403 response when origin verification fails.
 */
export function requireOrigin(req) {
  try {
    verifyRequestOrigin(req);
  } catch {
    throw new Response("Bad origin", {
      status: 403,
      headers: { "Content-Type": "text/plain; charset=utf-8" },
    });
  }
}
