import { requireOrigin } from "../lib/identity.mjs";
import { logout } from "@netlify/identity";

const NO_STORE = { "Cache-Control": "private, no-store" };

/**
 * POST /api/logout — clears the runtime-owned session. Origin is verified
 * before Identity is invoked; logout is idempotent and never discloses a
 * rejected upstream call.
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

  try {
    await logout();
  } catch {
    // The pinned package clears the server-side auth cookies even when its
    // upstream logout call fails; nothing here may be exposed to the caller.
  }

  return new Response(null, {
    status: 302,
    headers: { Location: "/login/", ...NO_STORE },
  });
}

export const config = { path: "/api/logout" };
