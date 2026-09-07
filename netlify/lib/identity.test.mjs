import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import test from "node:test";
import vm from "node:vm";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const IDENTITY_SOURCE = process.env.IDENTITY_TEST_SOURCE ??
  resolve(ROOT, "netlify/lib/identity.mjs");
const identitySource = readFile(IDENTITY_SOURCE, "utf8");

async function loadIdentity({
  domain,
  email = "member@example.com",
  netlify = false,
  throwOnEnvRead = false,
}) {
  const logs = [];
  const environment = domain === undefined ? {} : { ORG_EMAIL_DOMAIN: domain };
  const context = vm.createContext({
    console: Object.freeze({
      error: (...values) => logs.push(values),
      info: (...values) => logs.push(values),
      log: (...values) => logs.push(values),
      warn: (...values) => logs.push(values),
    }),
    ...(netlify
      ? { Netlify: { env: { get: (name) => {
        if (throwOnEnvRead) throw new Error(`unavailable: ${environment[name]}`);
        return environment[name];
      } } } }
      : { process: { env: environment } }),
    Response,
  });
  const source = await identitySource;
  const identity = new vm.SourceTextModule(source, {
    context,
    identifier: "identity.mjs",
  });
  const provider = new vm.SyntheticModule(
    ["getUser", "verifyRequestOrigin"],
    function initialize() {
      this.setExport("getUser", async () => ({ id: "u_fixture_member", email, name: "Member" }));
      this.setExport("verifyRequestOrigin", () => {});
    },
    { context, identifier: "@netlify/identity" },
  );
  await identity.link((specifier) => {
    assert.equal(specifier, "@netlify/identity");
    return provider;
  });
  await identity.evaluate();
  return { identity: identity.namespace, logs };
}

test("configured organisation domain classifies exact mailbox domains", async () => {
  const matching = await loadIdentity({ domain: "@example.com" });
  assert.equal((await matching.identity.identify(new Request("https://docs.invalid"))).isOrg, true);

  const outside = await loadIdentity({
    domain: "@example.com",
    email: "member@outside.invalid",
  });
  assert.equal((await outside.identity.identify(new Request("https://docs.invalid"))).isOrg, false);
});

test("missing and malformed organisation domains fail closed", async (t) => {
  const cases = [
    ["unset", undefined],
    ["empty", ""],
    ["whitespace-only", "   "],
    ["missing leading at-sign", "example.com"],
    ["single DNS label", "@localhost"],
    ["surrounding whitespace", " @example.com"],
    ["embedded separator", "@example,com"],
    ["multiple at-signs", "@example.com@outside.invalid"],
    ["empty DNS label", "@example..com"],
  ];

  for (const netlify of [false, true]) {
    for (const [label, domain] of cases) {
      await t.test(`${netlify ? "Netlify.env" : "process.env"}: ${label}`, async () => {
        const loaded = await loadIdentity({ domain, email: "member@example.com", netlify });
        const result = await loaded.identity.identify(new Request("https://docs.invalid"));
        assert.equal(result.isOrg, false);
        assert.deepEqual(loaded.logs, []);
      });
    }
  }
});

test("suffix near-misses do not classify as organisation mailboxes", async () => {
  // A domain merely CONTAINING the configured one must not match. The last two
  // are registrable by an attacker, so an `includes`-style check would hand them
  // organisation membership; only exact-suffix matching rejects them.
  for (const email of [
    "member@notexample.com",
    "member@sub.example.com",
    "member@example.com.evil.com",
    "member@example.como",
  ]) {
    const loaded = await loadIdentity({ domain: "@example.com", email });
    assert.equal((await loaded.identity.identify(new Request("https://docs.invalid"))).isOrg, false);
  }
});

test("organisation matching is case-insensitive in both runtimes", async () => {
  for (const netlify of [false, true]) {
    const loaded = await loadIdentity({
      domain: "@EXAMPLE.COM",
      email: "MEMBER@Example.Com",
      netlify,
    });
    const result = await loaded.identity.identify(new Request("https://docs.invalid"));
    assert.equal(result.email, "member@example.com");
    assert.equal(result.isOrg, true);
  }
});

test("invalid configuration is neither thrown nor logged", async () => {
  const configuredValue = "@internal.example.invalid;debug=true";
  const loaded = await loadIdentity({
    domain: configuredValue,
    email: "guest@outside.invalid",
  });

  const result = await loaded.identity.identify(new Request("https://docs.invalid"));
  assert.equal(result.isOrg, false);
  assert.equal(JSON.stringify(result).includes(configuredValue), false);
  assert.deepEqual(loaded.logs, []);
});

test("an unavailable runtime environment fails closed without disclosure", async () => {
  const configuredValue = "@private.example.invalid";
  const loaded = await loadIdentity({
    domain: configuredValue,
    email: "member@outside.invalid",
    netlify: true,
    throwOnEnvRead: true,
  });

  const result = await loaded.identity.identify(new Request("https://docs.invalid"));
  assert.equal(result.isOrg, false);
  assert.equal(JSON.stringify(result).includes(configuredValue), false);
  assert.deepEqual(loaded.logs, []);
});
