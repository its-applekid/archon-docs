// Run with: node netlify/lib/notify.test.mjs
//
// The subject is the gap #95 reports: `notify()` used to validate notification
// text more strictly than the store validated the same text on the way in, and
// it throws rather than returning a value. Because callers invoke it *after* the
// authoritative write, a body the store accepted but `notify()` rejected became
// a 500 for a comment that had already landed. These assertions pin the two
// halves of the fix — the grammar now matches the store, and the characters the
// grammar no longer rejects are removed from the Slack message instead — and
// re-pin the P4-H fan-out matrix that must not have moved.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { createNotifier, notify as defaultNotify } from "./notify.mjs";

const BELL = "\u0007"; // C0, outside tab/LF/CR
const NEL = "\u0085"; // C1
const LONE_HIGH = "\ud800";
const LONE_LOW = "\udfff";
const ASTRAL = "\u{1f600}"; // a well-formed surrogate pair

const WEBHOOK = "https://hooks.slack.com/services/T0/B0/abcdef";
const ORIGIN = "https://docs.example.com";

const THREAD_ID = "t_m8x2k1_4f7a9c31";
const SUGGESTION_ID = "s_m8x2k1_4f7a9c31";
const AID = "a3f19c2b7";
const HASH =
  "8f14e45fceea167a5a36dedd4bea2543d42049f25f0f4c31f9e8b21f841f8277";

// --------------------------------------------------------------------------
// The store's grammar, mirrored from netlify/functions/threads.mjs.
// --------------------------------------------------------------------------

// `isBodyText` is module-private in the handler, so it is restated here and the
// restatement is checked against the handler source. If the store ever tightens
// or loosens its body grammar, this assertion fails and the alignment below has
// to be re-derived rather than silently drifting apart again.
const MAX_BODY_UNITS = 8_000;

function storeAcceptsBody(value) {
  return (
    typeof value === "string" &&
    value.length >= 1 &&
    value.length <= MAX_BODY_UNITS &&
    value.trim().length > 0
  );
}

for (const handler of ["threads.mjs", "thread.mjs"]) {
  const source = readFileSync(
    fileURLToPath(new URL(`../functions/${handler}`, import.meta.url)),
    "utf8",
  );
  assert.match(
    source,
    /function isBodyText\(value\) \{\n\s*return \(\n\s*typeof value === "string" &&\n\s*value\.length >= 1 &&\n\s*value\.length <= MAX_BODY_UNITS &&\n\s*value\.trim\(\)\.length > 0\n\s*\);\n\}/,
    `${handler} body grammar drifted from the mirror in this test`,
  );
  assert.match(
    source,
    /const MAX_BODY_UNITS = 8_000;/,
    `${handler} body bound drifted from the mirror in this test`,
  );
}

// --------------------------------------------------------------------------
// Harness
// --------------------------------------------------------------------------

function makeContext() {
  const accepted = [];
  return {
    accepted,
    context: {
      waitUntil(promise) {
        accepted.push(promise);
      },
    },
  };
}

function slackConfig(extra = {}) {
  const sent = [];
  const notifier = createNotifier({
    envGet: (name) =>
      name === "SLACK_WEBHOOK_URL" ? WEBHOOK : name === "URL" ? ORIGIN : undefined,
    fetchFn: (url, init) => {
      sent.push({ url, init, text: JSON.parse(init.body).text });
      return Promise.resolve(
        new Response("ok", { status: 200, headers: { "Content-Type": "text/plain" } }),
      );
    },
    timeoutSignalFn: () => undefined,
    publishFn: () => Promise.resolve(null),
    ...extra,
  });
  return { sent, notifier };
}

function threadCreated(overrides = {}) {
  return {
    t: "thread.created",
    docId: "0a1b2c",
    threadId: THREAD_ID,
    actorName: "Ada",
    threadKind: "comment",
    body: "hello",
    quote: null,
    ...overrides,
  };
}

async function settle() {
  await new Promise((resolve) => setImmediate(resolve));
}

// --------------------------------------------------------------------------
// 1. Every character the store durably accepts is notifiable
// --------------------------------------------------------------------------

// The three characters #95 confirmed reachable from ordinary client input:
// `JSON.parse` preserves them all, `isBodyText` accepts them all, and each one
// used to make `notify()` throw TypeError("Invalid notification").
for (const [label, hostile] of [
  ["C0 bell", BELL],
  ["C1 next-line", NEL],
  ["lone high surrogate", LONE_HIGH],
  ["lone low surrogate", LONE_LOW],
  ["every reported character at once", `a${BELL}b${NEL}c${LONE_HIGH}d`],
]) {
  const body = `before ${hostile} after`;
  assert.equal(storeAcceptsBody(body), true, `${label}: store must accept it`);

  const { sent, notifier } = slackConfig();
  const { context, accepted } = makeContext();
  assert.equal(
    notifier(context, threadCreated({ body })),
    true,
    `${label}: notify must not throw on text the store accepted`,
  );
  assert.equal(accepted.length, 2, `${label}: Slack and realtime both scheduled`);

  // ...and the character never reaches Slack.
  const { text } = sent[0];
  assert.equal(sent.length, 1);
  assert.doesNotMatch(
    text,
    /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]/,
    `${label}: Slack text must carry no control characters`,
  );
  assert.equal(
    text.isWellFormed(),
    true,
    `${label}: Slack text must be well-formed UTF-16`,
  );
  assert.equal(
    JSON.parse(JSON.stringify({ text })).text,
    text,
    `${label}: Slack text must survive JSON transport unchanged`,
  );
}

// The same holds for the other text-bearing fields and the other variants, so
// the alignment is not limited to the one field the issue happened to name.
{
  const { sent, notifier } = slackConfig();
  const { context } = makeContext();
  assert.equal(
    notifier(
      context,
      threadCreated({
        actorName: `Ada${BELL}`,
        quote: `quoted${NEL}text`,
        body: `body${LONE_HIGH}`,
      }),
    ),
    true,
  );
  assert.doesNotMatch(sent[0].text, /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]/);
  assert.equal(sent[0].text.isWellFormed(), true);
  assert.match(sent[0].text, /\*Ada\*/, "a control character is stripped, not the name");
}

{
  const { sent, notifier } = slackConfig();
  const { context } = makeContext();
  assert.equal(
    notifier(context, {
      t: "suggest.created",
      docId: "0a1b2c",
      suggestionId: SUGGESTION_ID,
      aid: AID,
      actorName: `Grace${NEL}`,
      text: `proposed${BELL}${LONE_LOW}`,
    }),
    true,
  );
  assert.doesNotMatch(sent[0].text, /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]/);
  assert.equal(sent[0].text.isWellFormed(), true);
}

{
  const { sent, notifier } = slackConfig();
  const { context } = makeContext();
  assert.equal(
    notifier(context, {
      t: "suggest.decided",
      docId: "0a1b2c",
      suggestionId: SUGGESTION_ID,
      aid: AID,
      authorName: `Grace${BELL}`,
      deciderName: `Ada${LONE_HIGH}`,
      outcome: "accepted",
    }),
    true,
  );
  assert.doesNotMatch(sent[0].text, /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]/);
  assert.equal(sent[0].text.isWellFormed(), true);
}

// A name that is nothing but control characters presents as the existing
// fallback rather than as an empty bold span.
{
  const { sent, notifier } = slackConfig();
  const { context } = makeContext();
  assert.equal(notifier(context, threadCreated({ actorName: BELL + NEL })), true);
  assert.match(sent[0].text, /^\*Someone\* commented on /);
}

// A body that sanitises away entirely simply contributes no line, exactly as a
// whitespace-only presentation already did.
{
  const { sent, notifier } = slackConfig();
  const { context } = makeContext();
  assert.equal(notifier(context, threadCreated({ body: BELL + NEL })), true);
  assert.equal(sent[0].text.includes("\n"), false);
}

// Well-formed astral text is preserved, not mangled by the surrogate handling.
{
  const { sent, notifier } = slackConfig();
  const { context } = makeContext();
  assert.equal(notifier(context, threadCreated({ body: `hi ${ASTRAL}` })), true);
  assert.match(sent[0].text, /hi \u{1f600}$/u);
}

// Truncation still cuts on code points, and replacing lone surrogates first
// means the ellipsis can never land mid-pair.
{
  const { sent, notifier } = slackConfig();
  const { context } = makeContext();
  assert.equal(notifier(context, threadCreated({ body: ASTRAL.repeat(500) })), true);
  const line = sent[0].text.split("\n")[1];
  assert.equal([...line].length, 400);
  assert.equal(line.endsWith("…"), true);
  assert.equal(line.isWellFormed(), true);
}

// --------------------------------------------------------------------------
// 2. Length bounds and structural validation are unchanged
// --------------------------------------------------------------------------

// Aligning the character grammar did not turn `notify()` into a predicate that
// accepts anything: the bounds the store also enforces still hold.
{
  const { notifier } = slackConfig();
  const { context } = makeContext();
  assert.equal(storeAcceptsBody("x".repeat(MAX_BODY_UNITS)), true);
  assert.equal(notifier(context, threadCreated({ body: "x".repeat(8_000) })), true);
  assert.equal(storeAcceptsBody("x".repeat(MAX_BODY_UNITS + 1)), false);
  assert.throws(
    () => notifier(context, threadCreated({ body: "x".repeat(8_001) })),
    { name: "TypeError", message: "Invalid notification" },
  );
  assert.throws(
    () => notifier(context, threadCreated({ actorName: "x".repeat(201) })),
    { name: "TypeError", message: "Invalid notification" },
  );
}

// Programmer errors — a kind outside the union, a missing or extra key, a
// non-string body, a malformed identifier — still throw. Those are caller bugs
// rather than client input, and no store write can produce them.
{
  const { notifier } = slackConfig();
  const { context } = makeContext();
  for (const bad of [
    { ...threadCreated(), t: "thread.unknown" },
    { ...threadCreated(), extra: 1 },
    threadCreated({ body: 5 }),
    threadCreated({ body: undefined }),
    threadCreated({ threadId: "nope" }),
    threadCreated({ docId: "zzzzzz" }),
    threadCreated({ threadKind: "other" }),
    null,
    [],
    "thread.created",
  ]) {
    assert.throws(() => notifier(context, bad), {
      name: "TypeError",
      message: "Invalid notification",
    });
  }
  // A body key that the shape omits entirely is still rejected.
  const missing = threadCreated();
  delete missing.body;
  assert.throws(() => notifier(context, missing), { name: "TypeError" });
}

// --------------------------------------------------------------------------
// 3. The context predicate accepts the shapes a real platform may hand over
// --------------------------------------------------------------------------

// This predicate also runs after the durable write, so an over-tight assumption
// about a Netlify-supplied object is the same failure in every deployment at
// once. A callable `waitUntil` is all the fan-out needs.
{
  const { notifier } = slackConfig();
  const seen = [];

  class PlatformContext {
    waitUntil(promise) {
      seen.push(promise);
    }
  }
  const prototypeMethod = new PlatformContext();

  const accessor = {};
  Object.defineProperty(accessor, "waitUntil", {
    get: () => (promise) => seen.push(promise),
    enumerable: true,
    configurable: true,
  });

  const inheritedData = Object.create({
    waitUntil: (promise) => seen.push(promise),
  });

  const nullPrototype = Object.create(null);
  nullPrototype.waitUntil = (promise) => seen.push(promise);

  const withExtras = {
    waitUntil: (promise) => seen.push(promise),
    requestId: "abc",
  };

  for (const context of [
    prototypeMethod,
    accessor,
    inheritedData,
    nullPrototype,
    withExtras,
  ]) {
    seen.length = 0;
    assert.equal(notifier(context, threadCreated()), true);
    assert.equal(seen.length, 2);
  }

  // Unrelated accessors are still never read.
  let touched = false;
  const untouched = { waitUntil: () => {} };
  Object.defineProperty(untouched, "unrelated", {
    get: () => {
      touched = true;
      return 1;
    },
    enumerable: true,
  });
  assert.equal(notifier(untouched, threadCreated()), true);
  assert.equal(touched, false, "an unrelated context accessor must not be read");
}

// Proxy rejection still precedes reflection, and a context that cannot schedule
// anything is still rejected rather than silently dropping the fan-out.
{
  const { notifier } = slackConfig();
  let trapped = false;
  const proxy = new Proxy(
    { waitUntil: () => {} },
    {
      get(target, key, receiver) {
        trapped = true;
        return Reflect.get(target, key, receiver);
      },
    },
  );
  assert.throws(() => notifier(proxy, threadCreated()), {
    name: "TypeError",
    message: "Invalid notification",
  });
  assert.equal(trapped, false, "the Proxy must be rejected before any trap runs");

  for (const bad of [null, undefined, {}, [], "context", 7, { waitUntil: 1 }]) {
    assert.throws(() => notifier(bad, threadCreated()), {
      name: "TypeError",
      message: "Invalid notification",
    });
  }

  // A context whose accessor throws is reported as the documented rejection,
  // not as whatever the platform threw, so the caller boundary sees one type.
  const throwing = {};
  Object.defineProperty(throwing, "waitUntil", {
    get() {
      throw new RangeError("platform exploded");
    },
    configurable: true,
  });
  assert.throws(() => notifier(throwing, threadCreated()), {
    name: "TypeError",
    message: "Invalid notification",
  });
}

// --------------------------------------------------------------------------
// 4. The P4-H fan-out matrix is unchanged
// --------------------------------------------------------------------------

{
  const published = [];
  const { sent, notifier } = slackConfig({
    publishFn: (docId, event) => {
      published.push({ docId, event });
      return Promise.resolve(null);
    },
  });

  const edit = { t: "edit.saved", docId: "0a1b2c", aid: AID, hash: HASH };
  const suggestion = {
    t: "suggest.created",
    docId: "0a1b2c",
    suggestionId: SUGGESTION_ID,
    aid: AID,
    actorName: "Grace",
    text: "proposed",
  };

  const replied = threadCreated({ t: "thread.replied" });
  delete replied.threadKind;

  const cases = [
    [threadCreated(), 1, 1],
    [replied, 1, 1],
    [suggestion, 1, 0],
    [edit, 0, 1],
  ];

  for (const [notification, slackCount, realtimeCount] of cases) {
    sent.length = 0;
    published.length = 0;
    const { context, accepted } = makeContext();
    assert.equal(notifier(context, notification), true, notification.t);
    assert.equal(sent.length, slackCount, `${notification.t}: Slack promises`);
    assert.equal(published.length, realtimeCount, `${notification.t}: realtime promises`);
    assert.equal(accepted.length, slackCount + realtimeCount, `${notification.t}: waitUntil`);
  }

  // The realtime projection is still exactly identifiers, proved by whole-object
  // equality rather than by looking for selected property spellings.
  published.length = 0;
  const { context } = makeContext();
  notifier(
    context,
    threadCreated({ body: `secret${BELL}`, quote: "quoted", actorName: "Ada" }),
  );
  assert.equal(published.length, 1);
  assert.equal(published[0].docId, "0a1b2c");
  assert.deepEqual(published[0].event, { t: "thread.changed", threadId: THREAD_ID });
  assert.equal(Object.getPrototypeOf(published[0].event), Object.prototype);

  published.length = 0;
  const editContext = makeContext();
  notifier(editContext.context, edit);
  assert.deepEqual(published[0].event, { t: "edit.saved", aid: AID, hash: HASH });
}

// With Slack unconfigured, a text-bearing input that used to be rejected before
// the config read is still accepted, still schedules realtime, and a suggestion
// still schedules nothing.
{
  const published = [];
  const notifier = createNotifier({
    envGet: () => undefined,
    fetchFn: () => assert.fail("Slack must not be called when unconfigured"),
    timeoutSignalFn: () => undefined,
    publishFn: (docId, event) => {
      published.push({ docId, event });
      return Promise.resolve(null);
    },
  });

  const thread = makeContext();
  assert.equal(notifier(thread.context, threadCreated({ body: `x${NEL}` })), true);
  assert.equal(thread.accepted.length, 1);
  assert.equal(published.length, 1);

  const suggestion = makeContext();
  assert.equal(
    notifier(suggestion.context, {
      t: "suggest.created",
      docId: "0a1b2c",
      suggestionId: SUGGESTION_ID,
      aid: AID,
      actorName: "Grace",
      text: `proposed${BELL}`,
    }),
    false,
  );
  assert.equal(suggestion.accepted.length, 0);
  assert.equal(published.length, 1, "a suggestion still publishes nothing");
}

// A failing sink still cannot reach the durable response, and the two sinks stay
// independent.
{
  const notifier = createNotifier({
    envGet: (name) => (name === "SLACK_WEBHOOK_URL" ? WEBHOOK : ORIGIN),
    fetchFn: () => {
      throw new Error("slack down");
    },
    timeoutSignalFn: () => undefined,
    publishFn: () => Promise.reject(new Error("ably down")),
  });
  const { context, accepted } = makeContext();
  assert.equal(notifier(context, threadCreated({ body: `x${BELL}` })), true);
  assert.equal(accepted.length, 1, "only the realtime promise was scheduled");
  await assert.rejects(accepted[0], /ably down/);
  await settle();
}

// The default export is still a usable notifier built from the real defaults.
assert.equal(typeof defaultNotify, "function");
assert.throws(() => defaultNotify({ waitUntil: () => {} }, { t: "nope" }), {
  name: "TypeError",
  message: "Invalid notification",
});

console.log("PASS  notify() accepts every text the store durably accepts");
console.log("PASS  notify() sanitises control characters and lone surrogates for Slack");
console.log("PASS  notify() accepts every ordinary platform context shape");
console.log("PASS  P4-H fan-out matrix and text-free realtime projection preserved");
