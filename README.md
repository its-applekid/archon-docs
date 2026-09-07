# archon-docs

A hosted [Archon](https://github.com/aiur-team/archon) instance. One splash page, one document, and the
live layer running behind it.

Archon is **Always-on Architecture Docs**: a document builds into one self-contained HTML file — every
stylesheet and script inlined, no external request except a font — and that same file gains sign-in,
comments anchored to text that moves, inline suggestions and edits, per-document roles, history and
near-real-time presence when it is served by an Archon site.

## What is here

| Path | What it is |
|---|---|
| `index.html` | The splash page. Plain HTML and CSS, no build step |
| `how-archon-works/` | The example document, as an Archon document instance |
| `how-archon-works/doc.json` | Its masthead and its permanent id `3c7f1a` |
| `how-archon-works/sections/` | The source, one file per section |
| `how-archon-works/anchors.json` | Committed block identities, so a comment survives a rebuild |
| `how-archon-works/dist/` | The built artifact and its edit manifest |
| `netlify/` | The live layer, vendored from `aiur-team/archon`: functions, shared lib, edge gate |
| `login/`, `invite/` | The two static pages the site build copies in, vendored the same way |
| `scripts/site-splash.mjs` | Puts `index.html` back at the site root after the site build |
| `netlify.toml` | The build command, the function directory, and the edge gate |

## How it is assembled

The **builder** comes from npm: `@aiur-team/docbuild` carries the compiled builder plus the base assets
and the skeleton, so nothing under `templates/` needs to be copied here and there is no second copy of
the theme to drift.

The **live layer** is vendored. `netlify/` is not part of that package — a deploy carries `netlify/`,
`netlify.toml` and the lockfile, and there is no other way for a consumer to obtain it — so the tree is
copied byte-for-byte from `aiur-team/archon`. Every relative import under `netlify/` resolves under
`netlify/`; that is the property that makes the copy safe to move, and Archon's
`scripts/vendor-netlify-lib.mjs` is what holds it upstream. Re-vendor with a plain recursive copy of
`netlify/`, `login/` and `invite/`; never hand-edit a file in them.

The build is two commands:

```bash
npm install
npm run build        # docbuild --site && node scripts/site-splash.mjs
```

`docbuild --site` writes `_site/` from scratch — `_site/how-archon-works/index.html`, the `login/` and
`invite/` pages, `_redirects` with the permanent `/d/3c7f1a` route, and a generated root index listing
every document. That last file is the one thing this repository does not want, because its front page is
the splash. `scripts/site-splash.mjs` replaces it and fails the build if the generated index is missing
or is not the file it expects, so the splash cannot be lost quietly.

## Setting the site up by hand

These are the steps a person has to do in the Netlify UI, in order. Nothing here can be committed.

1. **Create the site** from this repository. `netlify.toml` already sets the build command, the publish
   directory, the function directory and the edge gate; change none of them.
2. **Enable Identity** on the site (Site configuration → Identity). Sign-in is Netlify Identity; without
   it every gated path answers 503.
3. **Set registration** to *Invite only* or *Open* under Identity → Registration. Open is what makes this
   a public demo; invite-only is what makes it a private instance.
4. **Enable Netlify Blobs.** Access rows, threads, suggestions and history all live in the site's blob
   store. No variable configures it; it is on or it is not.
5. **Set the environment variables below**, scoped to **Functions** rather than Builds. The edge gate and
   the functions read them at request time; the build reads none of them.
6. **Deploy.** The first deploy is the first time the gate runs.

### Required

| Variable | Value |
|---|---|
| `ORG_EMAIL_DOMAIN` | The organisation email suffix, including the leading `@` — for example `@example.com`. Matching is case-insensitive. Unset, empty or malformed grants **nobody** organisation membership; it fails closed on purpose. |
| `DOC_OWNERS` | Comma-separated `<document-id>:<email>` owner seeds. For this repository the document id is `3c7f1a`, so one seed looks like `3c7f1a:owner@example.com`. |

### Optional

| Variable | Effect when set |
|---|---|
| `PUBLIC_DEFAULT_ROLE` | `viewer` or `commenter`. Gives any signed-in visitor that role on a deliberately public instance. This is the demo access posture and the only thing it is used for here; unset, only owners and explicitly granted users can read. |
| `ABLY_API_KEY` | Turns on realtime presence and live event fan-out. Unset, the document still works; it polls instead. |
| `SLACK_WEBHOOK_URL` | Posts comment and suggestion notifications to a Slack webhook. |

### Optional, but all four together or none

Repository-backed editing. Set all four and an edit commits back through the token as a reviewable
change on the source branch. Set none and the instance is standalone: an editor changes the live
document with no review, and export is the only path back to a reviewable artifact. **Partial
configuration is a fatal invalid state** — `DOCS_REPO` with any of the others missing fails, and so does
any `DOCS_*` variable without `DOCS_REPO`.

| Variable | Value |
|---|---|
| `DOCS_REPO` | This repository, in `<owner>/<repository>` form |
| `DOCS_BASE_BRANCH` | The branch edits land on. Defaults to `main` |
| `DOCS_GITHUB_TOKEN` | A fine-grained token with contents write on `DOCS_REPO` |
| `DOCS_BOT_EMAIL` | The committer email edits are attributed to |

`URL` is set by Netlify itself and is read only to build absolute links in notifications. Nothing here
sends a configuration value to a caller or writes one to a log.

## The document

`how-archon-works/` is deliberately meta: **an architecture document about how Archon works, built with
Archon**, so the page a reader is looking at is itself the demonstration. Open
`how-archon-works/dist/how-archon-works.html` from disk and it works — that is the argument it makes.

Rebuild one document on its own with `npx docbuild how-archon-works`. The builder fails on a missing
section field, a duplicate section id, an unfilled placeholder and an unknown character reference, then
reports tag balance, theme states and size. `dist/` and `anchors.json` are committed with the source, and
a rebuild must leave them byte-identical.

## What is public and what is not

The splash at `/` is the only path excluded from the edge gate beyond sign-in, the API and hashed
assets. `/how-archon-works/` is gated: an unauthenticated reader is sent to `/login/`, and what a
signed-in reader may do is decided by `DOC_OWNERS`, `ORG_EMAIL_DOMAIN`, `PUBLIC_DEFAULT_ROLE` and any
per-document grant, never by the request.

## What this repository is not

It is not the Archon source. The template, the builder, the client modules and the design documents all
live in [`aiur-team/archon`](https://github.com/aiur-team/archon). What is here is one instance of it.
