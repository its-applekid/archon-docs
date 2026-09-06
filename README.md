# archon-docs

An example of a hosted [Archon](https://github.com/aiur-team/archon) instance.

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
| `netlify.toml`, `_redirects` | Static publish, and the two routes the site builder would generate |

## The document

`how-archon-works/` is deliberately meta: **an architecture document about how Archon works, built with
Archon**, so the page a reader is looking at is itself the demonstration. Open
`how-archon-works/dist/how-archon-works.html` from disk and it works — that is the argument it makes.

To rebuild it you need a checkout of `aiur-team/archon` and Node 18 or later:

```bash
cp -r /path/to/archon-docs/how-archon-works /path/to/archon/
cd /path/to/archon && templates/build how-archon-works
```

The builder fails on a missing section field, a duplicate section id, an unfilled placeholder and an
unknown character reference, then reports tag balance, theme states and size. Commit `dist/` and
`anchors.json` with the source.

## What this repository is not

It is not the Archon source. The template, the builder, the client modules, the Netlify functions and
the design documents all live in [`aiur-team/archon`](https://github.com/aiur-team/archon).

It also does not run the live layer. A repository-backed instance sets `command = "templates/build
--site"`, vendors `templates/`, and configures its site environment — an organisation email domain, the
document owners, the source repository and a token for it, and optionally a realtime key. This showcase
publishes a committed artifact, so what you get here is the document, not the sign-in.
