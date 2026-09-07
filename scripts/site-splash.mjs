#!/usr/bin/env node
/**
 * Put the hand-written splash back at the site root.
 *
 * `docbuild --site` always writes a generated root index: one row per
 * discovered document, theme.css inlined, deterministic. For a repository with
 * several documents that is the right front page. This one has a single
 * document and a designed splash, so the generated index is discarded and
 * `index.html` from the repository root takes its place.
 *
 * The replacement is asserted rather than assumed. Both files must exist and
 * the generated one must be the file this script expects to be replacing, so
 * that a builder change which stops writing a root index, or a deleted splash,
 * fails the deploy here instead of publishing whichever page happened to
 * survive. Copying without checking is how a front page disappears quietly.
 *
 *   node scripts/site-splash.mjs
 *
 * Output contract: one `PASS` line on stdout and exit 0, or one
 * `FAIL site splash:` line on stderr and exit 1.
 */

import { copyFileSync, readFileSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const SPLASH = join(ROOT, "index.html");
const GENERATED = join(ROOT, "_site", "index.html");

/** The generated index's title, from docbuild's renderIndex(). */
const GENERATED_TITLE = "<title>Architecture docs</title>";

const fail = (message) => {
  process.stderr.write(`FAIL site splash: ${message}\n`);
  process.exit(1);
};

const regularFile = (path, label) => {
  let stat;
  try {
    stat = statSync(path);
  } catch (e) {
    fail(`${label}: ${e.message}`);
  }
  if (!stat.isFile()) fail(`${label}: expected a regular file`);
};

regularFile(SPLASH, "index.html");
regularFile(GENERATED, "_site/index.html");

// If docbuild ever stops writing a root index, _site/index.html is either
// absent (caught above) or something else's output, and overwriting it blindly
// would be the bug this check exists to refuse.
if (!readFileSync(GENERATED, "utf8").includes(GENERATED_TITLE)) {
  fail("_site/index.html is not the generated document index; refusing to replace it");
}

try {
  copyFileSync(SPLASH, GENERATED);
} catch (e) {
  fail(`_site/index.html: ${e.message}`);
}

process.stdout.write("PASS site splash: index.html is the site root\n");
