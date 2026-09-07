// Generated file. Do not edit.
//
// The compiled output of `templates/docbuild/src/inline_md.ts`, vendored
// here so the deploy tree the P4-S connect tool copies is self-contained.
// Editing this file by hand cannot change what the builder or the browser
// runs; edit that source instead.
//
// Regenerate with `node scripts/vendor-netlify-lib.mjs --write`. CI runs
// `node scripts/vendor-netlify-lib.mjs` and fails on any drift.

/**
 * The canonical inline-text converter for editable block bodies.
 *
 * This is not Markdown. Its whole mark vocabulary is three paired inline HTML
 * elements — `code`, `strong`, `em` — and their three editable-text
 * delimiters — backticks, `**`, and `*`. Both directions are bounded string
 * transforms made of ordered literal passes; nothing here parses HTML or
 * Markdown, and nothing is recursive.
 *
 * The module has no imports, no filesystem or Node access, no DOM reference,
 * no side effect, no locale operation, no regular-expression lookbehind and no
 * dependency. Both functions operate on JavaScript strings and return a string
 * for every string input; they never throw on unsupported syntax. Unsupported
 * syntax is preserved literally, so exact-equality callers (the round-trip
 * gate) can reject a containing block instead of silently normalising it.
 *
 * Because each ordered pass inspects the output of the earlier passes, the
 * exact cross-mark nested forms those passes produce are representable when the
 * reverse passes reproduce the original string. Every other nested form gets no
 * special interpretation and is admitted only if the declared transforms happen
 * to reverse exactly.
 */
/** Replace every exact `needle` in `input` with `replacement`. */
const replaceLiteral = (input, needle, replacement) => input.split(needle).join(replacement);
/**
 * One `untag` pass: scan left to right for the next exact `<tag>`. When no
 * exact `</tag>` follows that opening tag, append the untouched remainder and
 * stop the pass. Otherwise the first following close wins: append the preceding
 * bytes, `open`, the bytes between the two tags unchanged, and `close`, then
 * resume immediately after the close.
 */
function untag(input, tag, open, close) {
    const openTag = `<${tag}>`;
    const closeTag = `</${tag}>`;
    let out = "";
    let rest = input;
    for (;;) {
        const openAt = rest.indexOf(openTag);
        if (openAt === -1)
            return out + rest;
        const closeAt = rest.indexOf(closeTag, openAt + openTag.length);
        if (closeAt === -1)
            return out + rest;
        out += rest.slice(0, openAt);
        out += open;
        out += rest.slice(openAt + openTag.length, closeAt);
        out += close;
        rest = rest.slice(closeAt + closeTag.length);
    }
}
/**
 * One `wrap` pass. Find the next delimiter from left to right and let `run` be
 * the bytes after it through, but not including, the first occurrence of the
 * delimiter's single character. Wrap only when `run` is nonempty and the bytes
 * immediately following `run` start with the complete delimiter; on success
 * append `<tag>run</tag>` and resume after the closing delimiter. On failure
 * append through the opening delimiter unchanged and resume after it.
 */
function wrap(input, delimiter, tag) {
    const single = delimiter[0];
    let out = "";
    let rest = input;
    for (;;) {
        const openAt = rest.indexOf(delimiter);
        if (openAt === -1)
            return out + rest;
        const runStart = openAt + delimiter.length;
        const singleAt = rest.indexOf(single, runStart);
        if (singleAt === -1) {
            // No closing marker anywhere after this opener: literal through the
            // opening delimiter, then keep scanning past it.
            out += rest.slice(0, runStart);
            rest = rest.slice(runStart);
            continue;
        }
        const run = rest.slice(runStart, singleAt);
        if (run !== "" && rest.startsWith(delimiter, singleAt)) {
            out += rest.slice(0, openAt);
            out += `<${tag}>`;
            out += run;
            out += `</${tag}>`;
            rest = rest.slice(singleAt + delimiter.length);
        }
        else {
            // The first single character is not a complete closing delimiter (or the
            // run is empty): treat the opening delimiter as literal and continue
            // after it.
            out += rest.slice(0, runStart);
            rest = rest.slice(runStart);
        }
    }
}
/**
 * Convert an inner-HTML string to editable text.
 *
 * Stages, in this exact order:
 *  1. `untag` for `code`, opening/closing delimiter `` ` ``.
 *  2. `untag` for `strong`, delimiter `**`.
 *  3. `untag` for `em`, delimiter `*`.
 *  4. Decode by literal split/join in this order: `&lt;` to `<`, `&gt;` to
 *     `>`, then `&amp;` to `&`.
 */
export function toMd(html) {
    let out = untag(untag(untag(html, "code", "`", "`"), "strong", "**", "**"), "em", "*", "*");
    out = replaceLiteral(out, "&lt;", "<");
    out = replaceLiteral(out, "&gt;", ">");
    out = replaceLiteral(out, "&amp;", "&");
    return out;
}
/**
 * Convert editable text to an inner-HTML string.
 *
 * Stages, in this exact order:
 *  1. Encode literal `&` as `&amp;`, then `<` as `&lt;`, then `>` as `&gt;`
 *     using literal split/join. Quotes are not encoded in element text.
 *  2. `wrap` for delimiter `` ` `` and tag `code`.
 *  3. `wrap` for delimiter `**` and tag `strong`.
 *  4. `wrap` for delimiter `*` and tag `em`.
 */
export function toHtml(text) {
    let out = replaceLiteral(text, "&", "&amp;");
    out = replaceLiteral(out, "<", "&lt;");
    out = replaceLiteral(out, ">", "&gt;");
    out = wrap(out, "`", "code");
    out = wrap(out, "**", "strong");
    out = wrap(out, "*", "em");
    return out;
}
