// Generated file. Do not edit.
//
// The compiled output of `templates/docbuild/src/anchor-core.ts`, vendored
// here so the deploy tree the P4-S connect tool copies is self-contained.
// Editing this file by hand cannot change what the builder or the browser
// runs; edit that source instead.
//
// Regenerate with `node scripts/vendor-netlify-lib.mjs --write`. CI runs
// `node scripts/vendor-netlify-lib.mjs` and fails on any drift.

/**
 * The single shared block boundary and normalisation core.
 *
 * This module is the only source of the block tag list, whitespace
 * normalisation, and raw-HTML block scanning. It has no imports and must not
 * reference Node built-ins or any global host object: the builder compiles
 * this exact ESM, inlines it into the page ahead of the feature modules, and
 * exposes only the runtime values through the shared anchor object.
 *
 * `scanBlocks()` implements the bounded HTML grammar this platform relies on:
 * paired block candidates from `BLOCK`, opaque comments and `script`/`style`
 * raw text, quoted attributes, and the exact semicolon-required character
 * reference set. It never mutates its argument and reports source offsets so
 * the Node pass can splice generated attributes without reserializing markup.
 */
export const BLOCK = [
    "p", "li", "h2", "h3", "h4", "td", "th", "pre", "blockquote", "figcaption", "dd", "dt",
];
/** Collapse every run of JavaScript whitespace to one space, then trim. */
export const norm = (s) => s.replace(/\s+/g, " ").trim();
const BLOCK_SET = new Set(BLOCK);
const NAMED = {
    amp: "&",
    apos: "'",
    gt: ">",
    harr: "\u2194",
    lt: "<",
    mdash: "\u2014",
    nbsp: "\u00a0",
    ndash: "\u2013",
    quot: '"',
    rarr: "\u2192",
};
function coreErr(offset, message) {
    throw new Error(`anchor scan at ${offset}: ${message}`);
}
const isAsciiLetter = (c) => c !== undefined && c.length === 1 && /[A-Za-z]/.test(c);
const isAsciiDigit = (c) => c !== undefined && c.length === 1 && /[0-9]/.test(c);
const isAsciiAlnum = (c) => isAsciiLetter(c) || isAsciiDigit(c);
const isHexDigit = (c) => c !== undefined && c.length === 1 && /[0-9a-fA-F]/.test(c);
const isAsciiWhitespace = (c) => c !== undefined && c.length === 1 && /[ \t\n\r\f\v]/.test(c);
/** Tag names are ASCII letters then letters, digits or hyphens. */
const isTagNameChar = (c) => isAsciiAlnum(c) || c === "-";
/**
 * Scan a section-body fragment and return its outermost nonempty block
 * elements in source order. Every member of `BLOCK` is paired; comments and
 * raw-text elements are opaque; other tags are ordinary markup.
 */
export function scanBlocks(fragment) {
    const results = [];
    const stack = [];
    const n = fragment.length;
    let i = 0;
    const top = () => stack[stack.length - 1];
    const appendText = (s) => {
        if (stack.length > 0)
            top().chunks.push(s);
    };
    // ------------------------------------------------------------------- entities
    const decodeReference = (amp) => {
        const next = fragment[amp + 1];
        if (next === "#") {
            let j = amp + 2;
            let hex = false;
            const x = fragment[j];
            if (x === "x" || x === "X") {
                hex = true;
                j++;
            }
            const digitsStart = j;
            while (j < n && (hex ? isHexDigit(fragment[j]) : isAsciiDigit(fragment[j])))
                j++;
            if (j === digitsStart)
                coreErr(amp, "numeric character reference is malformed");
            const after = fragment[j];
            if (isAsciiLetter(after))
                coreErr(amp, "numeric character reference is malformed");
            if (after !== ";")
                coreErr(amp, 'numeric character reference is missing ";"');
            const value = parseInt(fragment.slice(digitsStart, j), hex ? 16 : 10);
            const scalar = value >= 1 && value <= 0x10ffff && !(value >= 0xd800 && value <= 0xdfff);
            if (!scalar)
                coreErr(amp, "numeric character reference is not a Unicode scalar value");
            appendText(String.fromCodePoint(value));
            return j + 1;
        }
        if (isAsciiLetter(next)) {
            let j = amp + 1;
            while (j < n && isAsciiAlnum(fragment[j]))
                j++;
            if (j >= n || fragment[j] !== ";") {
                coreErr(amp, 'named character reference is missing ";"');
            }
            const name = fragment.slice(amp + 1, j);
            const decoded = NAMED[name];
            if (decoded === undefined)
                coreErr(amp, `unknown named character reference "${name}"`);
            appendText(decoded);
            return j + 1;
        }
        // A bare ampersand not starting a candidate is literal text.
        appendText("&");
        return amp + 1;
    };
    // ------------------------------------------------------------------ raw text
    const skipRawText = (open, openEnd, tag) => {
        let m = openEnd;
        while (m < n) {
            const lt = fragment.indexOf("<", m);
            if (lt === -1)
                coreErr(open, `unclosed raw-text element ${tag}`);
            if (fragment[lt + 1] === "/") {
                let q = lt + 2;
                const ns = q;
                while (q < n && isTagNameChar(fragment[q]))
                    q++;
                if (fragment.slice(ns, q).toLowerCase() === tag) {
                    let r = q;
                    while (r < n && isAsciiWhitespace(fragment[r]))
                        r++;
                    if (fragment[r] === ">")
                        return r + 1;
                }
            }
            m = lt + 1;
        }
        coreErr(open, `unclosed raw-text element ${tag}`);
    };
    // ------------------------------------------------------------- tag handling
    /**
     * Read a complete start-tag token beginning at `<`. Returns its end offset
     * (just past the closing `>`), whether it is self-closing, and the
     * canonical-lowercased tag name. Throws `unterminated tag` when the `>` is
     * never found, honoring quoted attribute values.
     */
    const readStartTag = (start) => {
        let k = start + 1;
        const ns = k;
        while (k < n && isTagNameChar(fragment[k]))
            k++;
        const name = fragment.slice(ns, k).toLowerCase();
        let quote = null;
        for (; k < n; k++) {
            const c = fragment[k];
            if (quote !== null) {
                if (c === quote)
                    quote = null;
            }
            else if (c === '"' || c === "'") {
                quote = c;
            }
            else if (c === ">") {
                return { name, end: k + 1, selfClosing: false };
            }
            else if (c === "/" && fragment[k + 1] === ">") {
                return { name, end: k + 2, selfClosing: true };
            }
        }
        coreErr(start, "unterminated tag");
    };
    /**
     * Consume an ordinary tag-like token (`</name ...>`, `<!DOCTYPE>`, ...) that
     * does not participate in block scanning. Throws `unterminated tag` when the
     * token never reaches a `>`.
     */
    const skipOrdinaryToken = (start) => {
        let k = start + 1;
        let quote = null;
        for (; k < n; k++) {
            const c = fragment[k];
            if (quote !== null) {
                if (c === quote)
                    quote = null;
            }
            else if (c === '"' || c === "'") {
                quote = c;
            }
            else if (c === ">") {
                return k + 1;
            }
        }
        coreErr(start, "unterminated tag");
    };
    while (i < n) {
        const c = fragment[i];
        if (c === "<") {
            if (fragment.startsWith("<!--", i)) {
                const end = fragment.indexOf("-->", i + 4);
                if (end === -1)
                    coreErr(i, "unterminated HTML comment");
                i = end + 3;
                continue;
            }
            const slash = fragment[i + 1] === "/";
            const nameStart = slash ? i + 2 : i + 1;
            if (isAsciiLetter(fragment[nameStart])) {
                if (slash) {
                    // Candidate closing tag: parse the name and require only ASCII
                    // whitespace between it and the closing `>`.
                    let q = nameStart;
                    const ns = q;
                    while (q < n && isTagNameChar(fragment[q]))
                        q++;
                    const closeName = fragment.slice(ns, q);
                    let r = q;
                    while (r < n && isAsciiWhitespace(fragment[r]))
                        r++;
                    if (fragment[r] === ">") {
                        const closeEnd = r + 1;
                        const lower = closeName.toLowerCase();
                        if (BLOCK_SET.has(lower)) {
                            if (stack.length === 0 || top().tag !== lower) {
                                coreErr(i, `unexpected closing block </${lower}>`);
                            }
                            const frame = stack.pop();
                            const raw = frame.chunks.join("");
                            if (frame.outer) {
                                const text = norm(raw);
                                if (text !== "") {
                                    results.push({
                                        tag: frame.tag,
                                        openStart: frame.openStart,
                                        openEnd: frame.openEnd,
                                        innerStart: frame.openEnd,
                                        innerEnd: i,
                                        closeEnd,
                                        text,
                                    });
                                }
                            }
                            else if (stack.length > 0) {
                                top().chunks.push(raw);
                            }
                            i = closeEnd;
                        }
                        else {
                            // An ordinary non-block closing tag contributes no text.
                            i = closeEnd;
                        }
                        continue;
                    }
                    // `</name ...>` with junk before `>` is not a valid closing tag;
                    // consume it as ordinary markup and continue scanning inside.
                    i = skipOrdinaryToken(i);
                    continue;
                }
                const tag = readStartTag(i);
                if (tag.name === "script" || tag.name === "style") {
                    if (tag.selfClosing) {
                        i = tag.end;
                    }
                    else {
                        i = skipRawText(i, tag.end, tag.name);
                    }
                    continue;
                }
                if (BLOCK_SET.has(tag.name)) {
                    if (tag.selfClosing)
                        coreErr(i, `self-closing block ${tag.name}`);
                    stack.push({
                        tag: tag.name,
                        openStart: i,
                        openEnd: tag.end,
                        outer: stack.length === 0,
                        chunks: [],
                    });
                    i = tag.end;
                    continue;
                }
                // Ordinary non-block start tag: its descendant text still counts.
                i = tag.end;
                continue;
            }
            // A stray `<` that does not begin a comment, close or open tag is text.
            appendText("<");
            i++;
            continue;
        }
        if (c === "&" && stack.length > 0) {
            i = decodeReference(i);
            continue;
        }
        // Consume a literal run up to the next structural boundary.
        const runStart = i;
        while (i < n && fragment[i] !== "<" && !(fragment[i] === "&" && stack.length > 0))
            i++;
        if (i > runStart)
            appendText(fragment.slice(runStart, i));
    }
    if (stack.length > 0) {
        const frame = stack[stack.length - 1];
        coreErr(frame.openStart, `unclosed block ${frame.tag}`);
    }
    return results;
}
