/*!
 * Antirea — anti reverse-engineering toolkit.
 * @author Diamond Rubinny
 * @license Apache-2.0
 * Copyright (c) 2026 Diamond Rubinny. All rights reserved.
 * Credit required: keep this notice (Apache-2.0 §4) in all copies and derivatives.
 */
/**
 * Embed and recover a per-viewer watermark token in served text/code.
 *
 * Two modes:
 *  - "comment": a bang comment of the form "slash-star-bang wm:<token>
 *    star-slash" — robust in code; survives
 *    minifiers that keep legal (`/*!`) comments, but a minifier set to strip all
 *    comments will remove it.
 *  - "zerowidth": the token is encoded in invisible zero-width characters inside
 *    the text. Survives copy-paste of the visible content and most minifiers
 *    (it lives inside a string/text), and is far stealthier.
 *
 * LIMITATIONS (honest): a watermark identifies a leaked COPY; it does not
 * prevent copying, and an attacker who knows the scheme can strip it (normalize
 * whitespace / strip comments). Use several carriers and keep the scheme
 * private for better odds. Tokens must be unique per recipient to trace them.
 */
export type WatermarkMode = "comment" | "zerowidth";

const ZERO = "​"; // zero-width space  -> bit 0
const ONE = "‌"; // zero-width non-joiner -> bit 1
const START = "⁠"; // word joiner (frame)
const END = "⁣"; // invisible separator (frame)

const COMMENT_RE = /\/\*!wm:([A-Za-z0-9_-]{4,128})\*\//g;
const ZW_RE = new RegExp(`${START}([${ZERO}${ONE}]+)${END}`, "g");

/** Insert a watermark token into `text`. Returns the watermarked text. */
export function embed(text: string, token: string, mode: WatermarkMode = "zerowidth"): string {
  if (!/^[A-Za-z0-9_-]{4,128}$/.test(token)) throw new Error("watermark token must be [A-Za-z0-9_-]{4,128}");
  if (mode === "comment") {
    return `${text}\n/*!wm:${token}*/\n`;
  }
  // zero-width: encode each char's low byte as 8 bits.
  let bits = "";
  for (let i = 0; i < token.length; i++) {
    const code = token.charCodeAt(i) & 0xff;
    bits += code.toString(2).padStart(8, "0");
  }
  const zw = START + [...bits].map((b) => (b === "1" ? ONE : ZERO)).join("") + END;
  // Insert after the first whitespace run if present, else append.
  const m = /\s/.exec(text);
  if (m) return text.slice(0, m.index + 1) + zw + text.slice(m.index + 1);
  return text + zw;
}

/** Recover every watermark token found in `text` (both modes). */
export function recover(text: string): string[] {
  const out = new Set<string>();
  for (const m of text.matchAll(COMMENT_RE)) out.add(m[1]);
  for (const m of text.matchAll(ZW_RE)) {
    const bits = [...m[1]].map((ch) => (ch === ONE ? "1" : "0")).join("");
    let token = "";
    for (let i = 0; i + 8 <= bits.length; i += 8) {
      token += String.fromCharCode(parseInt(bits.slice(i, i + 8), 2));
    }
    if (/^[A-Za-z0-9_-]{4,128}$/.test(token)) out.add(token);
  }
  return [...out];
}

/** Strip any zero-width watermark framing (e.g. before re-watermarking). */
export function stripZeroWidth(text: string): string {
  return text.replace(ZW_RE, "");
}
