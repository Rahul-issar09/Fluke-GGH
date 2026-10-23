// A small Markdown reader for posts, questions and answers. It turns text into a plain tree of nodes;
// Markdown.jsx renders that tree as React elements, so nothing a user writes is ever parsed as HTML.
// Supported: # headings (1-3), paragraphs, line breaks, - and 1. lists, > quotes, ``` code blocks,
// `code`, **bold**, *italic* / _italic_, [text](https://...), bare https:// links and @mentions.
// Links are kept only for http(s); anything else (javascript:, data:, ...) stays as plain text.

/** @returns {string|null} the URL when it is a safe http(s) link, otherwise null */
export function safeHref(url) {
  try {
    const u = new URL(String(url));
    return u.protocol === "https:" || u.protocol === "http:" ? u.toString() : null;
  } catch {
    return null;
  }
}

const INLINE = new RegExp(
  [
    "(`[^`\\n]+`)", // 1 code
    "\\[([^\\]\\n]{1,200})\\]\\(([^)\\s]{1,2000})\\)", // 2 text, 3 url
    "\\*\\*([^*\\n]+?)\\*\\*", // 4 bold
    "(?<![\\w*])\\*([^*\\n]+?)\\*(?![\\w*])", // 5 italic *
    "(?<![\\w_])_([^_\\n]+?)_(?![\\w_])", // 6 italic _
    "(?<![\\w@/])@([a-z0-9_]{3,24})\\b", // 7 mention
    "(https?:\\/\\/[^\\s<>()]*[^\\s<>().,;:!?'\"])", // 8 bare link
    "(\\n)", // 9 line break
  ].join("|"),
  "g",
);

/** Inline text -> nodes: {t:"text",v} {t:"code",v} {t:"b",c} {t:"i",c} {t:"a",href,c} {t:"mention",name} {t:"br"} */
export function parseInline(text) {
  const out = [];
  const src = String(text ?? "");
  let last = 0;
  const push = (node) => {
    if (node.t === "text" && out.length && out[out.length - 1].t === "text") out[out.length - 1].v += node.v;
    else out.push(node);
  };
  for (const m of src.matchAll(INLINE)) {
    if (m.index > last) push({ t: "text", v: src.slice(last, m.index) });
    last = m.index + m[0].length;
    if (m[1]) push({ t: "code", v: m[1].slice(1, -1) });
    else if (m[2] !== undefined) {
      const href = safeHref(m[3]);
      if (href) push({ t: "a", href, c: [{ t: "text", v: m[2] }] });
      else push({ t: "text", v: m[0] });
    } else if (m[4] !== undefined) push({ t: "b", c: parseInline(m[4]) });
    else if (m[5] !== undefined) push({ t: "i", c: parseInline(m[5]) });
    else if (m[6] !== undefined) push({ t: "i", c: parseInline(m[6]) });
    else if (m[7] !== undefined) push({ t: "mention", name: m[7] });
    else if (m[8] !== undefined) {
      const href = safeHref(m[8]);
      push(href ? { t: "a", href, c: [{ t: "text", v: m[8] }] } : { t: "text", v: m[8] });
    } else if (m[9] !== undefined) push({ t: "br" });
  }
  if (last < src.length) push({ t: "text", v: src.slice(last) });
  return out;
}

const FENCE = /^\s*```\s*([\w+-]*)\s*$/;
const HEADING = /^(#{1,3})\s+(.*)$/;
const UL = /^\s*[-*+]\s+(.*)$/;
const OL = /^\s*\d{1,3}[.)]\s+(.*)$/;
const QUOTE = /^\s*>\s?(.*)$/;
const startsBlock = (line) => FENCE.test(line) || HEADING.test(line) || UL.test(line) || OL.test(line) || QUOTE.test(line);

/** Markdown -> blocks: {t:"code",lang,text} {t:"h",level,c} {t:"ul"|"ol",items:[c]} {t:"quote",c} {t:"p",c} */
export function parseMarkdown(text) {
  const lines = String(text ?? "").replace(/\r\n?/g, "\n").split("\n");
  const blocks = [];
  let i = 0;
  while (i < lines.length) {
    const line = lines[i];
    if (!line.trim()) { i++; continue; }
    let m;
    if ((m = line.match(FENCE))) {
      const body = [];
      i++;
      while (i < lines.length && !/^\s*```\s*$/.test(lines[i])) body.push(lines[i++]);
      i++; // the closing fence (or the end)
      blocks.push({ t: "code", lang: m[1] || "", text: body.join("\n") });
    } else if ((m = line.match(HEADING))) {
      blocks.push({ t: "h", level: m[1].length, c: parseInline(m[2]) });
      i++;
    } else if (UL.test(line) || OL.test(line)) {
      const re = UL.test(line) ? UL : OL;
      const items = [];
      while (i < lines.length && re.test(lines[i])) items.push(parseInline(lines[i++].match(re)[1]));
      blocks.push({ t: re === UL ? "ul" : "ol", items });
    } else if (QUOTE.test(line)) {
      const body = [];
      while (i < lines.length && QUOTE.test(lines[i])) body.push(lines[i++].match(QUOTE)[1]);
      blocks.push({ t: "quote", c: parseInline(body.join("\n")) });
    } else {
      const body = [];
      while (i < lines.length && lines[i].trim() && (body.length === 0 || !startsBlock(lines[i]))) body.push(lines[i++]);
      blocks.push({ t: "p", c: parseInline(body.join("\n")) });
    }
  }
  return blocks;
}

/** Markdown -> plain one-paragraph text, for excerpts and the share image. */
export function plainText(text, max = Infinity) {
  const flat = (nodes) => nodes.map((n) => (n.t === "text" || n.t === "code" ? n.v : n.t === "mention" ? `@${n.name}` : n.t === "br" ? " " : flat(n.c || []))).join("");
  const out = parseMarkdown(text)
    .map((b) => (b.t === "code" ? b.text : b.t === "ul" || b.t === "ol" ? b.items.map(flat).join("; ") : flat(b.c)))
    .join(" ")
    .replace(/\s+/g, " ")
    .trim();
  return out.length > max ? `${out.slice(0, max - 1).trimEnd()}…` : out;
}
