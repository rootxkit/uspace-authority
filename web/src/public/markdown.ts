// The rules page's Markdown (WEB_RULES_FILE_KA, WEB_RULES_FILE_EN): a
// small, safe subset parsed into a tree the page renders as React
// elements. No HTML is passed through and nothing is set as HTML: a tag
// in the text is shown as text. Links go to http(s) addresses or to a
// path on this site only; any other link is its text.
//
// Blocks: "#", "##", "###" headings; "- " or "* " list items; "1. " list
// items; paragraphs separated by a blank line. Inline: **strong**,
// *emphasis*, `code`, [text](url).

export type Inline =
  | { t: "text"; v: string }
  | { t: "strong"; c: Inline[] }
  | { t: "em"; c: Inline[] }
  | { t: "code"; v: string }
  | { t: "link"; href: string; c: Inline[] };

export type Block = { t: "h"; level: 1 | 2 | 3; c: Inline[] } | { t: "p"; c: Inline[] } | { t: "ul"; items: Inline[][] } | { t: "ol"; items: Inline[][] };

/** A link target the page may render as a link. */
export function safeHref(href: string): string | null {
  const h = href.trim();
  if (/^https?:\/\/[^\s]+$/i.test(h)) return h;
  if (/^\/(?!\/)[^\s]*$/.test(h)) return h;
  return null;
}

export function parseInline(s: string): Inline[] {
  const out: Inline[] = [];
  let text = "";
  const flush = () => {
    if (text !== "") out.push({ t: "text", v: text });
    text = "";
  };
  let i = 0;
  while (i < s.length) {
    const rest = s.slice(i);
    let m: RegExpMatchArray | null;
    if ((m = /^\*\*(.+?)\*\*/.exec(rest)) !== null) {
      flush();
      out.push({ t: "strong", c: parseInline(m[1] ?? "") });
      i += m[0].length;
    } else if ((m = /^\*([^*\s][^*]*?)\*/.exec(rest)) !== null) {
      flush();
      out.push({ t: "em", c: parseInline(m[1] ?? "") });
      i += m[0].length;
    } else if ((m = /^`([^`]+)`/.exec(rest)) !== null) {
      flush();
      out.push({ t: "code", v: m[1] ?? "" });
      i += m[0].length;
    } else if ((m = /^\[([^\]]+)\]\(([^)\s]+)\)/.exec(rest)) !== null) {
      flush();
      const href = safeHref(m[2] ?? "");
      const label = parseInline(m[1] ?? "");
      if (href === null) out.push(...label);
      else out.push({ t: "link", href, c: label });
      i += m[0].length;
    } else {
      text += s[i];
      i++;
    }
  }
  flush();
  return out;
}

export function parseMarkdown(src: string): Block[] {
  const blocks: Block[] = [];
  let para: string[] = [];
  let list: { t: "ul" | "ol"; items: Inline[][] } | null = null;
  const endPara = () => {
    if (para.length > 0) blocks.push({ t: "p", c: parseInline(para.join(" ")) });
    para = [];
  };
  const endList = () => {
    if (list !== null) blocks.push(list);
    list = null;
  };
  for (const raw of src.replace(/\r\n?/g, "\n").split("\n")) {
    const line = raw.trimEnd();
    if (line.trim() === "") {
      endPara();
      endList();
      continue;
    }
    const h = /^(#{1,3})\s+(.*)$/.exec(line);
    if (h !== null) {
      endPara();
      endList();
      blocks.push({ t: "h", level: (h[1] ?? "#").length as 1 | 2 | 3, c: parseInline(h[2] ?? "") });
      continue;
    }
    const ul = /^\s*[-*]\s+(.*)$/.exec(line);
    const ol = /^\s*\d+[.)]\s+(.*)$/.exec(line);
    const item = ul ?? ol;
    if (item !== null) {
      endPara();
      const kind = ul !== null ? "ul" : "ol";
      if (list === null || list.t !== kind) {
        endList();
        list = { t: kind, items: [] };
      }
      list.items.push(parseInline(item[1] ?? ""));
      continue;
    }
    endList();
    para.push(line.trim());
  }
  endPara();
  endList();
  return blocks;
}
