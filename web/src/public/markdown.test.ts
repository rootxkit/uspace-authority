// The rules page's Markdown subset: what is rendered, and what never is
// (HTML, a script link). Each refusal beside the acceptance (E-01).
import { describe, expect, it } from "vitest";
import { parseInline, parseMarkdown, safeHref } from "./markdown";

describe("rules markdown", () => {
  it("headings, paragraphs and both lists", () => {
    const b = parseMarkdown("# Rules\n\nFly *below* **120 m**.\nKeep sight.\n\n- one\n- two\n\n1. first\n2. second\n");
    expect(b.map((x) => x.t)).toEqual(["h", "p", "ul", "ol"]);
    expect(b[1]).toEqual({
      t: "p",
      c: [
        { t: "text", v: "Fly " },
        { t: "em", c: [{ t: "text", v: "below" }] },
        { t: "text", v: " " },
        { t: "strong", c: [{ t: "text", v: "120 m" }] },
        { t: "text", v: ". Keep sight." },
      ],
    });
  });

  it("an https or site link is a link", () => {
    expect(parseInline("[map](https://example.test/a)")).toEqual([{ t: "link", href: "https://example.test/a", c: [{ t: "text", v: "map" }] }]);
    expect(safeHref("/en/check")).toBe("/en/check");
  });

  it("any other link is its text only, and HTML stays text (the pair above)", () => {
    expect(parseInline("[x](javascript:alert(1))")).toEqual([{ t: "text", v: "x" }, { t: "text", v: ")" }]);
    expect(safeHref("//evil.test/x")).toBeNull();
    expect(safeHref("data:text/html,x")).toBeNull();
    expect(parseMarkdown("<script>alert(1)</script>")).toEqual([{ t: "p", c: [{ t: "text", v: "<script>alert(1)</script>" }] }]);
  });
});
