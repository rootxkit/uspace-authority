// CLAUDE.md rule 12: every display string goes through the ka/en
// catalogues. A JSX text node with a letter in it, or a string literal
// given to an attribute a person reads (aria-label, title, alt,
// placeholder, label), is a display string outside the catalogue.
// Punctuation, numbers and an empty alt pass; so does anything in braces
// that is not a plain string literal (a `t(...)` call).
const LETTER = /\p{L}/u;
const LABEL_ATTRS = new Set(["aria-label", "aria-description", "aria-valuetext", "title", "alt", "placeholder", "label"]);

/** @type {import("eslint").Rule.RuleModule} */
export default {
  meta: {
    type: "problem",
    docs: { description: "Display strings come from the ka/en catalogues, never from JSX literals (CLAUDE.md rule 12)." },
    schema: [],
    messages: {
      text: "Display text '{{text}}' outside the catalogue: put it in src/i18n/en.json and ka.json and render t(key).",
      attr: "'{{name}}' is read by a person: '{{text}}' belongs in the catalogue (t(key)).",
    },
  },
  create(context) {
    const literalOf = (value) => {
      if (value === null || value === undefined) return null;
      if (value.type === "Literal" && typeof value.value === "string") return value.value;
      if (value.type === "JSXExpressionContainer") {
        const e = value.expression;
        if (e.type === "Literal" && typeof e.value === "string") return e.value;
        if (e.type === "TemplateLiteral" && e.expressions.length === 0) return e.quasis.map((q) => q.value.cooked ?? "").join("");
      }
      return null;
    };
    return {
      JSXText(node) {
        if (LETTER.test(node.value)) context.report({ node, messageId: "text", data: { text: node.value.trim().slice(0, 40) } });
      },
      JSXExpressionContainer(node) {
        // {"text"} as a child is a text node in braces.
        if (node.parent?.type !== "JSXElement" && node.parent?.type !== "JSXFragment") return;
        const text = literalOf(node);
        if (text !== null && LETTER.test(text)) context.report({ node, messageId: "text", data: { text: text.slice(0, 40) } });
      },
      JSXAttribute(node) {
        const name = node.name.type === "JSXIdentifier" ? node.name.name : null;
        if (name === null || !LABEL_ATTRS.has(name)) return;
        const text = literalOf(node.value);
        if (text !== null && LETTER.test(text)) context.report({ node, messageId: "attr", data: { name, text: text.slice(0, 40) } });
      },
    };
  },
};
