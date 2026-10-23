// Renders the tree from markdown.js as React elements. React escapes every string, and links are
// already limited to http(s), so a post cannot inject markup or script.
import React from "react";
import { useCommunity } from "./context.js";
import { parseMarkdown, plainText } from "./markdown.js";

function Inline({ nodes }) {
  const { go } = useCommunity();
  return nodes.map((n, i) => {
    switch (n.t) {
      case "text": return <React.Fragment key={i}>{n.v}</React.Fragment>;
      case "code": return <code key={i} className="cm-icode">{n.v}</code>;
      case "b": return <strong key={i}><Inline nodes={n.c} /></strong>;
      case "i": return <em key={i}><Inline nodes={n.c} /></em>;
      case "br": return <br key={i} />;
      case "a": return <a key={i} href={n.href} target="_blank" rel="noopener noreferrer nofollow"><Inline nodes={n.c} /></a>;
      case "mention": return <button key={i} type="button" className="link cm-mention" onClick={() => go(`u/${n.name}`)}>@{n.name}</button>;
      default: return null;
    }
  });
}

export function Markdown({ text, className = "" }) {
  const blocks = React.useMemo(() => parseMarkdown(text), [text]);
  return (
    <div className={`cm-md ${className}`}>
      {blocks.map((b, i) => {
        if (b.t === "code") return <pre key={i} className="cm-pre">{b.lang && <span className="cm-lang">{b.lang}</span>}{b.text}</pre>;
        if (b.t === "h") { const H = `h${b.level + 2}`; return <H key={i}><Inline nodes={b.c} /></H>; }
        if (b.t === "ul") return <ul key={i}>{b.items.map((c, j) => <li key={j}><Inline nodes={c} /></li>)}</ul>;
        if (b.t === "ol") return <ol key={i}>{b.items.map((c, j) => <li key={j}><Inline nodes={c} /></li>)}</ol>;
        if (b.t === "quote") return <blockquote key={i}><Inline nodes={b.c} /></blockquote>;
        return <p key={i}><Inline nodes={b.c} /></p>;
      })}
    </div>
  );
}

export { plainText };
