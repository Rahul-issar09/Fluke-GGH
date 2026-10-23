// Feed: posts (text, images, Markdown articles, code, shared findings, reposts), likes, comments with one
// reply level, sharing (link, repost, image card), owner-only edit/delete, reports. Sort, filter and search.
import React from "react";
import { Badge, Loading, useLoad } from "../components/ui.jsx";
import * as cm from "./api.js";
import { useCommunity } from "./context.js";
import { Markdown, plainText } from "./Markdown.jsx";
import { copyText, download, postCard, postLink } from "./share.js";
import { CODE_LANGS } from "./types.js";
import {
  AuthorLine, CodeView, ErrorNote, FindingCard, FindingPicker, ImagePicker, LoadMore, ReportButton, Tags,
  parseTags, useAction, useDebounced,
} from "./widgets.jsx";

const TYPE_LABEL = { text: "Text", image: "Images", article: "Article", code: "Code", finding: "Finding", repost: "Repost" };
const COMPOSE_TYPES = ["text", "image", "article", "code", "finding"];

// "#community/post/p-1" -> rest ["post", "p-1"]
export default function Feed({ rest }) {
  if (rest[0] === "post" && rest[1]) return <PostDetail key={rest[1]} id={rest[1]} />;
  return <FeedList />;
}

function FeedList() {
  const { version } = useCommunity();
  const [sort, setSort] = React.useState("latest");
  const [type, setType] = React.useState("");
  const [tag, setTag] = React.useState("");
  const [q, setQ] = React.useState("");
  const query = useDebounced(q);
  const [items, setItems] = React.useState(null);
  const [cursor, setCursor] = React.useState(null);
  const [busy, setBusy] = React.useState(false);
  const [error, setError] = React.useState(null);
  const ticket = React.useRef(0);

  const load = React.useCallback(async (from) => {
    const mine = ++ticket.current;
    setBusy(true);
    setError(null);
    try {
      const r = await cm.listPosts({ sort, type, tag, q: query.trim(), cursor: from || undefined });
      if (mine !== ticket.current) return;
      setItems((old) => (from ? [...(old || []), ...r.items] : r.items));
      setCursor(r.nextCursor);
    } catch (err) {
      if (mine === ticket.current) setError(err);
    } finally {
      if (mine === ticket.current) setBusy(false);
    }
  }, [sort, type, tag, query]);

  React.useEffect(() => { load(null); }, [load, version]);

  const replace = (id, post) => setItems((list) => (post ? list.map((p) => (p.id === id ? post : p)) : list.filter((p) => p.id !== id)));
  const prepend = (post) => setItems((list) => [post, ...(list || [])]);

  return (
    <div className="cm-col">
      <Composer onPosted={prepend} />
      <div className="cm-filters">
        <select value={sort} onChange={(e) => setSort(e.target.value)} aria-label="Sort">
          <option value="latest">Latest</option>
          <option value="top">Top this week</option>
        </select>
        <select value={type} onChange={(e) => setType(e.target.value)} aria-label="Post type">
          <option value="">All post types</option>
          {Object.entries(TYPE_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
        </select>
        <input className="grow" value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search posts…" aria-label="Search posts" />
        {tag && <button type="button" className="cm-tag cm-tag-on" onClick={() => setTag("")} title="Clear tag filter">#{tag} ×</button>}
      </div>
      <ErrorNote error={error} />
      {items === null ? <Loading /> : items.length === 0 ? <div className="empty">No posts match.</div> : (
        items.map((p) => <PostCard key={p.id} post={p} onTag={setTag} onChange={(np) => replace(p.id, np)} onReposted={prepend} />)
      )}
      <LoadMore cursor={cursor} busy={busy} onMore={() => load(cursor)} />
    </div>
  );
}

function PostDetail({ id }) {
  const { go, version } = useCommunity();
  const { data, error, loading } = useLoad(() => cm.getPost(id), [id, version]);
  const [gone, setGone] = React.useState(false);
  return (
    <div className="cm-col">
      <div><button type="button" className="link" onClick={() => go("feed")}>← All posts</button></div>
      {loading && !data ? <Loading /> : error || gone ? (
        <div className="empty">{gone ? "The post was deleted." : error?.code === "NOT_FOUND" ? "This post does not exist any more." : error?.message}</div>
      ) : (
        <PostCard post={data} full onChange={(np) => (np ? null : setGone(true))} onReposted={(np) => go(`post/${np.id}`)} />
      )}
    </div>
  );
}

// ── composer ──────────────────────────────────────────────
function Composer({ onPosted }) {
  const { requireAuth } = useCommunity();
  const [open, setOpen] = React.useState(false);
  const [type, setType] = React.useState("text");
  const [title, setTitle] = React.useState("");
  const [body, setBody] = React.useState("");
  const [images, setImages] = React.useState([]);
  const [code, setCode] = React.useState({ lang: "python", source: "" });
  const [finding, setFinding] = React.useState(null);
  const [tags, setTags] = React.useState("");
  const [preview, setPreview] = React.useState(false);
  const act = useAction();

  if (!open) {
    return <button type="button" className="cm-compose-open" onClick={() => requireAuth(() => setOpen(true))}>Share something: a tip, a screenshot, an article, some code or a finding…</button>;
  }
  const reset = () => { setTitle(""); setBody(""); setImages([]); setCode({ lang: "python", source: "" }); setFinding(null); setTags(""); setPreview(false); act.setError(null); };
  const submit = (e) => {
    e.preventDefault();
    const input = { type, body, tags: parseTags(tags) };
    if (type === "article") Object.assign(input, { title, images });
    if (type === "image") input.images = images;
    if (type === "code") input.code = code;
    if (type === "finding") input.finding = finding;
    act.run(async () => {
      const post = await cm.createPost(input);
      reset();
      setOpen(false);
      onPosted(post);
    });
  };

  return (
    <form className="cm-card cm-composer" onSubmit={submit}>
      <div className="cm-seg" role="tablist" aria-label="Post type">
        {COMPOSE_TYPES.map((t) => (
          <button key={t} type="button" role="tab" aria-selected={type === t} className={type === t ? "cm-seg-on" : ""} onClick={() => { setType(t); setImages([]); act.setError(null); }}>{TYPE_LABEL[t]}</button>
        ))}
      </div>
      {type === "article" && <input value={title} onChange={(e) => setTitle(e.target.value)} placeholder="Article title" aria-label="Title" maxLength={150} />}
      {type === "code" && (
        <div className="row gap">
          <select value={code.lang} onChange={(e) => setCode({ ...code, lang: e.target.value })} aria-label="Language">{CODE_LANGS.map((l) => <option key={l}>{l}</option>)}</select>
        </div>
      )}
      {type === "code" && <textarea className="cm-codearea" rows={8} value={code.source} onChange={(e) => setCode({ ...code, source: e.target.value })} placeholder="Paste the code snippet" aria-label="Code" spellCheck={false} />}
      {type === "finding" && <FindingPicker value={finding} onChange={setFinding} />}
      {preview && type === "article" ? <div className="cm-preview"><Markdown text={body || "_Nothing to preview yet._"} /></div> : (
        <textarea rows={type === "article" ? 12 : 3} value={body} onChange={(e) => setBody(e.target.value)} aria-label="Text"
          placeholder={{ text: "What do you want to share? Markdown works: **bold**, `code`, lists.", image: "Say something about the images (optional)", article: "Write the article in Markdown: # headings, lists, ``` code blocks, [links](https://…)", code: "What does this code show? (optional)", finding: "What did you learn from it? (optional)" }[type]} />
      )}
      {(type === "image" || type === "article") && <ImagePicker images={images} onChange={setImages} max={type === "article" ? 1 : 4} />}
      <input value={tags} onChange={(e) => setTags(e.target.value)} placeholder="Tags, e.g. sqli, python (up to 5)" aria-label="Tags" />
      <ErrorNote error={act.error} />
      <div className="row gap wrap">
        <button className="primary" type="submit" disabled={act.busy}>{act.busy ? "Posting…" : "Post"}</button>
        {type === "article" && <button type="button" onClick={() => setPreview(!preview)}>{preview ? "Edit" : "Preview"}</button>}
        <button type="button" className="link" onClick={() => { reset(); setOpen(false); }}>Cancel</button>
        <span className="muted small">Posts are checked for API keys and tokens before they are saved.</span>
      </div>
    </form>
  );
}

// ── one post ──────────────────────────────────────────────
function PostCard({ post: initial, full = false, onChange, onReposted, onTag }) {
  const { user, requireAuth, go } = useCommunity();
  const [post, setPost] = React.useState(initial);
  const [editing, setEditing] = React.useState(false);
  const [showComments, setShowComments] = React.useState(full);
  const act = useAction();
  React.useEffect(() => setPost(initial), [initial]);

  const mine = user && user.id === post.author.id;
  const update = (p) => { setPost(p); onChange?.(p); };
  const like = () => requireAuth(() => act.run(async () => {
    const r = await cm.toggleLike(post.id);
    update({ ...post, likedByMe: r.liked, likeCount: r.likeCount });
  }));
  const remove = () => {
    if (!window.confirm("Delete this post and its comments?")) return;
    act.run(async () => { await cm.deletePost(post.id); onChange?.(null); });
  };

  return (
    <article className="cm-card cm-post">
      <div className="row between gap">
        <AuthorLine user={post.author} at={post.createdAt}>{post.editedAt ? " · edited" : ""}</AuthorLine>
        <Badge kind="muted">{TYPE_LABEL[post.type] || post.type}</Badge>
      </div>
      {editing ? (
        <PostEditor post={post} onSaved={(p) => { update(p); setEditing(false); }} onCancel={() => setEditing(false)} />
      ) : (
        <PostBody post={post} full={full} />
      )}
      <Tags tags={post.tags} onTag={onTag} />
      <div className="cm-actions">
        <button type="button" className={post.likedByMe ? "cm-liked" : ""} aria-pressed={post.likedByMe} onClick={like}>♥ {post.likeCount}</button>
        <button type="button" onClick={() => setShowComments(!showComments)} aria-expanded={showComments}>💬 {post.commentCount}</button>
        <ShareMenu post={post} onReposted={onReposted} />
        {!full && <button type="button" className="link small" onClick={() => go(`post/${post.id}`)}>Open</button>}
        <span className="grow" />
        {mine && !editing && <button type="button" className="link small" onClick={() => setEditing(true)}>Edit</button>}
        {mine && <button type="button" className="link small" onClick={remove}>Delete</button>}
        {!mine && <ReportButton kind="post" id={post.id} />}
      </div>
      <ErrorNote error={act.error} />
      {showComments && <Comments postId={post.id} onCount={(n) => n !== post.commentCount && update({ ...post, commentCount: n })} />}
    </article>
  );
}

function PostBody({ post, full }) {
  const { go } = useCommunity();
  if (post.type === "repost") {
    const o = post.repostOf;
    return (
      <div className="cm-body">
        {post.body?.trim() && <Markdown text={post.body} />}
        {o ? (
          <button type="button" className="cm-quoted" onClick={() => go(`post/${o.id}`)}>
            <span className="small muted">Reposted from <strong>{o.author.name}</strong></span>
            {o.title && <strong>{o.title}</strong>}
            <span>{o.type === "finding" ? o.finding?.summary : o.type === "code" ? `${o.code?.lang} snippet` : plainText(o.body, 220)}</span>
          </button>
        ) : <div className="muted small cm-quoted">The original post was removed.</div>}
      </div>
    );
  }
  return (
    <div className="cm-body">
      {post.type === "article" && (full ? <h3 className="cm-post-title">{post.title}</h3> : <button type="button" className="link cm-post-title" onClick={() => go(`post/${post.id}`)}>{post.title}</button>)}
      {post.type === "finding" && <FindingCard finding={post.finding} />}
      {post.type === "article" && !full ? (
        <>
          {post.images?.[0] && <img className="cm-cover" src={post.images[0]} alt="" />}
          <p className="cm-excerpt">{plainText(post.body, 280)}</p>
          <button type="button" className="link" onClick={() => go(`post/${post.id}`)}>Read the article</button>
        </>
      ) : (
        <>
          {post.type === "article" && post.images?.[0] && <img className="cm-cover" src={post.images[0]} alt="" />}
          {post.body?.trim() && <Markdown text={post.body} />}
        </>
      )}
      {post.type === "image" && (
        <div className={`cm-gallery cm-gallery-${Math.min(post.images.length, 4)}`}>
          {post.images.map((src, i) => <img key={i} src={src} alt={`image ${i + 1} of ${post.images.length}`} loading="lazy" />)}
        </div>
      )}
      {post.type === "code" && post.code && <CodeView code={post.code} />}
    </div>
  );
}

function PostEditor({ post, onSaved, onCancel }) {
  const [title, setTitle] = React.useState(post.title || "");
  const [body, setBody] = React.useState(post.body || "");
  const [source, setSource] = React.useState(post.code?.source || "");
  const [tags, setTags] = React.useState((post.tags || []).join(", "));
  const act = useAction();
  const save = (e) => {
    e.preventDefault();
    const input = { body, tags: parseTags(tags) };
    if (post.type === "article") input.title = title;
    if (post.type === "code") input.code = { lang: post.code.lang, source };
    act.run(async () => onSaved(await cm.updatePost(post.id, input)));
  };
  return (
    <form className="cm-editor" onSubmit={save}>
      {post.type === "article" && <input value={title} onChange={(e) => setTitle(e.target.value)} aria-label="Title" />}
      {post.type === "code" && <textarea className="cm-codearea" rows={8} value={source} onChange={(e) => setSource(e.target.value)} aria-label="Code" spellCheck={false} />}
      <textarea rows={post.type === "article" ? 12 : 4} value={body} onChange={(e) => setBody(e.target.value)} aria-label="Text" />
      <input value={tags} onChange={(e) => setTags(e.target.value)} aria-label="Tags" />
      <ErrorNote error={act.error} />
      <div className="row gap">
        <button className="primary" type="submit" disabled={act.busy}>Save</button>
        <button type="button" onClick={onCancel}>Cancel</button>
      </div>
    </form>
  );
}

// ── sharing ───────────────────────────────────────────────
function ShareMenu({ post, onReposted }) {
  const { requireAuth } = useCommunity();
  const [open, setOpen] = React.useState(false);
  const [msg, setMsg] = React.useState("");
  const [reposting, setReposting] = React.useState(false);
  const [comment, setComment] = React.useState("");
  const act = useAction();
  const link = postLink(post.id);

  const copy = async () => setMsg((await copyText(link)) ? "Link copied." : `Copy this link: ${link}`);
  const card = () => act.run(async () => { download(await postCard(post), `aegis-community-${post.id}.png`); setMsg("Image card downloaded."); });
  const repost = () => act.run(async () => {
    const np = await cm.sharePost(post.id, comment);
    setReposting(false);
    setComment("");
    setMsg("Reposted to the feed.");
    onReposted?.(np);
  });

  return (
    <span className="cm-share">
      <button type="button" aria-expanded={open} onClick={() => { setOpen(!open); setMsg(""); }}>↗ Share</button>
      {open && (
        <span className="cm-share-box">
          <button type="button" onClick={copy}>Copy link</button>
          <button type="button" onClick={() => requireAuth(() => setReposting(true))}>Repost</button>
          <button type="button" onClick={card} disabled={act.busy}>Image card</button>
          {reposting && (
            <span className="cm-repost">
              <input value={comment} onChange={(e) => setComment(e.target.value)} placeholder="Add a comment (optional)" aria-label="Repost comment" />
              <button type="button" className="primary" onClick={repost} disabled={act.busy}>Repost</button>
            </span>
          )}
          {msg && <span className="small muted cm-share-msg">{msg}</span>}
          <ErrorNote error={act.error} />
        </span>
      )}
    </span>
  );
}

// ── comments (one reply level) ────────────────────────────
function Comments({ postId, onCount }) {
  const { user, version } = useCommunity();
  const { data, error, reload } = useLoad(() => cm.listComments(postId), [postId, version]);
  const [replyTo, setReplyTo] = React.useState(null);
  const act = useAction();
  React.useEffect(() => { if (data) onCount?.(data.length); }, [data]); // eslint-disable-line react-hooks/exhaustive-deps

  if (error) return <ErrorNote error={error} />;
  if (!data) return <Loading />;
  const top = data.filter((c) => !c.parentId);
  const replies = (id) => data.filter((c) => c.parentId === id);
  const remove = (id) => window.confirm("Delete this comment?") && act.run(async () => { await cm.deleteComment(id); reload(); });

  const one = (c, isReply) => (
    <div key={c.id} className={isReply ? "cm-comment cm-reply" : "cm-comment"}>
      <AuthorLine user={c.author} at={c.createdAt} />
      <Markdown text={c.body} />
      <div className="cm-actions cm-actions-sm">
        {!isReply && <button type="button" className="link small" onClick={() => setReplyTo(replyTo === c.id ? null : c.id)}>Reply</button>}
        {user?.id === c.author.id ? <button type="button" className="link small" onClick={() => remove(c.id)}>Delete</button> : <ReportButton kind="comment" id={c.id} />}
      </div>
      {!isReply && replies(c.id).map((r) => one(r, true))}
      {!isReply && replyTo === c.id && <CommentForm postId={postId} parentId={c.id} onDone={() => { setReplyTo(null); reload(); }} />}
    </div>
  );

  return (
    <div className="cm-comments">
      {top.length === 0 && <div className="muted small">No comments yet.</div>}
      {top.map((c) => one(c, false))}
      <ErrorNote error={act.error} />
      <CommentForm postId={postId} onDone={reload} />
    </div>
  );
}

function CommentForm({ postId, parentId, onDone }) {
  const { requireAuth } = useCommunity();
  const [body, setBody] = React.useState("");
  const act = useAction();
  const send = (e) => {
    e.preventDefault();
    requireAuth(() => act.run(async () => { await cm.addComment(postId, body, parentId); setBody(""); onDone(); }));
  };
  return (
    <form className="cm-comment-form" onSubmit={send}>
      <input value={body} onChange={(e) => setBody(e.target.value)} placeholder={parentId ? "Write a reply…" : "Write a comment…"} aria-label={parentId ? "Reply" : "Comment"} maxLength={2000} />
      <button type="submit" disabled={act.busy || !body.trim()}>{parentId ? "Reply" : "Comment"}</button>
      <ErrorNote error={act.error} />
    </form>
  );
}
