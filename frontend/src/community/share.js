// Sharing a post: a link to it, or an image card drawn in the browser (no network call).
import { plainText } from "./markdown.js";

export const postLink = (id) => `${location.origin}${location.pathname}#community/post/${encodeURIComponent(id)}`;

/** @returns {Promise<boolean>} true when the text reached the clipboard */
export async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}

function wrap(ctx, text, width, maxLines) {
  const words = text.split(" ");
  const lines = [];
  let line = "";
  for (const w of words) {
    const next = line ? `${line} ${w}` : w;
    if (ctx.measureText(next).width > width && line) {
      lines.push(line);
      line = w;
      if (lines.length === maxLines) break;
    } else line = next;
  }
  if (lines.length < maxLines && line) lines.push(line);
  else if (lines.length === maxLines) lines[maxLines - 1] = `${lines[maxLines - 1].replace(/\s*\S*$/, "")} …`;
  return lines;
}

/** Draws the post as a 1200x630 PNG. @returns {Promise<Blob>} */
export function postCard(post) {
  const W = 1200, H = 630, PAD = 72;
  const canvas = document.createElement("canvas");
  canvas.width = W;
  canvas.height = H;
  const ctx = canvas.getContext("2d");
  const grad = ctx.createLinearGradient(0, 0, W, H);
  grad.addColorStop(0, "#0f172a");
  grad.addColorStop(1, "#1e3a8a");
  ctx.fillStyle = grad;
  ctx.fillRect(0, 0, W, H);

  const font = (w, s) => `${w} ${s}px Inter, system-ui, sans-serif`;
  ctx.fillStyle = "#93c5fd";
  ctx.font = font(700, 28);
  ctx.fillText("AEGIS community", PAD, PAD + 10);

  const shown = post.type === "repost" && post.repostOf ? post.repostOf : post;
  const title = shown.title || (shown.type === "finding" ? `${shown.finding?.owasp || ""} finding · ${shown.finding?.category || ""}` : "");
  const body = shown.type === "code" ? shown.code?.source || "" : shown.type === "finding" ? shown.finding?.summary || "" : plainText(shown.body);
  let y = PAD + 90;
  ctx.fillStyle = "#ffffff";
  if (title) {
    ctx.font = font(700, 46);
    for (const l of wrap(ctx, title, W - 2 * PAD, 2)) { ctx.fillText(l, PAD, y); y += 58; }
    y += 10;
  }
  ctx.fillStyle = "#e2e8f0";
  ctx.font = shown.type === "code" ? "400 26px ui-monospace, Consolas, monospace" : font(400, 30);
  const lines = shown.type === "code" ? body.split("\n").slice(0, 7).map((l) => (l.length > 60 ? `${l.slice(0, 59)}…` : l)) : wrap(ctx, body.replace(/\s+/g, " "), W - 2 * PAD, title ? 5 : 7);
  for (const l of lines) { ctx.fillText(l, PAD, y); y += 42; }

  ctx.fillStyle = "#93c5fd";
  ctx.font = font(600, 26);
  ctx.fillText(`@${shown.author?.name || "unknown"}`, PAD, H - PAD);
  ctx.textAlign = "right";
  ctx.fillText((shown.tags || []).slice(0, 4).map((t) => `#${t}`).join("  "), W - PAD, H - PAD);
  return new Promise((resolve, reject) => canvas.toBlob((b) => (b ? resolve(b) : reject(new Error("Could not draw the image."))), "image/png"));
}

export function download(blob, name) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
