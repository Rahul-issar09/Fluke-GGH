// Image rules for uploads: png, jpeg and webp only, judged by the file's first bytes (not its name or
// its claimed type), at most 5 MB each and 4 per post. SVG is never accepted (it can carry script).

export const MAX_IMAGE_BYTES = 5 * 1024 * 1024;
export const MAX_IMAGES = 4;

/** @param {Uint8Array} b @returns {"png"|"jpeg"|"webp"|null} */
export function sniffImage(b) {
  if (b.length >= 8 && b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4e && b[3] === 0x47 && b[4] === 0x0d && b[5] === 0x0a && b[6] === 0x1a && b[7] === 0x0a) return "png";
  if (b.length >= 3 && b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) return "jpeg";
  const tag = (from, s) => [...s].every((c, i) => b[from + i] === c.charCodeAt(0));
  if (b.length >= 12 && tag(0, "RIFF") && tag(8, "WEBP")) return "webp";
  return null;
}

/** Throws an Error with a user-readable message when the bytes are not an acceptable image. */
export function checkImageBytes(bytes, name = "image") {
  if (bytes.length > MAX_IMAGE_BYTES) throw new Error(`${name}: larger than 5 MB`);
  if (!sniffImage(bytes)) throw new Error(`${name}: not a PNG, JPEG or WebP image`);
}

/** Validates a File chosen in the browser; resolves to a data URL, rejects with a readable message. */
export async function readImageFile(file) {
  if (file.size > MAX_IMAGE_BYTES) throw new Error(`${file.name}: larger than 5 MB`);
  const bytes = new Uint8Array(await file.arrayBuffer());
  checkImageBytes(bytes, file.name);
  const mime = { png: "image/png", jpeg: "image/jpeg", webp: "image/webp" }[sniffImage(bytes)];
  let binary = "";
  for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return `data:${mime};base64,${btoa(binary)}`;
}

/** Re-checks a stored or submitted image reference: data URLs are decoded and sniffed, same-origin paths pass. */
export function checkImageRef(ref) {
  if (typeof ref !== "string") throw new Error("image: invalid");
  if (ref.startsWith("/community/img/")) return; // the bundled demo images
  const m = ref.match(/^data:(image\/(?:png|jpeg|webp));base64,([A-Za-z0-9+/=]+)$/);
  if (!m) throw new Error("image: only PNG, JPEG or WebP data is accepted");
  const bin = atob(m[2]);
  const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
  checkImageBytes(bytes);
  const kind = sniffImage(bytes);
  if (`image/${kind}` !== m[1]) throw new Error("image: its contents do not match its declared type");
}
