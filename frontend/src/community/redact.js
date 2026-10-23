// Turns a finding from your own scan into something safe to share: only its id, scan, category, OWASP
// code, state and a one-line summary. Evidence, payloads, code and request data are never copied.
// In the summary, file paths become just the file name and hosts / IPs / URLs become <target>.
// The secret guard still runs on the result when it is posted.

const URL_RE = /\b[a-z][a-z0-9+.-]*:\/\/[^\s'"<>]+/gi;
const IP_RE = /\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b/g;
const LOCALHOST_RE = /\blocalhost(?::\d{1,5})?\b/gi;
const WIN_PATH_RE = /\b[A-Za-z]:[\\/][^\s'"<>,;)]*/g;
const UNC_RE = /\\\\[^\s'"<>,;)]+/g;
const ROOT_PATH_RE = /(?<![\w.])\/(?:home|Users|usr|var|etc|opt|tmp|srv|root|mnt|private|Volumes|workspace|app|data)\/[^\s'"<>,;)]*/g;
const REL_FILE_RE = /\b(?:[\w.-]+[\\/])+([\w.-]+\.\w{1,8})\b/g;

/** the last part of a path: "C:\\x\\app\\auth.py" -> "auth.py" */
export const basename = (path) => String(path || "").split(/[\\/]/).filter(Boolean).pop() || "";

/** Hides hosts and shortens paths in free text. */
export function redactText(text) {
  return String(text || "")
    .replace(URL_RE, "<target>")
    .replace(UNC_RE, (p) => basename(p))
    .replace(WIN_PATH_RE, (p) => basename(p))
    .replace(ROOT_PATH_RE, (p) => basename(p))
    .replace(REL_FILE_RE, (_, name) => name)
    .replace(IP_RE, "<target>")
    .replace(LOCALHOST_RE, "<target>")
    .replace(/\s+/g, " ")
    .trim();
}

/** A finding from the AEGIS API -> the FindingRef shape in types.js */
export function redactFinding(finding, scanId) {
  const where = finding.file ? ` (in ${basename(finding.file)}${finding.line ? `:${finding.line}` : ""})` : "";
  let summary = redactText(`${finding.title || finding.type || "Finding"}${where}`);
  if (summary.length > 300) summary = `${summary.slice(0, 299)}…`;
  return {
    id: String(finding.id),
    ...(scanId ? { scanId: String(scanId) } : {}),
    category: String(finding.type || finding.category || "finding"),
    owasp: String(finding.owasp || ""),
    state: String(finding.state || "candidate"),
    summary,
  };
}
