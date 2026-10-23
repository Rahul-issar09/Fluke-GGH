// Learning progress, kept in this browser only: { quiz, challenges, checklist }.
//   quiz        best score per quiz category, in percent: { A01: 86 }
//   challenges  completed practice challenges: { "sqli-py": true }
//   checklist   ticked crypto-migration steps: { inventory: true }
// Keys this version does not know are kept as they are, so nothing saved earlier is lost.

const KEY = "aegis.learn.v1";
const EMPTY = { quiz: {}, challenges: {}, checklist: {} };

export function loadProgress() {
  try {
    const saved = JSON.parse(localStorage.getItem(KEY) || "null");
    if (!saved || typeof saved !== "object") return { ...EMPTY };
    return { ...saved, quiz: saved.quiz || {}, challenges: saved.challenges || {}, checklist: saved.checklist || {} };
  } catch {
    return { ...EMPTY }; // private mode, or the stored value is not JSON
  }
}

export function saveProgress(change) {
  const next = { ...loadProgress(), ...change };
  try {
    localStorage.setItem(KEY, JSON.stringify(next));
  } catch {
    /* private mode: progress just isn't remembered */
  }
  return next;
}
