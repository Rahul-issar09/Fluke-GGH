// "AI draft" answers from the local model only: the browser calls Ollama on this computer directly
// (it allows localhost pages by default). No cloud model, no API key, and the AEGIS backend is not involved.
// A draft is only shown, labelled "verify"; it is never saved as an answer and earns no points.
// Override with VITE_COMMUNITY_OLLAMA / VITE_COMMUNITY_AI_MODEL if needed.

export const OLLAMA_URL = (import.meta.env.VITE_COMMUNITY_OLLAMA || "http://127.0.0.1:11434").replace(/\/$/, "");
export const AI_MODEL = import.meta.env.VITE_COMMUNITY_AI_MODEL || "qwen2.5:7b";
const MAX_TOKENS = 450; // short drafts, so a scan using the same model never waits long

const SYSTEM = [
  "You are a helpful application-security mentor answering a question on a developer forum.",
  "Answer in Markdown, in at most about 250 words, with a short code example when it helps.",
  "Explain the defensive fix. Do not write working exploits or attack steps against systems the asker does not own.",
  "If you are not sure, say so plainly.",
].join(" ");

let running = false; // one draft at a time

/** @returns {Promise<string>} the draft in Markdown; rejects with a readable Error */
export async function draftAnswer(question, signal) {
  if (running) throw new Error("A draft is already being written. Wait for it to finish.");
  running = true;
  try {
    let resp;
    try {
      resp = await fetch(`${OLLAMA_URL}/api/chat`, {
        method: "POST",
        signal,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          model: AI_MODEL,
          stream: false,
          options: { num_predict: MAX_TOKENS, temperature: 0.2 },
          messages: [
            { role: "system", content: SYSTEM },
            { role: "user", content: `${question.title}\n\n${question.body}`.slice(0, 6000) },
          ],
        }),
      });
    } catch (err) {
      if (err?.name === "AbortError") throw err;
      throw new Error(`Local model unavailable: Ollama is not reachable at ${OLLAMA_URL}.`);
    }
    if (resp.status === 404) throw new Error(`Local model unavailable: ${AI_MODEL} is not installed (run: ollama pull ${AI_MODEL}).`);
    if (!resp.ok) throw new Error(`Local model unavailable (HTTP ${resp.status}).`);
    const data = await resp.json().catch(() => null);
    const text = String(data?.message?.content || "").trim();
    if (!text) throw new Error("The local model returned an empty draft.");
    return text;
  } finally {
    running = false;
  }
}
