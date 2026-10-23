"""Scope gate (RAG15) — answer only questions that are about this scan's findings.

The chatbot is a findings assistant, not a general one: "what is k8s?" or "why does the kubernetes
ingress get exposed?" (when no finding mentions it) must get ``"No finding matches."`` rather than
an answer stitched from whatever was closest. Embedding similarity cannot make that call (unrelated
chunks still score ~0.6), and a 7B model does not reliably refuse, so the decision is deterministic
and lexical: the question's *distinctive* words must appear in the scan's own findings.

Question filler ("why", "is", "the") and words that only describe the *kind* of question ("risk",
"fix", "finding", "summarize", "critical") are ignored, so "what should I fix first?" is in scope.
What is left are the subject words ("kubernetes", "ingress", "stripe"); if too few of them occur in
the scan's vocabulary — directly, by simple stem, or through a small security-synonym table
("hardcoded" ~ "secret", "leak" ~ "expose") — the question is out of scope. Pure code: no model, no
I/O, same input → same result.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from aegis.chat.sparse import STOPWORDS

__all__ = ["Coverage", "term_coverage", "stem"]

_EXTRA_FILLER = frozenset(
    "another other also just very more most many much get gets got make makes made use used using tell "
    "give show explain describe mean means meaning happen happens work works need needs want please let "
    "go going know think say said thing things way ways like etc one two".split()
)

# words that describe the kind of question or the security domain in general — not a subject
_GENERIC = frozenset(
    "risk risks risky danger dangerous serious severe severity bad impact exploit exploitable exploited "
    "fix fixes fixed fixing remediate remediation patch resolve resolved issue issues finding findings "
    "vulnerability vulnerabilities vulnerable problem problems weakness weaknesses security secure "
    "insecure scan scanned report project app application code codebase repo repository top first last "
    "priority prioritize important critical high medium low worst biggest main overall summary summarize "
    "summarise overview list count number total state confirmed candidate corroborated attack attacker "
    "attackers".split()
)

# groups of words that mean the same thing for findings; a question word is covered if the scan
# contains ANY member of its group
_ALIASES: tuple[frozenset[str], ...] = tuple(frozenset(g.split()) for g in (
    "secret hardcoded credential password token apikey key private",
    "leak expose exposure disclose disclosure reveal exfiltration steal theft read view unauthorized unauthorised",
    "sqli sql injection query",
    "idor bola access authorization authorisation ownership permission privilege authz owner",
    "xss script scripting javascript",
    "tls ssl https certificate cert protocol cipher",
    "crypto cryptography cryptographic hash md5 sha1 encrypt encryption weak",
    "dependency package library cve outdated upgrade version",
    "ssrf forgery request",
    "misconfig misconfiguration config configuration setting header cors debug",
    "traversal path directory file",
    "deserialization deserialize pickle serialization",
))

_RUN = re.compile(r"[A-Za-z0-9]+(?:[._-][A-Za-z0-9]+)*")   # a whole identifier: get_account, cwe-89, a01
_PARTS = re.compile(r"[._-]+")

_SUFFIXES = ("ations", "ation", "ings", "ing", "ies", "ed", "es", "s")


def stem(word: str) -> str:
    """A light, deterministic stem: strip one common suffix, then a trailing 'e'."""
    w = word.lower()
    for suffix in _SUFFIXES:
        if w.endswith(suffix) and len(w) - len(suffix) >= 4:
            w = w[: -len(suffix)]
            break
    if w.endswith("e") and len(w) > 4:
        w = w[:-1]
    return w


def _stems(words) -> frozenset[str]:
    return frozenset({*words, *(stem(w) for w in words)})


_IGNORED = _stems(STOPWORDS | _EXTRA_FILLER | _GENERIC)
_ALIAS_STEMS: tuple[frozenset[str], ...] = tuple(_stems(g) for g in _ALIASES)


@dataclass(frozen=True)
class Coverage:
    ratio: float                 # matched / distinctive terms; 1.0 when there is nothing to check
    matched: tuple[str, ...]
    unmatched: tuple[str, ...]


def _covered(term: str, vocab: frozenset[str]) -> bool:
    s = stem(term)
    return term in vocab or s in vocab or any(s in g and not g.isdisjoint(vocab) for g in _ALIAS_STEMS)


def term_coverage(question: str, vocabulary) -> Coverage:
    """How much of the question's subject matter occurs in the scan's vocabulary.

    Each identifier in the question counts once (``A01`` is one term, not ``a01`` + ``01``); an
    identifier made of parts (``get_account``) is covered if it, or all of its parts, are.
    """
    terms: list[str] = []
    for run in _RUN.findall(question or ""):
        tok = run.lower()
        if len(tok) >= 2 and tok not in _IGNORED and stem(tok) not in _IGNORED and tok not in terms:
            terms.append(tok)
    if not terms or not vocabulary:
        return Coverage(1.0, (), ())          # nothing distinctive to check (or nothing indexed)

    vocab = _stems(vocabulary)
    matched, unmatched = [], []
    for term in terms:
        hit = _covered(term, vocab)
        if not hit:
            parts = [p for p in _PARTS.split(term) if len(p) >= 2 and p not in _IGNORED and stem(p) not in _IGNORED]
            hit = bool(parts) and all(_covered(p, vocab) for p in parts)
        (matched if hit else unmatched).append(term)
    return Coverage(len(matched) / len(terms), tuple(matched), tuple(unmatched))
