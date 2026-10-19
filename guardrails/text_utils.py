"""Shared text helpers: normalisation, tokenising, sentence splitting, numbers."""
from __future__ import annotations

import re
import unicodedata

# Zero-width and bidi control characters that attackers use to split keywords.
_INVISIBLE = dict.fromkeys(
    map(ord, "​‌‍⁠﻿‪‫‬‭‮­"), None
)
_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})

STOPWORDS = set(
    """a an the and or but if then so of to in on at by for with from as is are was were be been being
    it its this that these those there here what which who whom whose when where why how do does did
    can could should would may might must will shall i me my we our you your he she they them their
    not no yes than too very just also into over under about after before between each any all some
    such only own same other more most both few up down out off again further once per via""".split()
)


def normalize(text: str) -> str:
    """NFKC-normalise, strip invisible characters and collapse whitespace."""
    t = unicodedata.normalize("NFKC", text).translate(_INVISIBLE)
    return re.sub(r"\s+", " ", t).strip()


def deobfuscate(text: str) -> str:
    """Aggressive normalisation used only for injection scanning.

    Lower-cases, reverses common leetspeak and re-joins spaced-out letters
    ("i g n o r e" -> "ignore"). This destroys numbers, so never use it on
    text that is sent to the model.
    """
    t = normalize(text).lower()
    # Re-join runs of single characters separated by space/dot/dash/underscore.
    t = re.sub(
        r"\b(?:[a-z0-9@$][\s._-]){3,}[a-z0-9@$]\b",
        lambda m: re.sub(r"[\s._-]", "", m.group()),
        t,
    )
    # Leetspeak only inside tokens that contain letters (keeps pure numbers).
    t = re.sub(r"\S*[a-z]\S*", lambda m: m.group().translate(_LEET), t)
    return t


def stem(word: str) -> str:
    """Very small suffix stripper; enough for overlap scoring.

    Maps fence/fences, dispute/disputes, use/uses/used, property/properties
    to the same key.
    """
    if len(word) <= 3 or word.isdigit():
        return word
    for suf in ("ations", "ation", "ments", "ment", "ings", "ing", "ies", "ied", "ed", "es", "s"):
        if len(word) > len(suf) + 2 and word.endswith(suf):
            word = word[: -len(suf)] + ("i" if suf in ("ies", "ied") else "")
            break
    if word.endswith("y"):
        word = word[:-1] + "i"
    return word.rstrip("e") if len(word) > 3 else word


def tokens(text: str) -> list[str]:
    return re.findall(r"[a-z0-9]+(?:\.[0-9]+)?", text.lower())


def content_tokens(text: str) -> set[str]:
    return {stem(t) for t in tokens(text) if t not in STOPWORDS and len(t) > 1 or t.isdigit()}


def numbers(text: str) -> set[str]:
    """Extract numbers, normalising thousands separators (10,000,000 -> 10000000)."""
    out = set()
    for m in re.findall(r"\d[\d,]*(?:\.\d+)?", text):
        n = m.replace(",", "").rstrip(".")
        if n:
            out.add(n)
    return out


_SENT_SPLIT = re.compile(r"(?<=[.!?])\s+(?=[A-Z0-9\"'(])")


def sentences(text: str) -> list[str]:
    return [s.strip() for s in _SENT_SPLIT.split(text.strip()) if s.strip()]


NEGATIONS = {"not", "no", "never", "none", "cannot", "neither", "nor", "without", "n't"}


def has_negation(text: str) -> bool:
    low = text.lower().replace("n't", " n't")
    return any(t in NEGATIONS for t in re.findall(r"[a-z']+", low))
