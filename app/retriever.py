"""Small BM25 retriever over the knowledge base (no external dependencies)."""
from __future__ import annotations

import math
from collections import Counter

from guardrails.text_utils import STOPWORDS, stem, tokens


def _terms(text: str) -> list[str]:
    return [stem(t) for t in tokens(text) if t not in STOPWORDS]


class BM25Retriever:
    def __init__(self, docs: dict[str, str], k1: float = 1.4, b: float = 0.75) -> None:
        self.docs = docs
        self.k1, self.b = k1, b
        self.tf = {d: Counter(_terms(t)) for d, t in docs.items()}
        self.len = {d: sum(c.values()) for d, c in self.tf.items()}
        self.avg = sum(self.len.values()) / max(len(self.len), 1)
        df = Counter(term for c in self.tf.values() for term in c)
        n = len(docs)
        self.idf = {t: math.log(1 + (n - f + 0.5) / (f + 0.5)) for t, f in df.items()}

    def search(self, query: str, k: int = 3) -> list[tuple[str, float]]:
        q = _terms(query)
        scores = {}
        for d, tf in self.tf.items():
            s = 0.0
            for t in q:
                if t in tf:
                    f = tf[t]
                    s += self.idf[t] * f * (self.k1 + 1) / (f + self.k1 * (1 - self.b + self.b * self.len[d] / self.avg))
            if s > 0:
                scores[d] = round(s, 3)
        return sorted(scores.items(), key=lambda x: -x[1])[:k]
