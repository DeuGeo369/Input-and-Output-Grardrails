"""Command-line entry point.

    python cli.py "Which MGA zones cover NSW?"
    python cli.py "Summarise my notes" --context notes.txt --trace
    python cli.py "What is SCIMS?" --llm gemini        # needs GEMINI_API_KEY
    python cli.py --interactive
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from app.llm import ExtractiveMockLLM
from app.pipeline import GuardedAssistant


def make_llm(kind: str):
    if kind == "gemini":
        from app.llm import GeminiLLM
        return GeminiLLM()
    return ExtractiveMockLLM()


def show(res, trace: bool) -> None:
    print(f"\nstatus: {res.status}   attempts: {res.attempts}   "
          f"input_redacted: {res.input_redacted}   output_redacted: {res.output_redacted}")
    print(json.dumps(res.response, indent=2, ensure_ascii=False))
    for n in res.notices:
        print(f"note: {n}")
    if trace:
        print("\ntrace:")
        for t in res.trace:
            if "guardrail" in t:
                print(f"  [{t['stage']}{'#' + str(t['attempt']) if 'attempt' in t else ''}] "
                      f"{t['guardrail']:<28} flagged={t['flagged']!s:<5} action={t['action']:<24} score={t['score']}")
            else:
                print(f"  [{t['stage']}] hits={t['hits']} kept={t['kept']}")


def main() -> None:
    ap = argparse.ArgumentParser(description="SurveyGuard: guarded NSW surveying assistant")
    ap.add_argument("question", nargs="?")
    ap.add_argument("--context", help="path to an untrusted reference document (e.g. field notes)")
    ap.add_argument("--llm", choices=["mock", "gemini"], default="mock")
    ap.add_argument("--trace", action="store_true", help="print every guardrail decision")
    ap.add_argument("--interactive", action="store_true")
    a = ap.parse_args()

    bot = GuardedAssistant(llm=make_llm(a.llm))
    ctx = Path(a.context).read_text(encoding="utf-8") if a.context else None
    if a.interactive:
        while True:
            try:
                q = input("\nquestion> ").strip()
            except (EOFError, KeyboardInterrupt):
                break
            if q:
                show(bot.ask(q, ctx), a.trace)
    elif a.question:
        show(bot.ask(a.question, ctx), a.trace)
    else:
        ap.print_help()


if __name__ == "__main__":
    main()
