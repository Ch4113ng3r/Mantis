"""
Verbose logging for MANTIS debugging.

Activated via --verbose CLI flag or MANTIS_VERBOSE=1 environment variable.
When enabled, prints detailed scanner activity, AI calls, response analysis.
Designed for first-run debugging on real targets where you need to see what
MANTIS is doing.
"""

import os
import sys
import time
from datetime import datetime
from typing import Optional


class VerboseLogger:
    """
    Centralized verbose logger.

    Levels:
      QUIET   — only errors and final summaries
      NORMAL  — phase headers and finding counts (default)
      VERBOSE — every scanner invocation, every AI call, response sizes
      TRACE   — full request/response bodies (huge output)
    """

    # Singleton
    _instance: Optional["VerboseLogger"] = None

    def __init__(self):
        env = os.environ.get("MANTIS_VERBOSE", "").lower()
        if env in ("1", "true", "yes", "verbose"):
            self.level = "verbose"
        elif env == "trace":
            self.level = "trace"
        elif env in ("0", "false", "quiet"):
            self.level = "quiet"
        else:
            self.level = "normal"
        self.start_time = time.time()
        self.scanner_calls = 0
        self.ai_calls = 0
        self.http_requests = 0
        self.findings_emitted = 0

    @classmethod
    def get(cls) -> "VerboseLogger":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def set_level(self, level: str):
        if level in ("quiet", "normal", "verbose", "trace"):
            self.level = level

    def _ts(self) -> str:
        elapsed = time.time() - self.start_time
        return f"+{elapsed:6.1f}s"

    def _emit(self, prefix: str, msg: str, color: str = ""):
        sys.stdout.write(f"  {self._ts()} {prefix} {msg}\n")
        sys.stdout.flush()

    def phase(self, name: str):
        """Phase header (always shown)."""
        sys.stdout.write(f"\n{'=' * 70}\n  PHASE: {name}\n{'=' * 70}\n")
        sys.stdout.flush()

    def info(self, msg: str):
        """Normal info (NORMAL and above)."""
        if self.level in ("normal", "verbose", "trace"):
            self._emit("[INFO]", msg)

    def scanner(self, scanner_name: str, target: str, param: str = "", score: int = 0):
        """Scanner invocation (VERBOSE and above)."""
        self.scanner_calls += 1
        if self.level in ("verbose", "trace"):
            param_str = f" param={param}" if param else ""
            score_str = f" [AI score={score}]" if score else ""
            self._emit("[SCAN]", f"{scanner_name} → {target}{param_str}{score_str}")

    def scanner_skipped(self, scanner_name: str, reason: str):
        """Scanner skipped (VERBOSE only)."""
        if self.level in ("verbose", "trace"):
            self._emit("[SKIP]", f"{scanner_name} — {reason}")

    def ai_call(self, model: str, purpose: str, input_tokens: int = 0):
        """AI call (VERBOSE and above)."""
        self.ai_calls += 1
        if self.level in ("verbose", "trace"):
            tok_str = f" ~{input_tokens}t in" if input_tokens else ""
            self._emit("[AI]  ", f"{model} ({purpose}){tok_str}")

    def ai_response(self, purpose: str, response_summary: str):
        """AI response summary (VERBOSE and above)."""
        if self.level in ("verbose", "trace"):
            summary = response_summary[:200] if response_summary else "(empty)"
            self._emit("[AI<]", f"{purpose}: {summary}")

    def http(self, method: str, url: str, status: int = 0, size: int = 0):
        """HTTP request (VERBOSE and above)."""
        self.http_requests += 1
        if self.level in ("verbose", "trace"):
            stat = f" → {status}" if status else ""
            sz = f" ({size}b)" if size else ""
            self._emit("[HTTP]", f"{method} {url}{stat}{sz}")

    def http_body(self, body: str, direction: str = "response"):
        """HTTP body content (TRACE only)."""
        if self.level == "trace":
            preview = body[:500].replace("\n", "\\n")
            self._emit(f"[BODY{direction[:3].upper()}]", preview)

    def finding(self, title: str, severity: str, confidence: float = 0.0):
        """Finding emitted (NORMAL and above)."""
        self.findings_emitted += 1
        if self.level in ("normal", "verbose", "trace"):
            conf = f" ({confidence:.0%})" if confidence else ""
            self._emit(f"[FIND-{severity.upper()[:4]}]", f"{title}{conf}")

    def classification(self, url: str, purpose: str, top_scores: dict):
        """AI classification result (VERBOSE and above)."""
        if self.level in ("verbose", "trace"):
            top_3 = sorted(top_scores.items(), key=lambda x: x[1], reverse=True)[:3]
            scores_str = ", ".join(f"{k}={v}" for k, v in top_3)
            self._emit("[CLAS]", f"{url} → {purpose} [{scores_str}]")

    def investigation(self, endpoint: str, vuln_class: str, action: str, detail: str = ""):
        """Mode 2/3 investigation step (VERBOSE and above)."""
        if self.level in ("verbose", "trace"):
            self._emit("[INV] ", f"{endpoint} [{vuln_class}] {action}: {detail[:200]}")

    def interpretation(self, endpoint: str, verdict: str, confidence: float, reasoning: str):
        """Mode 2 response interpretation (VERBOSE and above)."""
        if self.level in ("verbose", "trace"):
            self._emit("[INTERP]",
                       f"{endpoint}: {verdict} ({confidence:.0%}) — {reasoning[:200]}")

    def error(self, msg: str, exc: Optional[Exception] = None):
        """Error (always shown)."""
        exc_str = f" [{type(exc).__name__}: {exc}]" if exc else ""
        self._emit("[ERROR]", f"{msg}{exc_str}")

    def warn(self, msg: str):
        """Warning (NORMAL and above)."""
        if self.level in ("normal", "verbose", "trace"):
            self._emit("[WARN]", msg)

    def summary(self):
        """Final stats summary (always shown)."""
        elapsed = time.time() - self.start_time
        sys.stdout.write(
            f"\n{'=' * 70}\n"
            f"  MANTIS RUN SUMMARY\n"
            f"{'=' * 70}\n"
            f"  Elapsed:          {elapsed:.1f}s\n"
            f"  HTTP requests:    {self.http_requests}\n"
            f"  Scanner calls:    {self.scanner_calls}\n"
            f"  AI calls:         {self.ai_calls}\n"
            f"  Findings emitted: {self.findings_emitted}\n"
            f"{'=' * 70}\n"
        )
        sys.stdout.flush()


# Module-level convenience
log = VerboseLogger.get()
