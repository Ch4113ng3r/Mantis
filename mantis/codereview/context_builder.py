"""
Smart context construction for token-optimized code analysis.

Instead of sending entire files to the LLM, builds minimal but
COMPLETE context: target function + data flow path + security-relevant
callees + sanitization status + config.

Typical output: 300-800 tokens instead of 3000-8000 for the full file.
"""

from dataclasses import dataclass
from typing import Optional


# Functions that are security-relevant when called
SECURITY_SENSITIVE = {
    "python": [
        "execute", "raw", "cursor", "eval", "exec", "system", "popen",
        "subprocess", "render_template_string", "open", "send_file",
        "redirect", "make_response", "loads", "pickle", "yaml.load",
    ],
    "javascript": [
        "eval", "innerHTML", "document.write", "exec", "spawn", "query",
        "raw", "dangerouslySetInnerHTML", "readFile", "writeFile",
    ],
    "java": [
        "executeQuery", "execute", "Runtime.exec", "ProcessBuilder",
        "ObjectInputStream", "readObject", "XMLDecoder", "ScriptEngine.eval",
    ],
}


@dataclass
class ScanContext:
    """Context package for a single function analysis."""
    target_function: str
    taint_path: str
    input_source: str
    dangerous_callees: list[str]
    sanitizers: list[str]
    sanitization_status: str
    relevant_config: str
    total_tokens_estimate: int


class SmartContextBuilder:
    """
    Build minimal but complete analysis context.

    Key insight: vulnerabilities are local phenomena with contextual
    dependencies. The right unit of analysis is the DATA FLOW PATH,
    not the file.
    """

    def __init__(self, callgraph=None, taint_map=None, source_reader=None):
        self.callgraph = callgraph
        self.taint_map = taint_map
        self.source = source_reader

    def build(self, file_path: str, function_name: str, language: str) -> ScanContext:
        """Build minimal context for analyzing a specific function."""
        # This will be populated when the callgraph/taint infrastructure is built
        target_fn = f"# Function: {function_name} in {file_path}"
        return ScanContext(
            target_function=target_fn,
            taint_path="",
            input_source="",
            dangerous_callees=[],
            sanitizers=[],
            sanitization_status="NONE detected",
            relevant_config="",
            total_tokens_estimate=0,
        )
