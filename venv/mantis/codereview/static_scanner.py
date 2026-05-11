"""
Static analysis phase using Semgrep and regex pattern matching.

Layer 1 of the four-layer funnel. Runs free, fast static analysis
to tag files with hit counts before Haiku triage.

Semgrep: if installed, runs community rules for the detected languages.
Regex: always runs, matches dangerous function patterns.
"""

import subprocess
import json
import re
import os
from mantis.engage.phases import Phase


# Dangerous function patterns by language
DANGEROUS_PATTERNS = {
    "python": [
        (r'\beval\s*\(', "eval() — arbitrary code execution"),
        (r'\bexec\s*\(', "exec() — arbitrary code execution"),
        (r'\bos\.system\s*\(', "os.system() — command injection"),
        (r'\bsubprocess\.(call|Popen|run)\s*\(.*shell\s*=\s*True', "subprocess with shell=True"),
        (r'\.raw\s*\(', "ORM .raw() — potential SQL injection"),
        (r'\bcursor\.execute\s*\([^,]*%', "cursor.execute with string formatting — SQL injection"),
        (r'\bpickle\.loads?\s*\(', "pickle deserialization — arbitrary code execution"),
        (r'\byaml\.load\s*\(', "yaml.load without SafeLoader — code execution"),
        (r'\brender_template_string\s*\(', "render_template_string — SSTI"),
        (r'\bmark_safe\s*\(', "mark_safe — XSS if user input"),
        (r'SECRET_KEY\s*=\s*["\'][^"\']{1,20}["\']', "Hardcoded secret key"),
        (r'password\s*=\s*["\'][^"\']+["\']', "Hardcoded password"),
    ],
    "javascript": [
        (r'\beval\s*\(', "eval() — arbitrary code execution"),
        (r'\.innerHTML\s*=', "innerHTML assignment — XSS"),
        (r'document\.write\s*\(', "document.write — XSS"),
        (r'\bchild_process\b.*\bexec\b', "child_process.exec — command injection"),
        (r'dangerouslySetInnerHTML', "React dangerouslySetInnerHTML — XSS"),
        (r'\.query\s*\([^)]*\+', "SQL query with string concatenation"),
        (r'new\s+Function\s*\(', "new Function() — code execution"),
        (r'api[_-]?key\s*[:=]\s*["\'][^"\']+', "Hardcoded API key"),
    ],
    "java": [
        (r'Runtime\.getRuntime\(\)\.exec\s*\(', "Runtime.exec — command injection"),
        (r'ProcessBuilder\s*\(', "ProcessBuilder — command injection"),
        (r'ObjectInputStream', "ObjectInputStream — deserialization"),
        (r'XMLDecoder', "XMLDecoder — XML deserialization"),
        (r'\.executeQuery\s*\([^)]*\+', "SQL query with concatenation"),
        (r'ScriptEngine.*eval', "ScriptEngine.eval — code execution"),
    ],
    "php": [
        (r'\bsystem\s*\(', "system() — command execution"),
        (r'\bexec\s*\(', "exec() — command execution"),
        (r'\bshell_exec\s*\(', "shell_exec() — command execution"),
        (r'\bpassthru\s*\(', "passthru() — command execution"),
        (r'\beval\s*\(', "eval() — code execution"),
        (r'\bmysql_query\s*\(', "mysql_query — SQL injection (deprecated)"),
        (r'\bunserialize\s*\(', "unserialize — deserialization"),
        (r'\binclude\s*\(\s*\$', "include with variable — LFI"),
    ],
}


def run_regex_scan(files: list[dict]) -> list[dict]:
    """Run regex pattern matching on all files."""
    results = []
    for file_meta in files:
        language = file_meta.get("language", "")
        patterns = DANGEROUS_PATTERNS.get(language, [])
        if not patterns:
            continue

        filepath = file_meta.get("full_path", "")
        try:
            with open(filepath, "r", errors="replace") as f:
                content = f.read()

            hits = []
            for pattern, description in patterns:
                matches = list(re.finditer(pattern, content))
                for match in matches:
                    line_num = content[:match.start()].count("\n") + 1
                    hits.append({
                        "pattern": description,
                        "line": line_num,
                        "match": match.group(0)[:100],
                    })

            if hits:
                results.append({
                    "path": file_meta["path"],
                    "language": language,
                    "hits": hits,
                    "hit_count": len(hits),
                })
                # Update file metadata with hit info
                file_meta["static_hits"] = f"{len(hits)} regex hits: {', '.join(h['pattern'] for h in hits[:3])}"

        except Exception:
            continue

    return results


def run_semgrep(repo_path: str) -> list[dict]:
    """Run Semgrep with auto config if installed."""
    try:
        result = subprocess.run(
            ["semgrep", "--config", "auto", "--json", "--quiet", repo_path],
            capture_output=True, text=True, timeout=300,
        )
        if result.returncode == 0:
            data = json.loads(result.stdout)
            findings = []
            for r in data.get("results", []):
                findings.append({
                    "path": r.get("path", ""),
                    "line": r.get("start", {}).get("line", 0),
                    "rule": r.get("check_id", ""),
                    "message": r.get("extra", {}).get("message", ""),
                    "severity": r.get("extra", {}).get("severity", ""),
                })
            return findings
    except FileNotFoundError:
        print("    Semgrep not installed — using regex patterns only")
    except subprocess.TimeoutExpired:
        print("    Semgrep timed out")
    except Exception as e:
        print(f"    Semgrep error: {e}")
    return []


class StaticScanPhase(Phase):
    """Phase: run static analysis (Semgrep + regex) on source files."""

    async def execute(self, context) -> dict:
        if not context.source_files:
            print("    No source files to scan")
            return {}

        # Run regex patterns on all files
        regex_results = run_regex_scan(context.source_files)
        total_regex_hits = sum(r["hit_count"] for r in regex_results)
        print(f"    Regex scan: {total_regex_hits} hits in {len(regex_results)} files")

        # Run Semgrep if available
        repo_path = self.config.source_path
        semgrep_results = []
        if repo_path:
            semgrep_results = run_semgrep(repo_path)
            if semgrep_results:
                print(f"    Semgrep: {len(semgrep_results)} findings")
                # Update file metadata with Semgrep hits
                semgrep_by_file = {}
                for r in semgrep_results:
                    path = r["path"]
                    if path not in semgrep_by_file:
                        semgrep_by_file[path] = []
                    semgrep_by_file[path].append(r)
                for file_meta in context.source_files:
                    path = file_meta.get("full_path", "")
                    if path in semgrep_by_file:
                        hits = semgrep_by_file[path]
                        existing = file_meta.get("static_hits", "")
                        file_meta["static_hits"] = f"{existing}; {len(hits)} semgrep hits" if existing else f"{len(hits)} semgrep hits"

        return {
            "triage_results": [],  # Will be populated by triage phase
        }
