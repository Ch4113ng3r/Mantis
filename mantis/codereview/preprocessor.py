"""
Source code preprocessor phase.

Enumerates source files, filters out non-relevant files (binaries,
vendor, tests, generated), and collects metadata (language, imports,
function signatures, line count) for each file.
"""

import os
import re
from pathlib import Path
from mantis.engage.phases import Phase


# File extensions to include by language
LANGUAGE_EXTENSIONS = {
    "python": [".py"],
    "javascript": [".js", ".jsx", ".ts", ".tsx", ".mjs"],
    "java": [".java"],
    "csharp": [".cs"],
    "go": [".go"],
    "ruby": [".rb"],
    "php": [".php"],
    "c": [".c", ".h"],
    "cpp": [".cpp", ".cc", ".cxx", ".hpp", ".hxx"],
    "rust": [".rs"],
    "swift": [".swift"],
    "kotlin": [".kt", ".kts"],
    "scala": [".scala"],
}

# Directories to always skip
SKIP_DIRS = {
    "node_modules", "vendor", "venv", ".venv", "__pycache__",
    ".git", ".svn", ".hg", "dist", "build", ".tox", ".mypy_cache",
    ".pytest_cache", "coverage", ".next", ".nuxt", "target",
    "bin", "obj", "packages", "bower_components",
}

# File patterns to skip
SKIP_PATTERNS = [
    "**/test_*", "**/*_test.*", "**/*.test.*", "**/*.spec.*",
    "**/migrations/*", "**/generated/*", "**/*.min.js", "**/*.min.css",
    "**/*.map", "**/package-lock.json", "**/yarn.lock", "**/Cargo.lock",
]


def enumerate_source_files(repo_path: str, skip_patterns: list = None) -> list[dict]:
    """
    Walk the repository and collect metadata for each source file.

    Returns list of file metadata dicts suitable for the triage engine.
    """
    all_skip = SKIP_PATTERNS + (skip_patterns or [])
    files = []

    # Build extension -> language map
    ext_to_lang = {}
    for lang, exts in LANGUAGE_EXTENSIONS.items():
        for ext in exts:
            ext_to_lang[ext] = lang

    for root, dirs, filenames in os.walk(repo_path):
        # Skip excluded directories
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]

        for filename in filenames:
            filepath = os.path.join(root, filename)
            rel_path = os.path.relpath(filepath, repo_path)
            ext = os.path.splitext(filename)[1].lower()

            if ext not in ext_to_lang:
                continue

            # Check skip patterns
            import fnmatch
            skip = False
            for pattern in all_skip:
                if fnmatch.fnmatch(rel_path, pattern):
                    skip = True
                    break
            if skip:
                continue

            # Collect metadata
            language = ext_to_lang[ext]
            try:
                with open(filepath, "r", errors="replace") as f:
                    content = f.read()
                lines = content.splitlines()
                line_count = len(lines)

                # Extract imports
                imports = _extract_imports(content, language)

                # Extract function/method signatures
                functions = _extract_functions(content, language)

                files.append({
                    "path": rel_path,
                    "full_path": filepath,
                    "language": language,
                    "line_count": line_count,
                    "imports": imports[:20],
                    "functions": functions[:20],
                    "size_bytes": os.path.getsize(filepath),
                    "static_hits": "",
                    "taint_summary": "",
                })
            except Exception:
                continue

    return files


def _extract_imports(content: str, language: str) -> list[str]:
    """Extract import statements from source code."""
    imports = []
    if language == "python":
        for match in re.finditer(r'^(?:from\s+(\S+)\s+)?import\s+(.+)$', content, re.MULTILINE):
            imports.append(match.group(0).strip())
    elif language in ("javascript", "typescript"):
        for match in re.finditer(r"(?:import|require)\s*\(?['\"]([^'\"]+)['\"]", content):
            imports.append(match.group(1))
    elif language == "java":
        for match in re.finditer(r'^import\s+([\w.]+);', content, re.MULTILINE):
            imports.append(match.group(1))
    elif language == "go":
        for match in re.finditer(r'"([^"]+)"', content[:2000]):
            imports.append(match.group(1))
    elif language == "php":
        for match in re.finditer(r'(?:use|require|include)\s+[\'"]?([^\s;\'\"]+)', content):
            imports.append(match.group(1))
    return imports


def _extract_functions(content: str, language: str) -> list[str]:
    """Extract function/method names from source code."""
    functions = []
    if language == "python":
        for match in re.finditer(r'^\s*(?:async\s+)?def\s+(\w+)', content, re.MULTILINE):
            functions.append(match.group(1))
    elif language in ("javascript", "typescript"):
        for match in re.finditer(r'(?:function\s+(\w+)|(\w+)\s*(?:=|:)\s*(?:async\s+)?(?:function|\([^)]*\)\s*=>))', content):
            name = match.group(1) or match.group(2)
            if name:
                functions.append(name)
    elif language == "java":
        for match in re.finditer(r'(?:public|private|protected|static|\s)+[\w<>\[\]]+\s+(\w+)\s*\(', content):
            functions.append(match.group(1))
    elif language == "go":
        for match in re.finditer(r'^func\s+(?:\([^)]+\)\s+)?(\w+)', content, re.MULTILINE):
            functions.append(match.group(1))
    elif language == "php":
        for match in re.finditer(r'function\s+(\w+)', content):
            functions.append(match.group(1))
    return functions


class PreprocessPhase(Phase):
    """Phase: enumerate and preprocess source files for code review."""

    async def execute(self, context) -> dict:
        source_path = self.config.source_path
        if not source_path:
            print("    No source path provided (--source flag). Skipping preprocessing.")
            return {}

        if not os.path.isdir(source_path):
            print(f"    Source path not found: {source_path}")
            return {}

        files = enumerate_source_files(source_path)
        print(f"    Preprocessed {len(files)} source files")

        # Summary by language
        lang_counts = {}
        for f in files:
            lang = f["language"]
            lang_counts[lang] = lang_counts.get(lang, 0) + 1
        for lang, count in sorted(lang_counts.items()):
            print(f"      {lang}: {count} files")

        return {"source_files": files}
