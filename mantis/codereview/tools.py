"""Tool definitions for the code review agent."""

from mantis.core.agent import ToolSpec


def get_codereview_tools() -> list[ToolSpec]:
    """Return all tools available for source code review."""
    return [
        ToolSpec(
            name="read_file",
            description="Read the contents of a source code file.",
            parameters={
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "File path to read"},
                },
                "required": ["path"],
            },
            handler=_handle_read_file,
            category="codereview",
        ),
        ToolSpec(
            name="search_code",
            description="Search for a pattern across source files using grep.",
            parameters={
                "type": "object",
                "properties": {
                    "pattern": {"type": "string", "description": "Regex pattern"},
                    "path": {"type": "string", "description": "Directory to search"},
                },
                "required": ["pattern", "path"],
            },
            handler=_handle_search_code,
            category="codereview",
        ),
    ]


async def _handle_read_file(path: str) -> str:
    try:
        with open(path) as f:
            return f.read()[:50000]  # Cap at 50K chars
    except Exception as e:
        return f"Error reading {path}: {e}"


async def _handle_search_code(pattern: str, path: str) -> str:
    import subprocess
    try:
        result = subprocess.run(
            ["grep", "-rn", pattern, path],
            capture_output=True, text=True, timeout=30,
        )
        return result.stdout[:10000] or "No matches found"
    except Exception as e:
        return f"Search error: {e}"
