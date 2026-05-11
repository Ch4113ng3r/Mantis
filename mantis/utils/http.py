"""HTTP client utilities."""

import httpx


def create_client(
    timeout: float = 30.0,
    verify: bool = False,
    user_agent: str = "MANTIS/1.0",
) -> httpx.AsyncClient:
    """Create a configured async HTTP client."""
    return httpx.AsyncClient(
        timeout=httpx.Timeout(timeout),
        verify=verify,
        headers={"User-Agent": user_agent},
        follow_redirects=True,
        limits=httpx.Limits(max_connections=20),
    )
