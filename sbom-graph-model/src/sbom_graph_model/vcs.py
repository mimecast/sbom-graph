"""Version Control System (VCS) URL utilities.

Centralised helpers for detecting known git hosting platforms and
parsing repository URLs into structured metadata.  Used by both the
CycloneDX and SPDX processors to avoid duplicating host-detection
logic.
"""

from typing import Optional
from urllib.parse import urlparse

KNOWN_GIT_HOSTS: frozenset[str] = frozenset({
    "github.com",
    "gitlab.com",
    "bitbucket.org",
})


def is_known_git_host(hostname: str) -> bool:
    """Return ``True`` if *hostname* belongs to a well-known git platform.

    Matches exact domains (``github.com``) as well as their
    subdomains (``enterprise.github.com``).

    Args:
        hostname: The hostname to check (should already be lower-cased).
    """
    host = hostname.lower()
    for domain in KNOWN_GIT_HOSTS:
        if host == domain or host.endswith(f".{domain}"):
            return True
    return False


def parse_repo_url(url: str) -> dict[str, Optional[str]]:
    """Parse a repository URL into namespace, name, and vcs_type.

    Args:
        url: A repository URL (HTTPS, SSH, git:// etc.).

    Returns:
        Dict with keys ``namespace`` (the netloc), ``name`` (the path
        component with a trailing ``.git`` stripped), and ``vcs_type``
        (``"git"`` when the host is a known git platform or the URL
        ends with ``.git``, otherwise ``None``).
    """
    parsed = urlparse(url.rstrip("/"))
    namespace = parsed.netloc or None
    path = parsed.path.lstrip("/")
    if path.endswith(".git"):
        path = path[:-4]
    host = (parsed.hostname or "").lower()
    is_git = is_known_git_host(host) or url.endswith(".git")
    return {
        "namespace": namespace,
        "name": path or None,
        "vcs_type": "git" if is_git else None,
    }
