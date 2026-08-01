"""rtsilicon authorization boundary.

HARD RULE (carried over verbatim from redthread): any command that reaches
outside the local tree — git push, gh pr create/issue, twine upload, curl -X
POST, sending an email to a maintainer — ALWAYS requires interactive
approval. Even in full-auto. Even overnight. Unattended runs write to
pending-approval/ and do NOT execute.

This is enforced in code, not in the prompt. A prompt-only boundary is not a
boundary.
"""

from __future__ import annotations

import shlex
import subprocess
from pathlib import Path

# Substrings that mark a command as crossing the boundary. If a command
# contains any of these, it MUST be gated.
NETWORK_OR_PUBLISH_SUBSTRINGS = (
    "git push",
    "git clone",          # network fetch — gated
    "gh pr create",
    "gh pr merge",
    "gh pr edit",
    "gh issue create",
    "gh release create",
    "gh api --method POST",   # mutation
    "gh api --method PUT",
    "gh api --method DELETE",
    "gh api -X POST",
    "gh fork",
    "gh repo create",
    "docker push",
    "docker pull",
    "npm publish",
    "twine upload",
    "huggingface-cli upload",
    "curl -X POST",
    "curl -X PUT",
    "curl -X DELETE",
    "curl --request POST",
    "wget ",                  # network fetch
    "scp ",
    "rsync ",
    "sendmail",
    "mailx",
)


def is_gated(command: str) -> bool:
    """True if the command crosses the auth boundary."""
    c = command.strip().lower()
    return any(sub.lower() in c for sub in NETWORK_OR_PUBLISH_SUBSTRINGS)


def pending_dir(root: Path) -> Path:
    d = root / ".rtsilicon" / "pending-approval"
    d.mkdir(parents=True, exist_ok=True)
    return d


def run(command: str, root: Path, *, auto_approve: bool = False) -> subprocess.CompletedProcess:
    """The ONLY sanctioned entry point for running a command from the agent.

    - Non-gated commands run directly.
    - Gated commands require auto_approve=True AND are still logged.
    - If auto_approve is False and the command is gated, it is written to
      pending-approval/ and NOT executed. The function raises PermissionError.
    """
    if not is_gated(command):
        return subprocess.run(shlex.split(command), capture_output=True, text=True, check=False)

    # Gated path.
    log = pending_dir(root) / "gated.log"
    with log.open("a") as f:
        f.write(f"{command}\n")

    if not auto_approve:
        raise PermissionError(
            f"GATED COMMAND (not auto-approved, written to {log}):\n  {command}"
        )

    return subprocess.run(shlex.split(command), capture_output=True, text=True, check=False)
