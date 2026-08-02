"""Entry point for ``python -m sentinel`` and the ``sentinel`` console script.

Kept deliberately thin: it exists to translate a few process-level concerns
(missing dependencies, Ctrl-C, a broken pipe) into clean messages and exit
codes before handing over to Typer.
"""

from __future__ import annotations

import contextlib
import sys


def main() -> int:
    """Run the CLI and return a process exit code."""
    try:
        from sentinel.cli.commands import app
    except ImportError as exc:
        # The most common cause by far is running from a source checkout
        # without installing the dependencies.
        print(
            f"Sentinel Scan could not start: {exc}\n\n"
            f"Install its dependencies with:\n"
            f"    pip install -r requirements.txt\n"
            f"or install the package itself:\n"
            f"    pip install -e .",
            file=sys.stderr,
        )
        return 2

    try:
        app()
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130
    except BrokenPipeError:
        # `sentinel scan --json | head` closes the pipe early. Exiting
        # quietly is the correct Unix behaviour.
        with contextlib.suppress(Exception):
            sys.stdout.close()
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
