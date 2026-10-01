"""``python -m aiguard`` entry point.

The CLI module is imported lazily so that importing this module (for example
by tooling) never pulls in the CLI or runs it.
"""


def _run() -> int:
    from .cli import main

    return main()


if __name__ == "__main__":
    raise SystemExit(_run())
