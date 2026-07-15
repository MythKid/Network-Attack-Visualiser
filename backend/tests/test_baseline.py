"""Tooling-baseline test.

Phase 0.5: proves the test runner, import path and package skeleton work
end to end. It exercises no application behaviour (there is none yet) — it
simply imports the backend package and checks its version marker so that
`pytest` has at least one real, passing test to collect.
"""

import app


def test_version_is_non_empty_string() -> None:
    """The package exposes a non-empty string version marker."""
    assert isinstance(app.__version__, str)
    assert app.__version__
