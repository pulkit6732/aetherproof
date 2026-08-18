"""The package version must agree with the build metadata.

0.5.0 shipped to PyPI with pyproject.toml at 0.5.0 and __init__.py still at
0.4.0, so `aetherproof.__version__` reported the wrong number to anyone who
asked. Bumping a release in one place and not the other is easy to do and
invisible until it is published, which is the worst time to find it.
"""

import re
import sys
from pathlib import Path

import aetherproof

ROOT = Path(__file__).resolve().parents[1]


def _pyproject_version() -> str:
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
    assert match, "pyproject.toml has no top-level version"
    return match.group(1)


def test_dunder_version_matches_pyproject():
    assert aetherproof.__version__ == _pyproject_version(), (
        f"aetherproof.__version__ is {aetherproof.__version__} but pyproject.toml "
        f"says {_pyproject_version()}; bump both"
    )


def test_installed_metadata_matches_when_available():
    """If the package is installed, its recorded version must agree too."""
    if sys.version_info < (3, 8):
        return
    from importlib import metadata

    try:
        installed = metadata.version("aetherproof")
    except metadata.PackageNotFoundError:
        return  # running from a source tree that was never installed
    assert installed == aetherproof.__version__, (
        f"installed metadata says {installed}, package says {aetherproof.__version__}"
    )


def test_version_is_a_plausible_release_number():
    assert re.fullmatch(r"\d+\.\d+\.\d+([.-]?(a|b|rc|dev)\d*)?", aetherproof.__version__), (
        f"{aetherproof.__version__!r} is not a release-shaped version"
    )
