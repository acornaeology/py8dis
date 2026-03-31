"""Shared test fixtures for py8dis tests.

Because py8dis uses extensive module-level global state that cannot be
reset between test cases, each test runs a self-contained disassembly
script in a subprocess. The run_py8dis() helper handles creating a
temporary ROM file and script, executing it, and returning the assembly
output.
"""

import os
import subprocess
import sys
import tempfile
import textwrap

import pytest


PY8DIS_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@pytest.fixture
def run_py8dis(tmp_path):
    """Return a helper that runs a py8dis script in a subprocess.

    Usage:
        output = run_py8dis(script, rom_bytes=b'\\xea' * 16)

    The helper writes `rom_bytes` to a temporary file, substitutes
    {rom_filepath} in the script with its path, and returns the
    assembly output string. Raises AssertionError on non-zero exit.
    """

    def _run(script, rom_bytes=b'\xea' * 16):
        rom_filepath = tmp_path / "test.rom"
        rom_filepath.write_bytes(rom_bytes)

        script = textwrap.dedent(script).strip()
        script = script.replace("{rom_filepath}", str(rom_filepath))

        script_filepath = tmp_path / "disassembly.py"
        script_filepath.write_text(script)

        result = subprocess.run(
            [sys.executable, str(script_filepath)],
            capture_output=True,
            text=True,
            cwd=str(tmp_path),
            env={**os.environ, "PYTHONPATH": PY8DIS_ROOT},
        )

        if result.returncode != 0:
            raise AssertionError(
                f"py8dis script failed (rc={result.returncode}):\n"
                f"--- stdout ---\n{result.stdout}\n"
                f"--- stderr ---\n{result.stderr}"
            )

        return result.stdout

    return _run
