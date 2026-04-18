"""Tests for `[label](address:HEX[?hex])` Markdown-style links in comments.

The markup is allowed in comment text and subroutine titles/descriptions
so downstream structured-JSON consumers can resolve labels to anchors.
The asm output must strip the markup to plain text via
`strip_address_uri_links`.
"""


def test_asm_output_strips_label_only(run_py8dis):
    """Bare `[label](address:HEX)` collapses to `label` in asm."""

    output = run_py8dis("""
        from py8dis.commands import *

        init()
        load(0x8000, "{rom_filepath}", "6502")

        entry(0x8000)
        comment(0x8000, "see [rx_frame_b](address:8005)", inline=True)

        go()
    """)

    assert "see rx_frame_b" in output
    assert "[rx_frame_b]" not in output
    assert "address:" not in output


def test_asm_output_expands_hex_flag(run_py8dis):
    """`?hex` flag appends ` (&HEX)` in asm, with hex upper-cased."""

    output = run_py8dis("""
        from py8dis.commands import *

        init()
        load(0x8000, "{rom_filepath}", "6502")

        entry(0x8000)
        comment(0x8000, "see [rx_frame_b](address:8005?hex)", inline=True)

        go()
    """)

    assert "see rx_frame_b (&8005)" in output
    assert "[rx_frame_b]" not in output


def test_version_qualifier_silently_stripped(run_py8dis):
    """`@version` is unused in listing context; strip it silently."""

    output = run_py8dis("""
        from py8dis.commands import *

        init()
        load(0x8000, "{rom_filepath}", "6502")

        entry(0x8000)
        comment(0x8000, "[rx_frame_b](address:8005@v1?hex)", inline=True)

        go()
    """)

    assert "rx_frame_b (&8005)" in output
    assert "@v1" not in output


def test_structured_json_preserves_markup(tmp_path):
    """Structured JSON emission keeps the Markdown-source link intact."""

    import json
    import os
    import subprocess
    import sys
    import textwrap

    rom_filepath = tmp_path / "test.rom"
    rom_filepath.write_bytes(b'\xea' * 16)
    out_filepath = tmp_path / "out.json"

    script = textwrap.dedent(f"""
        from py8dis.commands import *
        from py8dis import structured

        init()
        load(0x8000, "{rom_filepath}", "6502")

        entry(0x8000)
        comment(0x8000, "see [rx_frame_b](address:8005?hex)", inline=True)

        go()
        import json
        json.dump(structured.emit_structured(), open("{out_filepath}", "w"))
    """)
    script_filepath = tmp_path / "driver.py"
    script_filepath.write_text(script)

    py8dis_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    result = subprocess.run(
        [sys.executable, str(script_filepath)],
        capture_output=True, text=True, cwd=str(tmp_path),
        env={**os.environ, "PYTHONPATH": py8dis_root},
    )
    assert result.returncode == 0, f"stderr: {result.stderr}"

    data = json.loads(out_filepath.read_text())
    items_with_comment = [it for it in data["items"] if it.get("comment_inline")]
    assert len(items_with_comment) == 1
    # The JSON preserves the Markdown source so site-gen can resolve it.
    assert "[rx_frame_b](address:8005?hex)" in items_with_comment[0]["comment_inline"]


def test_subroutine_title_and_description_also_stripped(run_py8dis):
    """Subroutine titles/descriptions flow through the same comment path."""

    output = run_py8dis("""
        from py8dis.commands import *

        init()
        load(0x8000, "{rom_filepath}", "6502")

        entry(0x8000)
        subroutine(0x8000, "entry",
                   title="entry: hands off to [next](address:8005?hex)",
                   description="See [helper](address:8005).")

        go()
    """)

    # Title collapses with ?hex expansion
    assert "entry: hands off to next (&8005)" in output
    # Description collapses to label only
    assert "See helper." in output
    assert "address:" not in output


def test_backticks_stripped_from_label_in_asm(run_py8dis):
    """Backticks wrap the label in Markdown so HTML renderers apply
    <code> styling; they're meaningless inside an asm ; comment and
    should be stripped."""

    output = run_py8dis("""
        from py8dis.commands import *

        init()
        load(0x8000, "{rom_filepath}", "6502")

        entry(0x8000)
        comment(0x8000, "jumps to [`rx_frame_b`](address:8005?hex)", inline=True)

        go()
    """)

    assert "jumps to rx_frame_b (&8005)" in output
    assert "`" not in output.split("jumps to")[1].split("\n")[0]


def test_multiple_links_in_one_comment(run_py8dis):
    output = run_py8dis("""
        from py8dis.commands import *

        init()
        load(0x8000, "{rom_filepath}", "6502")

        entry(0x8000)
        comment(0x8000,
                "dispatch to [foo](address:8005?hex) or [bar](address:8008)",
                inline=True)

        go()
    """)

    assert "dispatch to foo (&8005) or bar" in output
