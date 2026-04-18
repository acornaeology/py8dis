"""Tests for the memory-map metadata attached to label() calls."""

import json
import os
import subprocess
import sys
import textwrap


def _run(tmp_path, body, rom_bytes=b'\xea' * 16):
    """Run a py8dis driver script and return (asm_stdout, structured_json).

    `body` is the script body after `init()`+`load()` are handled; it
    receives a pre-opened ROM, the address 0x8000, and is expected to
    call `go()` and then serialise structured output to the path
    placeholder `{json_path}`.
    """
    rom_path = tmp_path / "test.rom"
    rom_path.write_bytes(rom_bytes)
    json_path = tmp_path / "out.json"

    script = (
        "from py8dis.commands import *\n"
        "from py8dis import structured\n"
        "import json as _json\n"
        "\n"
        "init()\n"
        f'load(0x8000, "{rom_path}", "6502")\n'
        "entry(0x8000)\n"
        "\n"
        + body + "\n"
        "\n"
        "go()\n"
        f'_json.dump(structured.emit_structured(), open("{json_path}", "w"))\n'
    )

    script_path = tmp_path / "driver.py"
    script_path.write_text(script)

    py8dis_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    result = subprocess.run(
        [sys.executable, str(script_path)],
        capture_output=True, text=True, cwd=str(tmp_path),
        env={**os.environ, "PYTHONPATH": py8dis_root},
    )
    assert result.returncode == 0, f"stderr: {result.stderr}"

    structured_data = json.loads(json_path.read_text())
    return result.stdout, structured_data


def test_bare_label_unchanged(tmp_path):
    """A label() call without metadata emits a plain equate and does
    NOT appear in memory_map."""

    body = 'label(0x0080, "workspace_byte")'
    asm, data = _run(tmp_path, body)

    # Equate exists (column-aligned, so use a loose match)
    found = False
    for line in asm.splitlines():
        if "workspace_byte" in line and "&0080" in line:
            found = True
            # No trailing ';' comment on the equate line
            assert ";" not in line, f"unexpected ';' on bare equate: {line!r}"
    assert found, "workspace_byte equate missing from asm"
    assert data["memory_map"] == []
    assert "workspace_byte" in data["external_labels"]


def test_full_kwargs_emit_to_memory_map_and_asm_brief(tmp_path):
    """A label() with description/length/group/access appears in
    memory_map with all fields, and the asm equate gains a trailing
    `;` brief (first paragraph of the description)."""

    body = (
        'label(0x0080, "mem_ptr_lo",\n'
        '      description="Low byte of the indirect pointer used by ram_test.\\n\\nExtended paragraph.",\n'
        '      length=1, group="zero_page", access="rw")\n'
    )
    asm, data = _run(tmp_path, body)

    # Asm: equate + trailing brief
    found_line = None
    for line in asm.splitlines():
        if "mem_ptr_lo" in line and "&0080" in line:
            found_line = line
            break
    assert found_line is not None
    assert "; Low byte of the indirect pointer used by ram_test." in found_line
    # Extended paragraph stays out of the asm brief
    assert "Extended paragraph" not in found_line

    # JSON: full entry
    assert len(data["memory_map"]) == 1
    entry = data["memory_map"][0]
    assert entry["addr"] == 0x0080
    assert entry["name"] == "mem_ptr_lo"
    assert entry["length"] == 1
    assert entry["group"] == "zero_page"
    assert entry["access"] == "rw"
    # Full description -- brief AND extended paragraph -- stays in JSON
    assert "Low byte of the indirect pointer" in entry["description"]
    assert "Extended paragraph" in entry["description"]
    # Plain-text brief (just the first paragraph, Markdown stripped) is
    # exposed alongside so site renderers can use it for tooltips.
    assert "Low byte of the indirect pointer" in entry["brief"]
    assert "Extended paragraph" not in entry["brief"]


def test_brief_strips_inline_markdown(tmp_path):
    """The `brief` field has backticks and address links collapsed to
    plain text, for use in HTML attributes like `data-tip`."""
    body = (
        'label(0x0080, "mem_ptr_lo",\n'
        '      description="Paired with [`mem_ptr_hi`](address:0081).",\n'
        '      length=1, group="zp", access="rw")\n'
    )
    _, data = _run(tmp_path, body)
    entry = data["memory_map"][0]
    assert entry["brief"] == "Paired with mem_ptr_hi."


def test_multi_byte_buffer_records_length(tmp_path):
    body = (
        'label(0x025A, "reachable_via_b",\n'
        '      description="256-byte routing table for side B.",\n'
        '      length=256, group="ram_buffers", access="rw")\n'
    )
    _, data = _run(tmp_path, body)
    assert len(data["memory_map"]) == 1
    assert data["memory_map"][0]["length"] == 256


def test_first_paragraph_used_as_brief(tmp_path):
    """Paragraph split is on the first blank line (Pandoc-style)."""
    body = (
        'label(0x0080, "mem_ptr_lo",\n'
        '      description="Brief first line.\\n\\nExtended paragraph stays only in JSON.",\n'
        '      length=1, group="zp", access="rw")\n'
    )
    asm, _ = _run(tmp_path, body)
    for line in asm.splitlines():
        if "mem_ptr_lo" in line and "&0080" in line:
            assert "; Brief first line." in line
            assert "Extended paragraph" not in line
            return
    raise AssertionError("mem_ptr_lo equate not found in asm")


def test_markdown_in_brief_collapses_to_plain_text(tmp_path):
    """Backticks + address URIs inside the brief render to plain text
    in the asm comment via the markdown_asm pipeline."""
    body = (
        'label(0x0080, "mem_ptr_lo",\n'
        '      description="Paired with [`mem_ptr_hi`](address:0081).",\n'
        '      length=1, group="zp", access="rw")\n'
    )
    asm, _ = _run(tmp_path, body)
    for line in asm.splitlines():
        if "mem_ptr_lo" in line and "&0080" in line:
            assert "Paired with mem_ptr_hi" in line
            # Backticks and link markup are stripped in asm
            assert "`" not in line.split(";")[1]
            assert "address:" not in line
            return
    raise AssertionError("mem_ptr_lo equate not found in asm")


def test_memory_map_entries_sorted_by_address(tmp_path):
    body = (
        'label(0xC800, "adlc_a_cr1", description="ADLC A control register 1.",'
        ' length=1, group="io_a", access="w")\n'
        'label(0x0080, "mem_ptr_lo", description="Indirect pointer low byte.",'
        ' length=1, group="zp", access="rw")\n'
        'label(0x025A, "reachable_via_b", description="Routing table.",'
        ' length=256, group="ram_buffers", access="rw")\n'
    )
    _, data = _run(tmp_path, body)
    addrs = [e["addr"] for e in data["memory_map"]]
    assert addrs == [0x0080, 0x025A, 0xC800]


def test_rom_range_label_is_not_in_memory_map(tmp_path):
    """Labels inside the loaded ROM range stay in `items`, not
    `memory_map`."""
    body = (
        'label(0x8000, "my_code",\n'
        '      description="This is code, not workspace.", group="code")\n'
    )
    _, data = _run(tmp_path, body)
    assert data["memory_map"] == []
