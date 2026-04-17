"""Tests for the fill() command and the Fill classification."""


def test_fill_emits_beebasm_for_loop(run_py8dis):
    """fill() on a run of &FF bytes emits a single FOR/NEXT line."""

    output = run_py8dis("""
        from py8dis.commands import *

        init()
        load(0x8000, "{rom_filepath}", "6502")

        entry(0x8000)
        fill(0x8001, 15)

        go()
    """, rom_bytes=b'\xea' + b'\xff' * 15)

    assert "for _py8dis_fill_n%, 1, 15 : equb &ff : next" in output
    # The driver's 15-byte fill should replace 15 bytes of equb output
    # with a single line.
    lines = [ln for ln in output.splitlines() if "equb &ff" in ln]
    assert len(lines) == 1


def test_fill_with_explicit_value_matches(run_py8dis):
    """Passing value= should succeed when it matches the binary."""

    output = run_py8dis("""
        from py8dis.commands import *

        init()
        load(0x8000, "{rom_filepath}", "6502")

        entry(0x8000)
        fill(0x8001, 15, value=0xff)

        go()
    """, rom_bytes=b'\xea' + b'\xff' * 15)

    assert "for _py8dis_fill_n%, 1, 15 : equb &ff : next" in output


def test_fill_with_wrong_value_fails(run_py8dis):
    """Passing value= that doesn't match the binary should raise."""

    import pytest

    with pytest.raises(AssertionError, match="py8dis script failed"):
        run_py8dis("""
            from py8dis.commands import *

            init()
            load(0x8000, "{rom_filepath}", "6502")

            entry(0x8000)
            fill(0x8001, 15, value=0x00)

            go()
        """, rom_bytes=b'\xea' + b'\xff' * 15)


def test_fill_with_varying_bytes_fails(run_py8dis):
    """fill() on a range containing >1 byte value should raise."""

    import pytest

    with pytest.raises(AssertionError, match="py8dis script failed"):
        run_py8dis("""
            from py8dis.commands import *

            init()
            load(0x8000, "{rom_filepath}", "6502")

            entry(0x8000)
            fill(0x8001, 15)

            go()
        """, rom_bytes=b'\xea' + b'\xff' * 7 + b'\x00' + b'\xff' * 7)


def test_fill_hex_dump_comment_appears(run_py8dis):
    """The fill line should include the starting address in the hex dump."""

    output = run_py8dis("""
        from py8dis.commands import *

        init()
        load(0x8000, "{rom_filepath}", "6502")

        entry(0x8000)
        fill(0x8001, 20)

        go()
    """, rom_bytes=b'\xea' + b'\xff' * 20)

    # The address-hex-dump suffix should show the starting binary address
    # of the fill block.
    for_line = [ln for ln in output.splitlines() if "for _py8dis_fill_n%" in ln][0]
    assert "8001:" in for_line
