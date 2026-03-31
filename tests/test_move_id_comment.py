"""Tests for move_id parameter on comment(), formatted_comment(), and subroutine()."""


def test_comment_with_move_id_on_overlapping_moves(run_py8dis):
    """comment() with explicit move_id should resolve ambiguous addresses."""

    output = run_py8dis("""
        from py8dis.commands import *

        init()
        load(0x8000, "{rom_filepath}", "6502")

        move_a = move(0x0D0A, 0x8000, 8)
        move_b = move(0x0D0A, 0x8008, 8)

        with move_a:
            entry(0x0D0A)

        with move_b:
            entry(0x0D0A)

        comment(0x0D0A, "Comment for move_a", inline=True, move_id=move_a)
        comment(0x0D0A, "Comment for move_b", inline=True, move_id=move_b)

        go()
    """)

    assert "Comment for move_a" in output
    assert "Comment for move_b" in output


def test_formatted_comment_with_move_id(run_py8dis):
    """formatted_comment() with explicit move_id should resolve ambiguous addresses."""

    output = run_py8dis("""
        from py8dis.commands import *

        init()
        load(0x8000, "{rom_filepath}", "6502")

        move_a = move(0x0D0A, 0x8000, 8)
        move_b = move(0x0D0A, 0x8008, 8)

        with move_a:
            entry(0x0D0A)

        with move_b:
            entry(0x0D0A)

        formatted_comment(0x0D0A, "Formatted for A", move_id=move_a)
        formatted_comment(0x0D0A, "Formatted for B", move_id=move_b)

        go()
    """)

    assert "Formatted for A" in output
    assert "Formatted for B" in output


def test_subroutine_with_move_id_on_overlapping_moves(run_py8dis):
    """subroutine() with explicit move_id should resolve ambiguous addresses."""

    output = run_py8dis("""
        from py8dis.commands import *

        init()
        load(0x8000, "{rom_filepath}", "6502")

        move_a = move(0x0D0A, 0x8000, 8)
        move_b = move(0x0D0A, 0x8008, 8)

        with move_a:
            entry(0x0D0A)

        with move_b:
            entry(0x0D0A)

        subroutine(0x0D0A, "sub_a", title="Subroutine A", move_id=move_a)
        subroutine(0x0D0A, "sub_b", title="Subroutine B", move_id=move_b)

        go()
    """)

    assert "sub_a" in output
    assert "sub_b" in output
    assert "Subroutine A" in output
    assert "Subroutine B" in output


def test_comment_without_move_id_still_works(run_py8dis):
    """comment() without move_id should work when the address is unambiguous."""

    output = run_py8dis("""
        from py8dis.commands import *

        init()
        load(0x8000, "{rom_filepath}", "6502")

        entry(0x8000)
        comment(0x8000, "Simple comment", inline=True)

        go()
    """)

    assert "Simple comment" in output


def test_four_overlapping_moves(run_py8dis):
    """Simulate the ADFS scenario: 4 moves overlapping at the same runtime address."""

    output = run_py8dis("""
        from py8dis.commands import *

        init()
        load(0x8000, "{rom_filepath}", "6502")

        # Main block: 16 bytes copied to &0D00
        move_main  = move(0x0D00, 0x8000, 16)

        # Three patch variants overlapping at &0D0A
        move_write = move(0x0D0A, 0x8010, 6)
        move_tw    = move(0x0D0A, 0x8016, 6)
        move_tr    = move(0x0D0A, 0x801C, 6)

        with move_main:
            entry(0x0D00)

        with move_write:
            entry(0x0D0A)

        with move_tw:
            entry(0x0D0A)

        with move_tr:
            entry(0x0D0A)

        comment(0x0D0A, "Write patch", inline=True, move_id=move_write)
        comment(0x0D0A, "TW patch", inline=True, move_id=move_tw)
        comment(0x0D0A, "TR patch", inline=True, move_id=move_tr)

        subroutine(0x0D0A, "nmi_write", title="NMI write handler", move_id=move_write)
        subroutine(0x0D0A, "nmi_tw", title="NMI tube write", move_id=move_tw)
        subroutine(0x0D0A, "nmi_tr", title="NMI tube read", move_id=move_tr)

        go()
    """, rom_bytes=b'\xea' * 48)

    assert "Write patch" in output
    assert "TW patch" in output
    assert "TR patch" in output
    assert "nmi_write" in output
    assert "nmi_tw" in output
    assert "nmi_tr" in output
    assert "NMI write handler" in output
    assert "NMI tube write" in output
    assert "NMI tube read" in output


def test_comment_without_move_id_fails_on_ambiguous_address(run_py8dis):
    """comment() without move_id should fail when the address is ambiguous."""

    import subprocess
    import pytest

    with pytest.raises(AssertionError, match="py8dis script failed"):
        run_py8dis("""
            from py8dis.commands import *

            init()
            load(0x8000, "{rom_filepath}", "6502")

            move_a = move(0x0D0A, 0x8000, 8)
            move_b = move(0x0D0A, 0x8008, 8)

            with move_a:
                entry(0x0D0A)

            comment(0x0D0A, "This should fail")

            go()
        """)
