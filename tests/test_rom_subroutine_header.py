"""Tests for subroutine headers at ROM addresses within move blocks."""


# ROM: 8 bytes of relocatable code at &8000 (runs at &0D00),
# then 8 bytes of non-relocated code at &8008 that references it.
ROM_BYTES = bytes([
    0x48, 0xAD, 0x84, 0xFE, 0x29, 0x1F, 0x68, 0x40,  # &8000: pha, lda &fe84, and #&1f, pla, rti
    0x20, 0x00, 0x0D, 0xA9, 0x00, 0x8D, 0x00, 0x0D,  # &8008: jsr &0d00, lda #0, sta &0d00
])


def test_subroutine_at_rom_address_in_move_block(run_py8dis):
    """A subroutine() at a ROM address within a move range should produce
    a .label at the ROM position with a banner above it, not a constant
    at the runtime address."""

    output = run_py8dis("""
        from py8dis.commands import *

        init()
        load(0x8000, "{rom_filepath}", "6502")

        move_main = move(0x0D00, 0x8000, 8)
        with move_main:
            entry(0x0D00)

        entry(0x8008)

        label(0x0D00, "nmi_workspace")

        subroutine(0x8000, "my_handler_rom",
            title="My relocated handler",
            description="This code is copied to &0D00 at runtime.",
            at_binary_addr=True)

        go()
    """, rom_bytes=ROM_BYTES)

    # The label should appear as an inline .label at the ROM position,
    # NOT as a "my_handler_rom = &0d00" constant
    assert ".my_handler_rom" in output
    assert "my_handler_rom  = " not in output
    assert "my_handler_rom = " not in output

    # The subroutine banner should appear as a block comment above the label
    assert "My relocated handler" in output
    assert "This code is copied to" in output

    # The runtime label should still work
    assert ".nmi_workspace" in output


def test_subroutine_at_rom_address_no_runtime_label(run_py8dis):
    """Same scenario but without a separate runtime label — should still
    get a .label at ROM position."""

    output = run_py8dis("""
        from py8dis.commands import *

        init()
        load(0x8000, "{rom_filepath}", "6502")

        move_main = move(0x0D00, 0x8000, 8)
        with move_main:
            entry(0x0D00)

        entry(0x8008)

        subroutine(0x8000, "my_handler_rom",
            title="My relocated handler",
            at_binary_addr=True)

        go()
    """, rom_bytes=ROM_BYTES)

    assert ".my_handler_rom" in output
    assert "my_handler_rom  = " not in output
    assert "my_handler_rom = " not in output
    assert "My relocated handler" in output
