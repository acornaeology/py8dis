"""Tests for data_banner() — subroutine-style headers on data regions.

A normal `subroutine()` registers an entry point and traces from the
address. For data regions (`byte()` / `word()` / `string*()` runs)
that's wrong: py8dis would decode the bytes as opcodes, often leading
to spurious or conflicting classifications elsewhere. `data_banner()`
emits the same `* * *`-bordered header block but skips the trace-entry
registration.
"""


# Code at &8000 reads from a 4-byte data table at &8005. The table
# bytes happen to also decode as opcodes (`A9 00 8D 00`,
# i.e. `LDA #&00 / STA &??00`); if data_banner() accidentally
# registered the table as a code entry, py8dis would trace those
# bytes and disagree with the byte() classification.
ROM_BYTES = bytes([
    0xBD, 0x05, 0x80,              # &8000: lda my_table,X     (forces label reference)
    0x60,                          # &8003: rts
    0xEA,                          # &8004: nop (padding)
    0xA9, 0x00, 0x8D, 0x00,        # &8005-&8008: data table
])


def test_data_banner_emits_header_without_tracing(run_py8dis):
    """data_banner() should emit a banner header at the address but
    NOT register a code-entry, leaving the data classification intact."""

    output = run_py8dis("""
        from py8dis.commands import *

        init()
        load(0x8000, "{rom_filepath}", "6502")

        entry(0x8000)

        # Mark &8005..&8008 as four data bytes.
        for i in range(4):
            byte(0x8005 + i)

        data_banner(0x8005, "my_table",
            title="Four-byte demonstration table",
            description="Four bytes of test data; not code.")

        go()
    """, rom_bytes=ROM_BYTES)

    # The banner appears in the output.
    assert "Four-byte demonstration table" in output
    assert "Four bytes of test data; not code." in output

    # The label is placed at the data address (visible because the
    # LDA at &8000 references it).
    assert ".my_table" in output

    # The bytes stay classified as data (equb), not code (lda/sta).
    # Look at the line for &8005 specifically.
    lines = output.splitlines()
    body = [line for line in lines if "8005:" in line]
    assert body, f"no &8005 line in output:\n{output}"
    assert "equb" in body[0], (
        f"expected &8005 to be equb (data), got: {body[0]!r}\n"
        "If this is `lda #&00`, data_banner() is wrongly tracing from &8005."
    )


def test_data_banner_rejects_on_entry_kwarg(run_py8dis):
    """data_banner() takes the data-banner subset of subroutine()'s
    parameters; on_entry / on_exit / hook are not accepted."""

    output = run_py8dis("""
        from py8dis.commands import *

        init()
        load(0x8000, "{rom_filepath}", "6502")
        entry(0x8000)
        for i in range(4):
            byte(0x8005 + i)

        try:
            data_banner(0x8005, "x", on_entry={"a": "test"})
            print("ERROR: should have raised")
        except TypeError as e:
            print(f"raised: {e}")

        go()
    """, rom_bytes=ROM_BYTES)

    assert "raised: data_banner() got an unexpected keyword" in output
