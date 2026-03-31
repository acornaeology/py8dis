"""Tests for structured JSON output with at_binary_addr subroutines."""

import json


# ROM: 8 bytes of relocatable code at &8000 (runs at &0D00),
# then 8 bytes of non-relocated code at &8008 that references it.
ROM_BYTES = bytes([
    0x48, 0xAD, 0x84, 0xFE, 0x29, 0x1F, 0x68, 0x40,  # &8000: pha, lda &fe84, and #&1f, pla, rti
    0x20, 0x00, 0x0D, 0xA9, 0x00, 0x8D, 0x00, 0x0D,  # &8008: jsr &0d00, lda #0, sta &0d00
])


def run_structured(run_py8dis):
    """Run the standard at_binary_addr test case and return parsed JSON."""
    output = run_py8dis("""
        import json
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

        go(print_output=False)
        data = get_structured()
        print(json.dumps(data))
    """, rom_bytes=ROM_BYTES)
    return json.loads(output)


def test_subroutine_addr_is_runtime_addr(run_py8dis):
    """at_binary_addr subroutine should have addr=runtime, binary_addr=ROM."""
    data = run_structured(run_py8dis)

    subs = data["subroutines"]
    handler_sub = [s for s in subs if s.get("name") == "my_handler_rom"]
    assert len(handler_sub) == 1, f"Expected 1 subroutine named my_handler_rom, got {handler_sub}"

    sub = handler_sub[0]
    # addr should be the runtime address (0x0D00 = 3328)
    assert sub["addr"] == 0x0D00, f"Expected addr=0x0D00, got {hex(sub['addr'])}"
    # binary_addr should be the ROM address (0x8000 = 32768)
    assert sub["binary_addr"] == 0x8000, f"Expected binary_addr=0x8000, got {hex(sub['binary_addr'])}"
    assert sub["title"] == "My relocated handler"


def test_rom_label_appears_in_item(run_py8dis):
    """Label placed at ROM address via at_binary_addr should appear in
    the item at the corresponding runtime address."""
    data = run_structured(run_py8dis)

    # Find the item at runtime address 0x0D00
    items_at_0d00 = [i for i in data["items"] if i["addr"] == 0x0D00]
    assert len(items_at_0d00) >= 1, "No item found at runtime address 0x0D00"

    item = items_at_0d00[0]
    labels = item.get("labels", [])
    assert "my_handler_rom" in labels, f"Expected my_handler_rom in labels, got {labels}"
    assert "nmi_workspace" in labels, f"Expected nmi_workspace in labels, got {labels}"
