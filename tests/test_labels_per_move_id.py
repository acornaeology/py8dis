"""Test that structured JSON items only get labels for their own move_id."""

import json

ROM_BYTES = b'\xea' * 48


def test_overlapping_moves_get_distinct_labels(run_py8dis):
    """Each item at an overlapping runtime address should only have
    the label for its own move block, not labels from other moves."""

    output = run_py8dis("""
        import json
        from py8dis.commands import *

        init()
        load(0x8000, "{rom_filepath}", "6502")

        move_a = move(0x0D0A, 0x8000, 8)
        move_b = move(0x0D0A, 0x8008, 8)
        move_c = move(0x0D0A, 0x8010, 8)

        with move_a:
            entry(0x0D0A)
            label(0x0D0A, "label_a")

        with move_b:
            entry(0x0D0A)
            label(0x0D0A, "label_b")

        with move_c:
            entry(0x0D0A)
            label(0x0D0A, "label_c")

        go(print_output=False)
        data = get_structured()
        print(json.dumps(data))
    """, rom_bytes=ROM_BYTES)

    data = json.loads(output)

    # Find items at runtime address 0x0D0A
    items_0d0a = [i for i in data["items"] if i["addr"] == 0x0D0A]
    assert len(items_0d0a) == 3, f"Expected 3 items at 0x0D0A, got {len(items_0d0a)}"

    # Each item should have its own label (not labels from other moves).
    # The first item may also have pydis_start (a BASE_MOVE_ID label at
    # the start of the binary).
    labels_by_binary = {
        item.get("binary_addr", item["addr"]): item.get("labels", [])
        for item in items_0d0a
    }
    assert "label_a" in labels_by_binary[0x8000]
    assert "label_b" not in labels_by_binary[0x8000]
    assert "label_c" not in labels_by_binary[0x8000]

    assert "label_b" in labels_by_binary[0x8008]
    assert "label_a" not in labels_by_binary[0x8008]
    assert "label_c" not in labels_by_binary[0x8008]

    assert "label_c" in labels_by_binary[0x8010]
    assert "label_a" not in labels_by_binary[0x8010]
    assert "label_b" not in labels_by_binary[0x8010]
