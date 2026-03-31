"""Test that subroutine JSON includes binary_addr when move_id is used."""

import json

ROM_BYTES = b'\xea' * 16


def test_subroutine_with_move_id_has_binary_addr(run_py8dis):
    """subroutine() with move_id should populate binary_addr in JSON."""

    output = run_py8dis("""
        import json
        from py8dis.commands import *

        init()
        load(0x8000, "{rom_filepath}", "6502")

        move_a = move(0x0D0A, 0x8000, 8)

        with move_a:
            entry(0x0D0A)

        subroutine(0x0D0A, "my_sub", title="My sub", move_id=move_a)

        go(print_output=False)
        data = get_structured()
        print(json.dumps(data))
    """, rom_bytes=ROM_BYTES)

    data = json.loads(output)
    subs = data["subroutines"]
    my_sub = [s for s in subs if s.get("name") == "my_sub"]
    assert len(my_sub) == 1

    sub = my_sub[0]
    assert sub["addr"] == 0x0D0A
    assert sub["binary_addr"] == 0x8000, f"Expected binary_addr=0x8000, got {sub.get('binary_addr')}"


def test_subroutine_without_move_has_no_binary_addr(run_py8dis):
    """subroutine() without move_id at an unmoved address should not
    have binary_addr (since it would equal addr)."""

    output = run_py8dis("""
        import json
        from py8dis.commands import *

        init()
        load(0x8000, "{rom_filepath}", "6502")

        entry(0x8000)
        subroutine(0x8000, "plain_sub", title="Plain sub")

        go(print_output=False)
        data = get_structured()
        print(json.dumps(data))
    """, rom_bytes=ROM_BYTES)

    data = json.loads(output)
    subs = data["subroutines"]
    plain = [s for s in subs if s.get("name") == "plain_sub"]
    assert len(plain) == 1
    assert "binary_addr" not in plain[0]
