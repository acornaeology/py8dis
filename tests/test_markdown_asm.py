"""Tests for the Markdown-to-asm-text renderer used by Comment's asm output."""

from py8dis.markdown_asm import markdown_to_asm_text


def test_plain_prose_unchanged():
    """A plain paragraph with no Markdown survives verbatim."""

    src = "Read byte 0 (rx_dst_stn) from the ADLC FIFO."
    assert markdown_to_asm_text(src).strip() == src


def test_multiple_paragraphs_separated_by_blank_lines():
    src = "First paragraph.\n\nSecond paragraph."
    out = markdown_to_asm_text(src).strip()
    assert out == "First paragraph.\n\nSecond paragraph."


def test_emphasis_markers_stripped():
    src = "This is **bold** and *italic* and `code` text."
    out = markdown_to_asm_text(src).strip()
    assert out == "This is bold and italic and code text."


def test_inline_code_backticks_stripped():
    src = "Write `&82` into `CR1`."
    out = markdown_to_asm_text(src).strip()
    assert out == "Write &82 into CR1."


def test_backslash_escape_unescapes():
    # mistletoe resolves \* to a literal * at tokenisation time.
    src = r"The \*HELP command is handled in MOS."
    out = markdown_to_asm_text(src).strip()
    assert out == "The *HELP command is handled in MOS."


def test_unordered_list_renders_with_dashes():
    src = "- first item\n- second item\n- third item"
    out = markdown_to_asm_text(src).strip()
    assert out == "- first item\n- second item\n- third item"


def test_ordered_list_renders_with_numbers():
    src = "1. first\n2. second\n3. third"
    out = markdown_to_asm_text(src).strip()
    assert out == "1. first\n2. second\n3. third"


def test_ordered_list_wraps_with_continuation_indent():
    """Wrapped content in a list item should line up under the first letter."""

    src = "1. This is a fairly long item that needs wrapping across multiple lines."
    out = markdown_to_asm_text(src, wrap_width=40).strip()
    lines = out.split("\n")
    assert lines[0].startswith("1. ")
    for cont in lines[1:]:
        assert cont.startswith("   ")  # 3 spaces = len("1. ")


def test_fenced_code_block_preserves_content():
    src = "```6502\n    lda #0\n    rts\n```"
    out = markdown_to_asm_text(src).strip()
    assert "[6502]" in out
    assert "    lda #0" in out
    assert "    rts" in out


def test_table_renders_as_pipe_table():
    src = (
        "| ctrl | handler | role |\n"
        "|------|---------|------|\n"
        "| &80  | hnd80   | init |\n"
        "| &81  | hnd81   | re-a |"
    )
    out = markdown_to_asm_text(src).strip()
    lines = out.split("\n")
    assert lines[0].startswith("|") and lines[0].count("|") == 4
    # Separator row
    assert set(lines[1]) <= set("|-")
    # Cells should be padded to column width
    assert "hnd80" in lines[2]
    assert "hnd81" in lines[3]


def test_address_uri_link_collapses_to_label():
    src = "see [rx_frame_b](address:E263) for details"
    out = markdown_to_asm_text(src).strip()
    assert out == "see rx_frame_b for details"


def test_address_uri_hex_flag_appends_hex():
    src = "see [rx_frame_b](address:E263?hex) for details"
    out = markdown_to_asm_text(src).strip()
    assert out == "see rx_frame_b (&E263) for details"


def test_address_uri_with_backticked_label():
    src = "see [`rx_frame_b`](address:E263?hex) for details"
    out = markdown_to_asm_text(src).strip()
    assert out == "see rx_frame_b (&E263) for details"


def test_external_link_collapses_to_label():
    src = "see [docs](https://example.com/rx_frame_b) for details"
    out = markdown_to_asm_text(src).strip()
    assert out == "see docs for details"


def test_inline_collapses_to_single_line():
    src = "a paragraph\nwith two\nvisible newlines"
    out = markdown_to_asm_text(src, inline=True)
    assert "\n" not in out
    # Whitespace may collapse differently, just check the words survive.
    assert "a paragraph" in out
    assert "visible newlines" in out


def test_inline_strips_everything_to_one_line():
    src = "**bold** and *italic* and [`foo`](address:E051?hex) ready"
    out = markdown_to_asm_text(src, inline=True)
    assert out == "bold and italic and foo (&E051) ready"


def test_paragraph_word_wrapping():
    """Prose paragraphs wrap at wrap_width; structural blocks don't."""
    long = "word " * 30
    out = markdown_to_asm_text(long, wrap_width=40)
    for line in out.split("\n"):
        assert len(line) <= 40, f"line exceeds width: {line!r}"


def test_table_not_word_wrapped():
    """A wide table's row-lines should survive even when wrap_width is small."""
    src = (
        "| a very long column header | another very long header |\n"
        "|---------------------------|--------------------------|\n"
        "| c1                        | c2                       |"
    )
    out = markdown_to_asm_text(src, wrap_width=40)
    # No table row line should be broken.
    lines = [ln for ln in out.split("\n") if ln.strip().startswith("|")]
    assert len(lines) == 3
    # Each row keeps its full structure
    for ln in lines:
        assert ln.count("|") == 3


def test_heading_becomes_plain_line():
    src = "# Section\n\nBody text."
    out = markdown_to_asm_text(src).strip()
    assert out == "Section\n\nBody text."


def test_thematic_break_becomes_dashes():
    src = "above\n\n---\n\nbelow"
    out = markdown_to_asm_text(src).strip()
    assert "----" in out


def test_blockquote_prefixes_lines_with_gt():
    # CommonMark joins consecutive quoted lines into one paragraph;
    # our renderer emits that one paragraph with a `> ` prefix. When
    # wrapped, each wrapped continuation line gets its own prefix.
    src = "> a quoted line that is long enough to wrap across two lines"
    out = markdown_to_asm_text(src, wrap_width=30).strip()
    for line in out.split("\n"):
        assert line.startswith(">"), f"line missing blockquote prefix: {line!r}"


def test_legacy_bridge_rx_frame_a_prose_parses_sensibly():
    """The existing indented-prose style in bridge subroutine descriptions
    should round-trip to plain paragraphs, not stay trapped in <pre>."""

    src = (
        "Reached from main_loop_poll when ADLC A raises SR1 bit 7.\n\n"
        "Filtering stage 1 — addressing:\n\n"
        "  Expect SR2 bit 0 (AP: Address Present) -- if missing, bail to\n"
        "  main_loop (spurious IRQ).\n"
    )
    out = markdown_to_asm_text(src, wrap_width=80).strip()
    assert "Reached from main_loop_poll" in out
    assert "Filtering stage 1" in out
    assert "AP: Address Present" in out
    # The output should not have big runs of indentation left over.
    assert not out.startswith("  ")
