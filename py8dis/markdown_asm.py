"""Render Markdown from py8dis comments as plaintext for asm output.

The driver author writes full CommonMark (plus GFM tables) in
comment(), subroutine() title, and subroutine() description. This
module converts that source to the plaintext that will end up inside
a ";" comment in the beebasm listing. The assembler doesn't care
about Markdown, and a reader scanning the asm doesn't want to wade
through backticks and emphasis markers, so:

  - paragraphs are word-wrapped to a configurable width,
  - lists carry plain-text bullets (- or "N.") with proper
    continuation indents,
  - tables render as pipe tables with padded columns,
  - fenced code blocks are preserved verbatim, indented four spaces
    and prefixed with a "[language]" tag if one was declared,
  - emphasis, strong, strikethrough, and inline-code markers are
    stripped,
  - the custom `[label](address:HEX[?hex])` link markup collapses
    to `label` or `label (&HEX)` depending on the `?hex` flag,
  - ordinary Markdown links collapse to their label text.

The structured-JSON path keeps the Markdown source intact so that
downstream HTML renderers can resolve it to anchors; this module is
only the asm-side stripper.
"""

import re
import textwrap

import mistletoe
from mistletoe.base_renderer import BaseRenderer


# Match the `[label](address:HEX[@version][?flag])` URI shape used
# everywhere in the acornaeology driver scripts.
_ADDRESS_URI_TARGET_RE = re.compile(
    r'^address:'
    r'(?P<hex>[0-9A-Fa-f]{4,})'
    r'(?:@[^?]+)?'
    r'(?:\?(?P<flag>[^&]*))?'
    r'$',
    re.IGNORECASE,
)


class AsmTextRenderer(BaseRenderer):
    """Render a mistletoe `Document` as plaintext suitable for an asm
    comment block.

    Attributes:
        wrap_width: word-wrap column for prose paragraphs and list
            items. `None` disables wrapping. Tables, code fences, and
            inline-rendered output ignore this.
        inline: when `True`, render the document as a single-line
            string by collapsing all newlines to spaces at the end.
    """

    def __init__(self, wrap_width=None, inline=False):
        super().__init__()
        self.wrap_width = wrap_width
        self.inline = inline
        # Indentation applied to continuation lines inside nested lists.
        self._indent = ""
        # Running marker stack for ordered lists so `render_list_item`
        # knows which counter to emit.
        self._list_markers = []

    # ------------------------------------------------------------------
    # Document entry point
    # ------------------------------------------------------------------

    def render_document(self, token):
        text = self.render_inner(token).rstrip("\n")
        if self.inline:
            # Collapse all whitespace into single spaces so an inline
            # comment fits on one line.
            text = re.sub(r"\s+", " ", text).strip()
        return text

    # ------------------------------------------------------------------
    # Block tokens
    # ------------------------------------------------------------------

    def render_paragraph(self, token):
        text = self.render_inner(token)
        if self.wrap_width and not self.inline:
            text = textwrap.fill(text, width=self.wrap_width,
                                 break_long_words=False,
                                 break_on_hyphens=False)
        return text + "\n\n"

    def render_heading(self, token):
        # No # markers in asm -- just emit the heading text on its own
        # line with a blank line after. It reads like an ordinary
        # paragraph, which in a ; comment context is the right thing.
        text = self.render_inner(token)
        return text + "\n\n"

    def render_quote(self, token):
        inner = self.render_inner(token).rstrip("\n")
        quoted = "\n".join("> " + line if line else ">"
                           for line in inner.split("\n"))
        return quoted + "\n\n"

    def render_thematic_break(self, token):
        return "----\n\n"

    def render_list(self, token):
        # token.start is None for unordered, or the starting number
        # (usually 1) for ordered.
        start = getattr(token, "start", None)
        if start is None:
            self._list_markers.append(("unordered", None))
        else:
            self._list_markers.append(("ordered", start))
        try:
            inner = self.render_inner(token).rstrip("\n")
        finally:
            self._list_markers.pop()
        # Blank line after each list, but merge into surrounding
        # rstrip at document end.
        return inner + "\n\n"

    def render_list_item(self, token):
        kind, counter = self._list_markers[-1]
        if kind == "ordered":
            marker = f"{counter}. "
            # Advance counter for the next sibling
            self._list_markers[-1] = ("ordered", counter + 1)
        else:
            marker = "- "
        # Compose the item's body. Items may contain multiple block
        # children (paragraphs, nested lists, code blocks). Render
        # them and indent continuation lines under the marker.
        outer_indent = self._indent
        marker_indent = outer_indent + " " * len(marker)
        self._indent = marker_indent
        try:
            body = self.render_inner(token).rstrip("\n")
        finally:
            self._indent = outer_indent

        if not body:
            return outer_indent + marker + "\n"

        # Word-wrap each paragraph-ish segment in the body with the
        # appropriate initial + subsequent indents. The marker itself
        # goes on the first line of the first paragraph; everything
        # else lines up under `marker_indent`.
        wrapped_paragraphs = []
        first = True
        for para in _split_paragraphs(body):
            if self.wrap_width and _should_wrap(para):
                init = (outer_indent + marker) if first else marker_indent
                wrapped = textwrap.fill(
                    para, width=self.wrap_width,
                    initial_indent=init, subsequent_indent=marker_indent,
                    break_long_words=False, break_on_hyphens=False)
                wrapped_paragraphs.append(wrapped)
            else:
                # Non-wrapping content (tables, code) -- prefix each
                # line with the appropriate indent.
                lines = para.split("\n")
                out_lines = []
                for i, line in enumerate(lines):
                    prefix = (outer_indent + marker) if (first and i == 0) \
                        else marker_indent
                    out_lines.append(prefix + line if line else "")
                wrapped_paragraphs.append("\n".join(out_lines))
            first = False

        return "\n\n".join(wrapped_paragraphs) + "\n"

    def render_table(self, token):
        # Collect cells as plain strings so we can compute column widths.
        header = token.header
        header_cells = [self._render_cell(c) for c in header.children]
        body_rows = []
        for row in token.children:
            body_rows.append([self._render_cell(c) for c in row.children])

        col_count = len(header_cells)
        widths = [len(h) for h in header_cells]
        for row in body_rows:
            for i, cell in enumerate(row):
                if i < col_count:
                    widths[i] = max(widths[i], len(cell))

        def format_row(cells):
            padded = [cells[i].ljust(widths[i])
                      if i < len(cells) else " " * widths[i]
                      for i in range(col_count)]
            return "| " + " | ".join(padded) + " |"

        sep = "|" + "|".join("-" * (w + 2) for w in widths) + "|"
        lines = [format_row(header_cells), sep]
        for row in body_rows:
            lines.append(format_row(row))
        return "\n".join(lines) + "\n\n"

    def render_table_row(self, token):
        # Unused: render_table walks children directly so cells can be
        # column-aligned.
        return ""

    def render_table_cell(self, token):
        return self._render_cell(token)

    def _render_cell(self, token):
        return self.render_inner(token).strip()

    def render_block_code(self, token):
        # BlockCode (indented) and CodeFence both arrive here. Emit
        # contents indented by four spaces, with a "[lang]" banner on
        # its own line if a language was declared.
        content = getattr(token, "content", None)
        if content is None:
            # Fallback: pull text from children.
            content = "".join(getattr(c, "content", "") for c in token.children)
        content = content.rstrip("\n")
        language = getattr(token, "language", "") or ""
        body_lines = ["    " + line if line else "" for line in content.split("\n")]
        out = "\n".join(body_lines)
        if language:
            out = f"[{language}]\n" + out
        return out + "\n\n"

    # ------------------------------------------------------------------
    # Span tokens
    # ------------------------------------------------------------------

    def render_strong(self, token):
        return self.render_inner(token)

    def render_emphasis(self, token):
        return self.render_inner(token)

    def render_strikethrough(self, token):
        return self.render_inner(token)

    def render_inline_code(self, token):
        return self.render_inner(token)

    def render_line_break(self, token):
        return "\n" if not getattr(token, "soft", False) else " "

    def render_raw_text(self, token):
        return token.content

    def render_escape_sequence(self, token):
        # mistletoe represents \x as an EscapeSequence with one child
        # RawText holding the literal character.
        return self.render_inner(token)

    def render_link(self, token):
        label = self.render_inner(token)
        target = getattr(token, "target", "") or ""
        match = _ADDRESS_URI_TARGET_RE.match(target)
        if match:
            flag = (match.group("flag") or "").lower()
            hex_str = match.group("hex")
            if flag == "hex":
                return f"{label} (&{hex_str.upper()})"
            return label
        # Ordinary URLs: just drop the URL, keep the label. The asm is
        # a ; comment, not a hypertext surface.
        return label

    def render_auto_link(self, token):
        return getattr(token, "target", self.render_inner(token))

    def render_image(self, token):
        # No way to render an image in a ; comment. Fall back to the
        # alt text.
        return self.render_inner(token)


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------

def _split_paragraphs(text):
    """Split a block of rendered text into paragraphs separated by
    one or more blank lines, returning a list of paragraph strings
    with no trailing/leading blank lines."""
    out = []
    current = []
    for line in text.split("\n"):
        if line.strip() == "":
            if current:
                out.append("\n".join(current))
                current = []
        else:
            current.append(line)
    if current:
        out.append("\n".join(current))
    return out


def _should_wrap(paragraph):
    """Heuristic: prose paragraphs wrap; structural blocks don't.

    Tables (pipe-starting lines) and indented code blocks are left
    alone so their layout survives. Anything else is treated as prose
    for textwrap purposes.
    """
    first = paragraph.lstrip().splitlines()[0] if paragraph else ""
    if first.startswith("|") or first.startswith("    ") or first.startswith("["):
        # "[lang]" banner or indented-code continuation
        return False
    return True


# ----------------------------------------------------------------------
# Public API
# ----------------------------------------------------------------------

def markdown_to_asm_text(text, *, inline=False, wrap_width=None):
    """Render `text` (CommonMark + GFM tables) as plaintext for asm.

    - `inline=True` collapses the rendered output to a single line,
      suitable for an inline `;` comment on the right of an
      instruction.
    - `wrap_width=N` wraps prose paragraphs and list items at column
      N (roughly). Tables and code fences are laid out structurally
      and ignore the wrap.

    Returns the plaintext with paragraphs separated by blank lines
    and no trailing newline.
    """
    with AsmTextRenderer(wrap_width=wrap_width, inline=inline) as renderer:
        doc = mistletoe.Document(text)
        return renderer.render(doc)
