from . import utils
from . import config
from . import mainformatter
from . import markdown_asm
from .align import Align

class Annotation(object):
    """A raw string to add to the output."""

    def __init__(self, text, align=Align.INLINE, priority=None, auto_generated=False):
        if priority is None:
            priority = 0
        self.text = text
        self.priority = priority
        self.align = align
        self.auto_generated = auto_generated

    def as_string(self, binary_addr):
        return str(self.text)

    def __str__(self):
        return str(self.text)

    def __repr__(self) -> str:
        return self.__str__()

class Comment(Annotation):
    """A comment, either inline or standalone.

    Derives from the Annotation class."""

    def __init__(self, text, word_wrap=True, indent=0, align=Align.BEFORE_LABEL, priority=None, auto_generated=True):
        self.source_text = text

        def late_formatter():
            # `source_text` may contain Markdown (CommonMark + GFM
            # tables): paragraphs, lists, tables, fenced code,
            # inline code, emphasis, and our custom
            # [label](address:HEX[?hex]) links. Downstream
            # structured-JSON consumers (e.g. the site HTML
            # renderer) see `source_text` intact; the asm output is
            # plaintext so here we render Markdown -> plaintext with
            # paragraph wrap, ASCII list bullets, pipe-table layout,
            # fenced-code indents, and the `[label](...)`
            # collapse that `strip_address_uri_links` used to do.
            #
            # word_wrap=False signals "preserve my literal layout"
            # (used by subroutine-banner separators and by
            # formatted_comment() calls). There we skip structural
            # Markdown parsing -- it would otherwise turn a row of
            # asterisks into a thematic break, re-flow line breaks,
            # etc. -- and fall back to the single-regex URI stripper.
            prefix = config.get_indent_string() * indent \
                + config.get_assembler().comment_prefix() + " "
            inline = align == Align.INLINE
            if not word_wrap:
                strtext = utils.strip_address_uri_links(str(text))
            else:
                wrap_width = None if inline else max(
                    10,
                    config.get_word_wrap_comment_column() - len(prefix))
                strtext = markdown_asm.markdown_to_asm_text(
                    str(text), inline=inline, wrap_width=wrap_width)
            return "\n".join(prefix + line if line else prefix.rstrip()
                             for line in strtext.split("\n"))

        Annotation.__init__(self, utils.LazyString("%s", late_formatter), align=align, priority=priority, auto_generated=auto_generated)
