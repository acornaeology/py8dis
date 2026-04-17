"""
Assembler base class
"""

class Assembler(object):
    """The base assembler class. Classes representing particular assemblers such
    as acme, beebasm etc are derived from this class."""

    # 6502 assemblers vary in whether they output 'ROL A' or just 'ROL'. The
    # 'explicit_a' variable indicates whether the 'A' suffix should be output
    # for instructions with an implicit accumulator.
    explicit_a = False

    # At the end of the assembly output, py8dis also outputs a list of
    # assertions about the values of variables. This acts as a check that py8dis
    # is producing valid output in situations where it cannot otherwise easily
    # tell. This helps make sure that the output will byte-for-byte correspond
    # with the original binary.
    #
    # 'pending_assertions' is a dictionary holding the assertions as key-value
    # pairs.
    pending_assertions = {}

    # 'output_filename': Some assemblers (e.g. beebasm and acme) can save the
    # resulting binary to a specific filepath if specified.
    output_filename = None

    def set_output_filename(self, filename):
        self.output_filename = filename

    def assert_expr(self, expr, value):
        self.pending_assertions[expr] = value

    def fill_directive(self, value, length):
        """Emit `length` copies of a single byte `value`.

        Returns a list of assembler-source lines (without the leading
        indent or the inline hex-dump comment). Subclasses should
        override to emit the assembler's most compact fill idiom while
        still producing byte-identical output when reassembled.

        The default implementation falls back to repeated byte
        directives (one `byte_prefix()` line containing the value
        repeated `length` times), which is correct but not compact.
        """
        prefix = self.byte_prefix()
        value_str = self.hex2(value)
        return [prefix + ", ".join([value_str] * length)]
