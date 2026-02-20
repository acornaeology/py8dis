"""Structured data export for py8dis disassembly results.

Produces a JSON-serialisable dictionary containing the complete
disassembly data with semantic structure preserved, suitable for
rendering into HTML or other formats.

Must be called after go() has completed tracing, classification,
label resolution and emission.
"""

from . import classification
from .classification import INSIDE_A_CLASSIFICATION
from . import config
from . import disassembly
from . import labelmanager
from . import memorymanager
from . import movemanager
from . import trace
from . import utils
from .align import Align
from .comment import Comment
from .movemanager import BinaryLocation
from .memorymanager import BinaryAddr, RuntimeAddr


def emit_structured():
    """Extract structured disassembly data.

    Returns a JSON-serialisable dictionary with keys:
        meta            - load address, end address
        constants       - named constant definitions
        subroutines     - subroutine metadata (name, description, etc.)
        external_labels - labels outside the loaded binary range
        items           - ordered list of classified entries
    """
    return {
        "meta": _build_meta(),
        "constants": _build_constants(),
        "subroutines": _build_subroutines(),
        "external_labels": _build_external_labels(),
        "items": _build_items(),
    }


def _build_meta():
    start, end = memorymanager.get_entire_load_range()
    return {
        "load_addr": int(start),
        "end_addr": int(end),
    }


def _build_constants():
    result = []
    for c in disassembly.constants:
        entry = {"name": c.name, "value": c.value}
        if c.comment:
            entry["comment"] = c.comment
        result.append(entry)
    return result


def _build_subroutines():
    result = []
    for sub in trace.subroutines_list:
        entry = {"addr": int(sub.runtime_addr)}
        if sub.label_name:
            entry["name"] = sub.label_name
        if sub.title:
            entry["title"] = sub.title
        if sub.description:
            entry["description"] = sub.description
        if sub.on_entry:
            entry["on_entry"] = dict(sub.on_entry)
        if sub.on_exit:
            entry["on_exit"] = dict(sub.on_exit)
        result.append(entry)
    return result


def _build_external_labels():
    """Build a dict of labels defined outside the loaded binary range.

    These are labels for OS entry points, zero-page variables, etc.
    that are referenced by the disassembled code but not part of the
    binary itself. Maps label name -> runtime address.
    """
    result = {}
    for runtime_addr in sorted(labelmanager.labels):
        label = labelmanager.labels[runtime_addr]
        binary_addr, _ = movemanager.r2b(runtime_addr)
        if binary_addr is not None and memorymanager.is_data_loaded_at_binary_addr(binary_addr):
            continue
        name = label.get_already_emitted_name()
        if name:
            result[name] = int(runtime_addr)
    return result


def _get_labels_at(runtime_addr):
    """Get all emitted label names at a runtime address."""
    if runtime_addr not in labelmanager.labels:
        return []
    label = labelmanager.labels[runtime_addr]
    names = []
    for name_list in label.explicit_names.values():
        for name in name_list:
            if name.emitted:
                names.append(name.text)
    return names


def _get_references_to(runtime_addr):
    """Get runtime addresses that reference this address."""
    if runtime_addr not in labelmanager.labels:
        return []
    refs = []
    for ref_loc in labelmanager.labels[runtime_addr].references:
        ref_runtime = movemanager.b2r(ref_loc.binary_addr)
        refs.append(int(ref_runtime))
    return refs


def _get_annotations(binary_addr, move_id, length):
    """Extract comments/annotations for a classification.

    Returns (comments_before, comment_inline, comments_after) where
    each is a list of strings (or a single string for inline).
    """
    comments_before = []
    comment_inline = None
    comments_after = []

    for i in range(length):
        binary_loc = BinaryLocation(binary_addr + i, move_id)
        for annotation in utils.sorted_annotations(disassembly.annotations[binary_loc]):
            # Extract raw text
            if isinstance(annotation, Comment):
                text = str(annotation.source_text)
            else:
                text = str(annotation.text)

            if not text:
                continue

            if annotation.align in (Align.BEFORE_LABEL, Align.BEFORE_LINE):
                comments_before.append(text)
            elif annotation.align == Align.INLINE:
                if comment_inline is None:
                    comment_inline = text
                else:
                    comment_inline += " " + text
            elif annotation.align in (Align.AFTER_LABEL, Align.AFTER_LINE):
                comments_after.append(text)

    return comments_before, comment_inline, comments_after


def _extract_operand(opcode, binary_addr):
    """Extract the operand text from an opcode's formatted output.

    Strips the indentation and mnemonic prefix, and removes any
    trailing inline character literal comment.
    """
    if opcode.operand_length == 0:
        return None

    full_text = str(opcode.as_string(binary_addr)).strip()
    mnemonic = utils.force_case(opcode.mnemonic)

    if not full_text.startswith(mnemonic):
        return None

    operand = full_text[len(mnemonic):].strip()
    if not operand:
        return None

    # Strip trailing character-literal comment (e.g. "; 'A'")
    comment_prefix = config.get_assembler().comment_prefix()
    idx = operand.find(" " + comment_prefix)
    if idx >= 0:
        operand = operand[:idx].rstrip()

    return operand if operand else None


def _resolve_label(runtime_addr):
    """Get the emitted label name for a runtime address, or None."""
    runtime_addr = RuntimeAddr(runtime_addr)
    if runtime_addr in labelmanager.labels:
        return labelmanager.labels[runtime_addr].get_already_emitted_name()
    return None


def _build_items():
    """Build the ordered list of classified items."""
    items = []

    for start_addr, end_addr in sorted(memorymanager.load_ranges):
        addr = BinaryAddr(start_addr)
        while addr < end_addr:
            c = disassembly.classifications[addr]

            if c is None or c == INSIDE_A_CLASSIFICATION:
                addr += 1
                continue

            move_id = movemanager.move_id_for_binary_addr[addr]
            runtime_addr = movemanager.b2r(addr)
            length = c.length()

            # Raw bytes
            raw_bytes = [memorymanager.memory_binary[addr + i] for i in range(length)]

            # Labels at this address
            labels = _get_labels_at(runtime_addr)

            # Labels within multi-byte classifications (e.g. mid-instruction)
            sub_labels = {}
            for i in range(1, length):
                sub_rt = movemanager.b2r(addr + i)
                sub_lab = _get_labels_at(sub_rt)
                if sub_lab:
                    sub_labels[int(sub_rt)] = sub_lab

            # Comments and annotations
            comments_before, comment_inline, comments_after = (
                _get_annotations(addr, move_id, length)
            )

            # Cross-references
            refs = _get_references_to(runtime_addr)

            # Build the entry
            entry = {
                "addr": int(runtime_addr),
                "bytes": raw_bytes,
            }

            # Only include binary_addr when it differs from runtime_addr
            if int(addr) != int(runtime_addr):
                entry["binary_addr"] = int(addr)

            if labels:
                entry["labels"] = labels
            if sub_labels:
                entry["sub_labels"] = sub_labels
            if comments_before:
                entry["comments_before"] = comments_before
            if comment_inline:
                entry["comment_inline"] = comment_inline
            if comments_after:
                entry["comments_after"] = comments_after
            if refs:
                entry["references"] = refs

            # Classification-specific data
            if isinstance(c, trace.cpu.Opcode):
                entry["type"] = "code"
                entry["mnemonic"] = utils.force_case(c.mnemonic)
                operand = _extract_operand(c, addr)
                if operand is not None:
                    entry["operand"] = operand
                target = c.target(addr)
                if target is not None:
                    entry["target"] = int(target)
                    target_label = _resolve_label(target)
                    if target_label:
                        entry["target_label"] = target_label

            elif isinstance(c, classification.String):
                entry["type"] = "string"
                entry["string"] = "".join(
                    chr(b & 0x7f) if 32 <= (b & 0x7f) < 127 else "."
                    for b in raw_bytes
                )

            elif isinstance(c, classification.Word):
                entry["type"] = "word"
                values = []
                for i in range(0, length, 2):
                    values.append(raw_bytes[i] | (raw_bytes[i + 1] << 8))
                entry["values"] = values

            elif isinstance(c, classification.Byte):
                entry["type"] = "byte"
                entry["values"] = list(raw_bytes)

            items.append(entry)
            addr += length

    return items
