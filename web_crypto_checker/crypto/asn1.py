"""A small, strict DER reader for X.509 certificates.

DER is tag-length-value all the way down. This parses one TLV into a tree of
:class:`Node`, refusing anything a certificate has no business containing --
indefinite lengths, multi-byte tags, a length that runs off the end -- because
the bytes come from whatever the server chose to send.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Tuple

TAG_INTEGER = 0x02
TAG_BIT_STRING = 0x03
TAG_OCTET_STRING = 0x04
TAG_OID = 0x06
TAG_SEQUENCE = 0x10
TAG_SET = 0x11
TAG_UTC_TIME = 0x17
TAG_GENERALIZED_TIME = 0x18

#: Tag class of a context-specific tag (the ``[n]`` in an ASN.1 module).
CLASS_CONTEXT = 2


class Asn1Error(Exception):
    """A DER structure could not be parsed."""


@dataclass
class Node:
    """One tag-length-value node, with its children when it is constructed."""

    tag: int
    constructed: bool
    tag_class: int
    tag_number: int
    content: bytes
    raw: bytes = b""
    """The whole tag-length-value slice: what a signature is computed over."""
    children: List[Node] = field(default_factory=list)

    def integer(self) -> int:
        """The value of an INTEGER node, taken as non-negative (serials, moduli)."""
        return int.from_bytes(self.content, "big")


def parse(data: bytes) -> Node:
    """Parse the first TLV in ``data`` and return it."""
    node, _end = _parse_tlv(data, 0)
    return node


def _read_length(data: bytes, pos: int) -> Tuple[int, int]:
    if pos >= len(data):
        raise Asn1Error("truncated: no length byte")
    first = data[pos]
    pos += 1
    if first < 0x80:
        return first, pos
    count = first & 0x7F
    if count == 0:
        raise Asn1Error("indefinite lengths are not allowed in DER")
    if pos + count > len(data):
        raise Asn1Error("truncated: long-form length runs off the end")
    return int.from_bytes(data[pos : pos + count], "big"), pos + count


def _parse_tlv(data: bytes, pos: int) -> Tuple[Node, int]:
    if pos >= len(data):
        raise Asn1Error("truncated: no tag byte")
    start = pos
    tag = data[pos]
    pos += 1
    tag_number = tag & 0x1F
    if tag_number == 0x1F:
        raise Asn1Error("multi-byte tags are not supported")
    constructed = bool(tag & 0x20)
    length, pos = _read_length(data, pos)
    end = pos + length
    if end > len(data):
        raise Asn1Error("truncated: content runs off the end")
    content = data[pos:end]

    children: List[Node] = []
    if constructed:
        child_pos = pos
        while child_pos < end:
            child, child_pos = _parse_tlv(data, child_pos)
            children.append(child)

    node = Node(
        tag=tag,
        constructed=constructed,
        tag_class=tag >> 6,
        tag_number=tag_number,
        content=content,
        raw=data[start:end],
        children=children,
    )
    return node, end


def decode_oid(content: bytes) -> str:
    """Decode an OID's content octets into dotted-decimal form."""
    if not content:
        raise Asn1Error("empty OID")
    first = content[0]
    arcs = [str(first // 40), str(first % 40)]
    value = 0
    for byte in content[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            arcs.append(str(value))
            value = 0
    return ".".join(arcs)
