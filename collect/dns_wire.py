"""A DNS resolver that tells you WHY it got nothing.

WHY NOT socket.getaddrinfo
--------------------------
Measured: a name that does not exist and a resolver that could not answer both
raise the same `socket.gaierror`. Those are opposite facts —

    NXDOMAIN   the name is conclusively gone
    SERVFAIL   we could not find out

— and the whole of change tracking turns on the difference. Treating a resolver
outage as "the record was deleted" would report a customer's entire DNS estate
as disappearing overnight. Treating a real deletion as an outage would hide the
one change worth an alert.

`getaddrinfo` also cannot see a CNAME, which is the record takeover detection is
entirely about, and it silently follows the chain to an address.

So this speaks DNS over UDP with `socket` and `struct`, and returns the rcode.
It is a deliberately small parser: enough to read A, AAAA, CNAME, NS, MX and TXT
answers and report the response code, and nothing else.

The packet is built and parsed here; it is SENT by `collect/egress.py`, which
holds the permit check and the rate buckets. This module never opens a socket.
"""
from __future__ import annotations

import enum
import hashlib
import secrets
import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple


class Rcode(enum.IntEnum):
    NOERROR = 0
    FORMERR = 1
    SERVFAIL = 2
    NXDOMAIN = 3
    NOTIMP = 4
    REFUSED = 5

    @property
    def conclusive(self) -> bool:
        """Did the resolver actually answer the question?

        NOERROR and NXDOMAIN are answers — "here it is" and "it does not exist".
        Everything else means we did not find out, and must never supersede a
        stored record set.
        """
        return self in (Rcode.NOERROR, Rcode.NXDOMAIN)


class RRType(enum.IntEnum):
    A = 1
    NS = 2
    CNAME = 5
    SOA = 6
    MX = 15
    TXT = 16
    AAAA = 28


#: What a sweep asks for. CNAME first because takeover detection depends on it.
DEFAULT_RRTYPES: Tuple[RRType, ...] = (RRType.CNAME, RRType.A, RRType.AAAA,
                                       RRType.NS, RRType.TXT)


class WireError(ValueError):
    """The response could not be parsed. Never silently treated as empty."""


@dataclass(frozen=True)
class Answer:
    name: str
    rrtype: RRType
    value: str
    ttl: int = 0


@dataclass
class Response:
    name: str
    rrtype: RRType
    rcode: Rcode
    answers: List[Answer] = field(default_factory=list)
    resolver: str = ""
    #: True when the response could not be read at all — distinct from an empty
    #: answer section, which is a real and meaningful result (NODATA).
    unreadable: bool = False
    detail: str = ""

    @property
    def conclusive(self) -> bool:
        return self.rcode.conclusive and not self.unreadable

    @property
    def values(self) -> List[str]:
        return sorted(a.value for a in self.answers)

    @property
    def digest(self) -> str:
        """A stable fingerprint of the record set.

        TTL IS EXCLUDED. Including it makes every record set "change" on every
        run as the counter ticks down, which buries real changes under noise and
        trains the reader to ignore the feed.

        Values are lower-cased, dot-normalised and sorted, because a resolver
        may legitimately return them in any order and order is not a change.
        """
        material = "|".join(v.lower().rstrip(".") for v in self.values)
        return hashlib.sha256(material.encode("utf-8")).hexdigest()

    @property
    def state(self) -> Tuple[str, str]:
        """`(rcode, digest)` — the comparand for change tracking.

        The digest ALONE is not enough: NXDOMAIN and NODATA both produce an
        empty answer set and therefore the same sha256, so the two most
        meaningful DNS transitions — a zone deleted (NODATA -> NXDOMAIN) and a
        name created (NXDOMAIN -> NODATA) — would be invisible.
        """
        return (self.rcode.name, self.digest)


def _encode_name(name: str) -> bytes:
    out = bytearray()
    for label in str(name).strip().rstrip(".").split("."):
        encoded = label.encode("idna") if any(ord(c) > 127 for c in label) \
            else label.encode("ascii", "ignore")
        if len(encoded) > 63:
            raise WireError(f"label too long in {name!r}")
        out.append(len(encoded))
        out.extend(encoded)
    out.append(0)
    return bytes(out)


def build_query(name: str, rrtype: RRType, recursion: bool = True) -> Tuple[bytes, int]:
    """`(packet, transaction_id)`.

    The id is cryptographically random rather than sequential — a predictable id
    is what makes off-path response spoofing practical, and this is a resolver
    reading data the product will act on.
    """
    txid = secrets.randbelow(65536)
    flags = 0x0100 if recursion else 0x0000
    header = struct.pack(">HHHHHH", txid, flags, 1, 0, 0, 0)
    question = _encode_name(name) + struct.pack(">HH", int(rrtype), 1)
    return header + question, txid


def _read_name(data: bytes, offset: int, depth: int = 0) -> Tuple[str, int]:
    """Decompress a DNS name. Bounded, because a pointer loop is a hang."""
    if depth > 20:
        raise WireError("compression pointer loop")
    labels: List[str] = []
    while True:
        if offset >= len(data):
            raise WireError("name ran past the end of the packet")
        length = data[offset]
        if length == 0:
            return ".".join(labels), offset + 1
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                raise WireError("truncated compression pointer")
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            suffix, _ = _read_name(data, pointer, depth + 1)
            if suffix:
                labels.append(suffix)
            return ".".join(labels), offset + 2
        offset += 1
        if offset + length > len(data):
            raise WireError("label ran past the end of the packet")
        labels.append(data[offset:offset + length].decode("ascii", "replace"))
        offset += length


def parse_response(data: bytes, name: str, rrtype: RRType,
                   expect_txid: Optional[int] = None,
                   resolver: str = "") -> Response:
    """Read a response, or say plainly that it could not be read."""
    try:
        if len(data) < 12:
            raise WireError("response shorter than a DNS header")
        txid, flags, qdcount, ancount, _, _ = struct.unpack(">HHHHHH", data[:12])
        if expect_txid is not None and txid != expect_txid:
            # A mismatched transaction id is the signature of a spoofed or
            # crossed response. Refusing it is the point of randomising the id.
            raise WireError(f"transaction id {txid} does not match {expect_txid}")

        rcode_value = flags & 0x000F
        try:
            rcode = Rcode(rcode_value)
        except ValueError:
            rcode = Rcode.SERVFAIL

        offset = 12
        for _ in range(qdcount):
            _, offset = _read_name(data, offset)
            offset += 4

        answers: List[Answer] = []
        for _ in range(ancount):
            record_name, offset = _read_name(data, offset)
            if offset + 10 > len(data):
                raise WireError("record header ran past the end")
            rtype, _rclass, ttl, rdlength = struct.unpack(
                ">HHIH", data[offset:offset + 10])
            offset += 10
            rdata = data[offset:offset + rdlength]
            if len(rdata) < rdlength:
                raise WireError("rdata ran past the end")
            value = _render(data, offset, rtype, rdata)
            offset += rdlength
            if value is not None:
                try:
                    answers.append(Answer(record_name, RRType(rtype), value, ttl))
                except ValueError:
                    continue     # a record type this parser does not model
        return Response(name=name, rrtype=rrtype, rcode=rcode, answers=answers,
                        resolver=resolver)
    except WireError as exc:
        # UNREADABLE, not empty. An empty answer section is a real result;
        # a packet we could not parse is an absence of information, and
        # conflating them makes a parser bug look like a deleted zone.
        return Response(name=name, rrtype=rrtype, rcode=Rcode.SERVFAIL,
                        resolver=resolver, unreadable=True, detail=str(exc))
    except (struct.error, IndexError) as exc:
        return Response(name=name, rrtype=rrtype, rcode=Rcode.SERVFAIL,
                        resolver=resolver, unreadable=True,
                        detail=f"malformed packet: {exc}")


def _render(data: bytes, offset: int, rtype: int, rdata: bytes) -> Optional[str]:
    import socket as _socket

    if rtype == RRType.A and len(rdata) == 4:
        return _socket.inet_ntop(_socket.AF_INET, rdata)
    if rtype == RRType.AAAA and len(rdata) == 16:
        return _socket.inet_ntop(_socket.AF_INET6, rdata)
    if rtype in (RRType.CNAME, RRType.NS):
        rendered, _ = _read_name(data, offset)
        return rendered
    if rtype == RRType.MX and len(rdata) >= 3:
        rendered, _ = _read_name(data, offset + 2)
        return rendered
    if rtype == RRType.TXT:
        parts, index = [], 0
        while index < len(rdata):
            length = rdata[index]
            parts.append(rdata[index + 1:index + 1 + length].decode("utf-8", "replace"))
            index += 1 + length
        return "".join(parts)
    return None


__all__ = ["Rcode", "RRType", "DEFAULT_RRTYPES", "Answer", "Response",
           "WireError", "build_query", "parse_response"]
