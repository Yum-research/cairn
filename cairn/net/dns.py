from __future__ import annotations

import asyncio
import ipaddress
import os
import random
import socket
import struct
import time
from dataclasses import dataclass, field
from typing import Any

QTYPES = {
    "A": 1,
    "NS": 2,
    "CNAME": 5,
    "SOA": 6,
    "PTR": 12,
    "MX": 15,
    "TXT": 16,
    "AAAA": 28,
    "SRV": 33,
    "CAA": 257,
}
TYPE_NAMES = {v: k for k, v in QTYPES.items()}

RCODES = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
}


class DNSError(RuntimeError):
    pass


@dataclass
class DNSRecord:
    name: str
    rtype: str
    ttl: int
    value: Any

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "type": self.rtype, "ttl": self.ttl, "value": self.value}


@dataclass
class DNSAnswer:
    name: str
    qtype: str
    status: str
    records: list[DNSRecord] = field(default_factory=list)
    authoritative: bool = False
    truncated: bool = False
    elapsed_ms: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "qtype": self.qtype,
            "status": self.status,
            "authoritative": self.authoritative,
            "truncated": self.truncated,
            "elapsed_ms": self.elapsed_ms,
            "records": [r.to_dict() for r in self.records],
        }


def _encode_name(name: str) -> bytes:
    name = name.rstrip(".").encode("idna").decode("ascii")
    out = bytearray()
    if not name:
        return b"\x00"
    for label in name.split("."):
        raw = label.encode("ascii")
        if not 0 < len(raw) < 64:
            raise DNSError(f"Invalid DNS label in {name!r}")
        out.append(len(raw))
        out.extend(raw)
    out.append(0)
    return bytes(out)


def _build_query(name: str, qtype: str, txid: int | None = None) -> tuple[int, bytes]:
    ident = txid if txid is not None else random.randint(0, 65535)
    flags = 0x0100  # recursion desired
    header = struct.pack("!HHHHHH", ident, flags, 1, 0, 0, 0)
    qtype_num = QTYPES[qtype.upper()]
    question = _encode_name(name) + struct.pack("!HH", qtype_num, 1)
    return ident, header + question


def _read_name(data: bytes, offset: int, depth: int = 0) -> tuple[str, int]:
    if depth > 20:
        raise DNSError("DNS compression pointer loop")
    labels: list[str] = []
    cursor = offset
    while True:
        if cursor >= len(data):
            raise DNSError("Truncated DNS name")
        length = data[cursor]
        if length == 0:
            return ".".join(labels), cursor + 1
        if length & 0xC0 == 0xC0:
            if cursor + 1 >= len(data):
                raise DNSError("Truncated compression pointer")
            pointer = ((length & 0x3F) << 8) | data[cursor + 1]
            pointed, _ = _read_name(data, pointer, depth + 1)
            if pointed:
                labels.append(pointed)
            return ".".join(labels), cursor + 2
        cursor += 1
        if cursor + length > len(data):
            raise DNSError("Truncated DNS label")
        labels.append(data[cursor : cursor + length].decode("ascii", "replace"))
        cursor += length


def _parse_rdata(data: bytes, rtype: int, start: int, rdlength: int) -> Any:
    end = start + rdlength
    if rtype == 1 and rdlength == 4:
        return str(ipaddress.IPv4Address(data[start:end]))
    if rtype == 28 and rdlength == 16:
        return str(ipaddress.IPv6Address(data[start:end]))
    if rtype in (2, 5, 12):
        return _read_name(data, start)[0]
    if rtype == 15:
        preference = struct.unpack("!H", data[start : start + 2])[0]
        exchange = _read_name(data, start + 2)[0]
        return {"preference": preference, "exchange": exchange}
    if rtype == 16:
        strings: list[str] = []
        cursor = start
        while cursor < end:
            length = data[cursor]
            cursor += 1
            strings.append(data[cursor : cursor + length].decode("utf-8", "replace"))
            cursor += length
        return "".join(strings)
    if rtype == 6:
        mname, cursor = _read_name(data, start)
        rname, cursor = _read_name(data, cursor)
        serial, refresh, retry, expire, minimum = struct.unpack("!IIIII", data[cursor : cursor + 20])
        return {
            "mname": mname,
            "rname": rname,
            "serial": serial,
            "refresh": refresh,
            "retry": retry,
            "expire": expire,
            "minimum": minimum,
        }
    if rtype == 33:
        priority, weight, port = struct.unpack("!HHH", data[start : start + 6])
        target = _read_name(data, start + 6)[0]
        return {"priority": priority, "weight": weight, "port": port, "target": target}
    if rtype == 257:
        flags, tag_len = data[start], data[start + 1]
        tag = data[start + 2 : start + 2 + tag_len].decode("ascii", "replace")
        value = data[start + 2 + tag_len : end].decode("utf-8", "replace")
        return {"flags": flags, "tag": tag, "value": value}
    return data[start:end].hex()


def _parse_response(data: bytes, ident: int, expected_name: str, qtype: str) -> DNSAnswer:
    if len(data) < 12:
        raise DNSError("DNS response shorter than header")
    rid, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", data[:12])
    if rid != ident:
        raise DNSError("DNS transaction ID mismatch")
    rcode = flags & 0xF
    answer = DNSAnswer(
        name=expected_name,
        qtype=qtype,
        status=RCODES.get(rcode, f"RCODE{rcode}"),
        authoritative=bool(flags & 0x0400),
        truncated=bool(flags & 0x0200),
    )
    cursor = 12
    for _ in range(qdcount):
        _, cursor = _read_name(data, cursor)
        cursor += 4
    for section_count in (ancount, nscount, arcount):
        for _ in range(section_count):
            name, cursor = _read_name(data, cursor)
            if cursor + 10 > len(data):
                raise DNSError("Truncated DNS resource record")
            rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", data[cursor : cursor + 10])
            cursor += 10
            if cursor + rdlength > len(data):
                raise DNSError("Truncated DNS rdata")
            try:
                value = _parse_rdata(data, rtype, cursor, rdlength)
            except (struct.error, IndexError):
                value = "<unparseable>"
            cursor += rdlength
            if rtype == 41:  # OPT
                continue
            answer.records.append(
                DNSRecord(
                    name=name,
                    rtype=TYPE_NAMES.get(rtype, f"TYPE{rtype}"),
                    ttl=ttl,
                    value=value,
                )
            )
    return answer


class DNSResolver:
    def __init__(self, servers: list[str] | None = None, timeout: float = 2.5, cache_ttl: int = 60):
        raw = servers or [s.strip() for s in os.environ.get(
            "CAIRN_DNS_RESOLVERS", "1.1.1.1,8.8.8.8"
        ).split(",") if s.strip()]
        self.servers = [self._parse_server(s) for s in raw]
        self.timeout = timeout
        self.cache_ttl = cache_ttl
        self._cache: dict[tuple[str, str], tuple[float, DNSAnswer]] = {}

    @staticmethod
    def _parse_server(value: str) -> tuple[str, int]:
        value = value.strip()
        if value.startswith("["):
            host, _, port = value[1:].partition("]:")
            return host, int(port or 53)
        if value.count(":") == 1:
            host, port = value.rsplit(":", 1)
            if port.isdigit():
                return host, int(port)
        return value, 53

    async def query(self, name: str, qtype: str = "A", use_cache: bool = True) -> DNSAnswer:
        qtype = qtype.upper()
        if qtype not in QTYPES:
            raise DNSError(f"Unsupported DNS query type {qtype}")
        name = name.rstrip(".")
        cache_key = (name.lower(), qtype)
        if use_cache and cache_key in self._cache:
            expires, answer = self._cache[cache_key]
            if time.monotonic() < expires:
                return answer
        started = time.perf_counter()
        last_error: Exception | None = None
        for server in self.servers:
            try:
                ident, packet = _build_query(name, qtype)
                response = await self._udp(server, packet)
                answer = _parse_response(response, ident, name, qtype)
                if answer.truncated:
                    response = await self._tcp(server, packet)
                    answer = _parse_response(response, ident, name, qtype)
                answer.elapsed_ms = int((time.perf_counter() - started) * 1000)
                ttl = min([r.ttl for r in answer.records if r.ttl > 0] or [self.cache_ttl])
                self._cache[cache_key] = (time.monotonic() + max(5, min(ttl, self.cache_ttl)), answer)
                return answer
            except (TimeoutError, OSError, DNSError) as exc:
                last_error = exc
                continue
        raise DNSError(f"All DNS resolvers failed for {name} {qtype}: {last_error}")

    async def _udp(self, server: tuple[str, int], packet: bytes) -> bytes:
        loop = asyncio.get_running_loop()
        sock = socket.socket(socket.AF_INET6 if ":" in server[0] else socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        try:
            await loop.sock_sendto(sock, packet, server)
            return await asyncio.wait_for(loop.sock_recv(sock, 65535), timeout=self.timeout)
        finally:
            sock.close()

    async def _tcp(self, server: tuple[str, int], packet: bytes) -> bytes:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(server[0], server[1]), timeout=self.timeout
        )
        try:
            writer.write(struct.pack("!H", len(packet)) + packet)
            await writer.drain()
            length_raw = await asyncio.wait_for(reader.readexactly(2), timeout=self.timeout)
            length = struct.unpack("!H", length_raw)[0]
            return await asyncio.wait_for(reader.readexactly(length), timeout=self.timeout)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass

    async def records(self, name: str, qtype: str = "A", use_cache: bool = True) -> list[DNSRecord]:
        return (await self.query(name, qtype, use_cache=use_cache)).records

    async def resolve_host(self, host: str) -> list[str]:
        try:
            ipaddress.ip_address(host)
            return [host]
        except ValueError:
            pass
        addresses: list[str] = []
        for qtype in ("A", "AAAA"):
            try:
                answer = await self.query(host, qtype)
            except DNSError:
                continue
            for record in answer.records:
                if record.rtype in ("A", "AAAA") and isinstance(record.value, str) and record.value not in addresses:
                    addresses.append(record.value)
        if addresses:
            return addresses
        # Fall back to the platform resolver for split-horizon/internal names.
        try:
            infos = await asyncio.wait_for(
                asyncio.get_running_loop().getaddrinfo(host, None, type=socket.SOCK_STREAM), timeout=3
            )
        except (TimeoutError, OSError) as exc:
            raise DNSError(f"Could not resolve {host}: {exc}") from exc
        for info in infos:
            addr = info[4][0]
            if addr not in addresses:
                addresses.append(addr)
        if not addresses:
            raise DNSError(f"No addresses for {host}")
        return addresses

    async def reverse(self, ip: str) -> list[str]:
        addr = ipaddress.ip_address(ip)
        name = addr.reverse_pointer
        try:
            answer = await self.query(name, "PTR")
        except DNSError:
            return []
        return [r.value for r in answer.records if r.rtype == "PTR" and isinstance(r.value, str)]

    async def enumerate_common(self, name: str) -> dict[str, list[dict[str, Any]]]:
        out: dict[str, list[dict[str, Any]]] = {}
        for qtype in ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA"):
            try:
                answer = await self.query(name, qtype)
                out[qtype] = [r.to_dict() for r in answer.records if r.rtype in (qtype, "CNAME")]
            except DNSError as exc:
                out[qtype] = [{"error": str(exc)}]
        return out
