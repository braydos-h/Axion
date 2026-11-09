#!/usr/bin/env python3
"""Generate deterministic pcap/pcapng fixtures for Axion tests and demos.

No third-party packages are used. Every packet is built from first principles so
the fixtures remain reviewable and reproducible.
"""

import os
import struct

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURES = os.path.join(ROOT, "tests", "fixtures")


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ethernet(payload: bytes, ethertype: int = 0x0800) -> bytes:
    return bytes.fromhex("00112233445566778899aabb") + struct.pack("!H", ethertype) + payload


def ipv4(src: str, dst: str, proto: int, payload: bytes, ident: int = 1,
         frag: int = 0) -> bytes:
    src_b = bytes(map(int, src.split(".")))
    dst_b = bytes(map(int, dst.split(".")))
    total = 20 + len(payload)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, total, ident, frag, 64, proto, 0, src_b, dst_b,
    )
    return header + payload


def tcp(src: str, dst: str, sport: int, dport: int, payload: bytes,
        seq: int = 1, flags: int = 0x18) -> bytes:
    header = struct.pack(
        "!HHIIBBHHH",
        sport, dport, seq, 0, 0x50, flags, 65535, 0, 0,
    )
    return ipv4(src, dst, 6, header + payload)


def udp(src: str, dst: str, sport: int, dport: int, payload: bytes) -> bytes:
    header = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0)
    return ipv4(src, dst, 17, header + payload)


def dns_query(name: str = "www.example.com", ident: int = 0x1234) -> bytes:
    header = struct.pack("!HHHHHH", ident, 0x0100, 1, 0, 0, 0)
    qname = b"".join(bytes([len(part)]) + part.encode() for part in name.split(".")) + b"\0"
    return header + qname + struct.pack("!HH", 1, 1)


def tls_client_hello(sni: str = "www.example.com") -> bytes:
    session_id = bytes([0x22]) * 32
    ciphers = [0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F]
    suites = b"".join(struct.pack("!H", c) for c in ciphers)
    groups = b"".join(struct.pack("!H", g) for g in (0x001D, 0x0017, 0x0018))
    point_formats = bytes([1, 0])

    def ext(kind: int, value: bytes) -> bytes:
        return struct.pack("!HH", kind, len(value)) + value

    # SNI
    host = sni.encode()
    sni_entry = b"\x00" + struct.pack("!H", len(host)) + host
    sni_list = struct.pack("!H", len(sni_entry)) + sni_entry
    # ALPN
    protos = b"".join(bytes([len(p)]) + p for p in (b"h2", b"http/1.1"))
    alpn = struct.pack("!H", len(protos)) + protos
    supported_versions = bytes([4]) + struct.pack("!HH", 0x0304, 0x0303)
    signature_algorithms = struct.pack("!H", 4) + struct.pack("!HH", 0x0403, 0x0804)

    extensions = b"".join([
        ext(0, sni_list),
        ext(10, struct.pack("!H", len(groups)) + groups),
        ext(11, struct.pack("!B", len(point_formats)) + point_formats),
        ext(13, signature_algorithms),
        ext(16, alpn),
        ext(43, supported_versions),
        ext(0x0A0A, b""),  # GREASE, exercising fingerprint parsing
    ])
    body = (
        struct.pack("!H", 0x0303)
        + bytes([0x11]) * 32
        + bytes([len(session_id)]) + session_id
        + struct.pack("!H", len(suites)) + suites
        + b"\x01\x00"
        + struct.pack("!H", len(extensions)) + extensions
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


def socks5_request(host: str = "example.com", port: int = 443) -> bytes:
    greeting = bytes([5, 1, 0])
    request = bytes([5, 1, 0, 3, len(host)]) + host.encode() + struct.pack("!H", port)
    return greeting + request


def vless_request(host: str = "example.com", port: int = 443) -> bytes:
    uuid = bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x47, 0x88,
                  0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00])
    return (
        b"\x00" + uuid + b"\x00" + b"\x01"
        + struct.pack("!H", port)
        + b"\x02" + bytes([len(host)]) + host.encode()
        + b"GET / HTTP/1.1\r\n"
    )


def trojan_request(host: str = "example.com", port: int = 443) -> bytes:
    return (
        b"a" * 56 + b"\r\n" + b"\x01\x03" + bytes([len(host)]) + host.encode()
        + struct.pack("!H", port) + b"\r\n" + b"payload"
    )


def http_connect(host: str = "example.com", port: int = 443) -> bytes:
    return (
        f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n"
        "Proxy-Connection: keep-alive\r\n\r\n"
    ).encode()


def http_get(host: str = "example.com") -> bytes:
    return (
        f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: fixture/1.0\r\n\r\n"
    ).encode()


def write_pcap(path: str, frames, linktype: int = 1) -> None:
    with open(path, "wb") as out:
        out.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype))
        for index, frame in enumerate(frames):
            ts_sec = 1_700_000_000 + index
            out.write(struct.pack("<IIII", ts_sec, index * 1000, len(frame), len(frame)))
            out.write(frame)


def write_pcapng(path: str, frames, linktype: int = 1) -> None:
    def block(kind: int, body: bytes) -> bytes:
        total = 12 + len(body)
        padded = body + b"\0" * ((4 - len(body) % 4) % 4)
        total = 12 + len(padded)
        return struct.pack("<II", kind, total) + padded + struct.pack("<I", total)

    shb = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    idb = block(1, struct.pack("<HHI", linktype, 0, 65535))
    with open(path, "wb") as out:
        out.write(shb)
        out.write(idb)
        for index, frame in enumerate(frames):
            ts = (1_700_000_000 + index) * 1_000_000 + index
            body = struct.pack("<IIIII", 0, ts >> 32, ts & 0xFFFFFFFF, len(frame), len(frame)) + frame
            out.write(block(6, body))


def main() -> None:
    os.makedirs(FIXTURES, exist_ok=True)

    benign_tls = ethernet(tcp("192.0.2.10", "198.51.100.20", 50000, 443, tls_client_hello()))
    write_pcap(os.path.join(FIXTURES, "benign_tls.pcap"), [benign_tls])
    write_pcapng(os.path.join(FIXTURES, "benign_tls.pcapng"), [benign_tls])

    benign_http = ethernet(tcp("192.0.2.10", "198.51.100.30", 50001, 80, http_get()))
    write_pcap(os.path.join(FIXTURES, "benign_http.pcap"), [benign_http])

    dns = dns_query()
    dns_frame = ethernet(udp("192.0.2.10", "198.51.100.53", 53000, 53, dns))
    write_pcap(os.path.join(FIXTURES, "benign_dns.pcap"), [dns_frame])

    # IPv4 fragmentation: split the complete UDP datagram at a multiple of 8.
    l4 = struct.pack("!HHHH", 53001, 53, 8 + len(dns), 0) + dns
    split = 32
    first = ipv4("192.0.2.10", "198.51.100.53", 17, l4[:split], ident=0xBEEF, frag=0x2000)
    second = ipv4("192.0.2.10", "198.51.100.53", 17, l4[split:], ident=0xBEEF,
                  frag=split // 8)
    write_pcap(os.path.join(FIXTURES, "ipv4_fragmented_dns.pcap"),
               [ethernet(second), ethernet(first)])  # deliberately out of order

    write_pcap(os.path.join(FIXTURES, "proxy_socks5.pcap"), [ethernet(
        tcp("192.0.2.10", "198.51.100.108", 50002, 1080, socks5_request()))])
    write_pcap(os.path.join(FIXTURES, "proxy_http_connect.pcap"), [ethernet(
        tcp("192.0.2.10", "198.51.100.50", 50003, 8080, http_connect()))])
    write_pcap(os.path.join(FIXTURES, "proxy_vless_plaintext.pcap"), [ethernet(
        tcp("192.0.2.10", "198.51.100.60", 50004, 8443, vless_request()))])
    write_pcap(os.path.join(FIXTURES, "proxy_trojan_plaintext.pcap"), [ethernet(
        tcp("192.0.2.10", "198.51.100.70", 50005, 8443, trojan_request()))])

    print(f"wrote fixtures to {FIXTURES}")


if __name__ == "__main__":
    main()
