from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw

from sniffer import parse_packet


def test_parse_http_and_redact_sensitive_values():
    payload = (
        b"GET /profile?password=hunter2&item=book HTTP/1.1\r\n"
        b"Host: example.test\r\n"
        b"Authorization: Bearer private-token\r\n"
        b"Cookie: session=private-cookie\r\n"
        b"X-Contact: reader@example.test\r\n\r\n"
        b"private body"
    )
    packet = IP(src="192.0.2.4", dst="198.51.100.8") / TCP(sport=43120, dport=80) / Raw(load=payload)

    parsed = parse_packet(packet)
    rendered = repr(parsed)

    assert parsed["ip"]["src"] == "192.0.2.4"
    assert parsed["tcp"]["dst_port"] == 80
    assert parsed["http"]["method"] == "GET"
    assert "[REDACTED]" in parsed["http"]["target"]
    assert parsed["http"]["headers"]["authorization"] == "[REDACTED]"
    assert parsed["http"]["headers"]["cookie"] == "[REDACTED]"
    assert "[REDACTED_EMAIL]" in parsed["http"]["headers"]["x-contact"]
    assert all(secret not in rendered for secret in ("hunter2", "private-token", "private-cookie", "reader@example.test", "private body"))


def test_parse_udp_dns_question_and_answer():
    packet = (
        IP(src="192.0.2.4", dst="192.0.2.53")
        / UDP(sport=53000, dport=53)
        / DNS(
            id=7,
            qd=DNSQR(qname="example.test", qtype="A"),
            an=DNSRR(rrname="example.test", type="A", rdata="203.0.113.9"),
        )
    )

    parsed = parse_packet(packet)

    assert parsed["udp"]["dst_port"] == 53
    assert parsed["dns"]["questions"] == [{"name": "example.test", "type": 1}]
    assert parsed["dns"]["answers"] == [{"name": "example.test", "type": 1, "data": "203.0.113.9"}]