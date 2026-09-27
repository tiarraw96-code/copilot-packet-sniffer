import re

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.packet import Packet


_EMAIL_PATTERN = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
_QUERY_SECRET_PATTERN = re.compile(
	r"([?&](?:password|passwd|pwd|token|access_token|refresh_token|api_key|apikey|secret)=)[^&#\s]*",
	re.IGNORECASE,
)
_NAMED_SECRET_PATTERN = re.compile(
	r"\b((?:access[_-]?token|refresh[_-]?token|api[_-]?key|token|secret|password)\s*[:=]\s*)[^\s,;]+",
	re.IGNORECASE,
)
_BEARER_PATTERN = re.compile(r"\bBearer\s+[^\s,;]+", re.IGNORECASE)
_JWT_PATTERN = re.compile(
	r"\beyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"
)


def _text(value):
	if isinstance(value, bytes):
		value = value.decode("utf-8", errors="replace")
	return str(value)


def _redact(value):
	value = _text(value)
	value = _QUERY_SECRET_PATTERN.sub(r"\1[REDACTED]", value)
	value = _NAMED_SECRET_PATTERN.sub(r"\1[REDACTED]", value)
	value = _BEARER_PATTERN.sub("Bearer [REDACTED]", value)
	value = _JWT_PATTERN.sub("[REDACTED]", value)
	return _EMAIL_PATTERN.sub("[REDACTED_EMAIL]", value)


def _dns_records(record, count):
	records = []
	limit = int(count) if count else None
	if isinstance(record, (list, tuple)):
		section = record
	else:
		section = []
		while isinstance(record, (DNSQR, DNSRR)):
			section.append(record)
			record = record.payload

	for item in section[:limit]:
		if isinstance(item, DNSQR):
			records.append({
				"name": _redact(_text(item.qname).rstrip(".")),
				"type": int(item.qtype),
			})
		elif isinstance(item, DNSRR):
			records.append({
				"name": _redact(_text(item.rrname).rstrip(".")),
				"type": int(item.type),
				"data": _redact(item.rdata),
			})
	return records


def _http_summary(payload):
	header_bytes = payload.split(b"\r\n\r\n", 1)[0]
	lines = header_bytes.decode("latin-1", errors="replace").split("\r\n")
	if not lines:
		return None

	first_line = lines[0]
	request = re.match(r"^(\S+)\s+(\S+)\s+HTTP/(\d\.\d)$", first_line)
	response = re.match(r"^HTTP/(\d\.\d)\s+(\d{3})(?:\s+(.*))?$", first_line)
	if not request and not response:
		return None

	headers = {}
	for line in lines[1:]:
		name, separator, value = line.partition(":")
		if not separator:
			continue
		normalized_name = name.strip().lower()
		if normalized_name in {"authorization", "proxy-authorization", "cookie", "set-cookie"}:
			headers[normalized_name] = "[REDACTED]"
		else:
			headers[normalized_name] = _redact(value.strip())

	if request:
		return {
			"kind": "request",
			"method": request.group(1),
			"target": _redact(request.group(2)),
			"version": request.group(3),
			"headers": headers,
		}
	return {
		"kind": "response",
		"version": response.group(1),
		"status": int(response.group(2)),
		"reason": _redact(response.group(3) or ""),
		"headers": headers,
	}


def parse_packet(packet):
	"""Summarize a Scapy packet that has already been captured or read from a PCAP.

	This function only parses the supplied packet; it does not capture traffic.
	HTTP parsing is limited to visible, unencrypted headers and never returns a body.
	"""
	if not isinstance(packet, Packet):
		raise TypeError("packet must be a Scapy Packet")

	result = {"layers": []}
	ip_layer = None
	if packet.haslayer(IP):
		ip_layer = packet[IP]
		result["ip"] = {
			"version": 4,
			"src": _redact(ip_layer.src),
			"dst": _redact(ip_layer.dst),
			"ttl": int(ip_layer.ttl),
		}
		result["layers"].append("IP")
	elif packet.haslayer(IPv6):
		ip_layer = packet[IPv6]
		result["ip"] = {
			"version": 6,
			"src": _redact(ip_layer.src),
			"dst": _redact(ip_layer.dst),
			"hop_limit": int(ip_layer.hlim),
		}
		result["layers"].append("IPv6")

	if packet.haslayer(TCP):
		tcp = packet[TCP]
		result["tcp"] = {
			"src_port": int(tcp.sport),
			"dst_port": int(tcp.dport),
			"flags": str(tcp.flags),
			"seq": int(tcp.seq),
			"ack": int(tcp.ack),
		}
		result["layers"].append("TCP")
		http = _http_summary(bytes(tcp.payload)) if tcp.payload else None
		if http:
			result["http"] = http

	if packet.haslayer(UDP):
		udp = packet[UDP]
		result["udp"] = {
			"src_port": int(udp.sport),
			"dst_port": int(udp.dport),
			"length": int(udp.len or 0),
		}
		result["layers"].append("UDP")

	if packet.haslayer(DNS):
		dns = packet[DNS]
		result["dns"] = {
			"id": int(dns.id),
			"is_response": bool(dns.qr),
			"questions": _dns_records(dns.qd, dns.qdcount),
			"answers": _dns_records(dns.an, dns.ancount),
		}
		result["layers"].append("DNS")

	return result
if __name__ == "__main__":
    from scapy.all import sniff

    print("Starting authorized loopback packet capture...")
    print("Capturing 25 packets on lo0...")
    
    sniff(
        iface="lo0",
        filter="tcp port 8000",
        count=25,
        prn=lambda packet: print(parse_packet(packet))
    )

    print("Capture complete.")