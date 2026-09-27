# Copilot-Assisted Packet Sniffer: Seeing the Network Ethically

## Project Description

This project is a Python-based packet sniffer created for cybersecurity education. It uses Scapy to parse authorized network traffic and identify common packet information such as IP, TCP, UDP, DNS, and HTTP information.

The project is designed to demonstrate packet analysis while protecting sensitive information through filtering and redaction.

## Ethical Use

This tool must only be used on traffic that I am authorized to capture.

Authorized examples include:

* My own computer
* The local loopback interface
* An instructor-provided lab environment
* A PCAP file provided for the assignment

The tool should not be used to monitor other people's traffic or networks without permission.

## Requirements

* Python 3.10 or newer
* Scapy
* pytest
* VS Code
* GitHub repository

## Installation

Create and activate a Python virtual environment and install the required packages.

```bash
./.venv/bin/python -m pip install -r requirements.txt
```

## Running the Packet Sniffer

The current implementation is configured for authorized local loopback traffic.

The capture uses:

```text
Interface: lo0
Filter: tcp port 8000
Packet count: 25
```

Run the local test server:

```bash
./.venv/bin/python test_server.py
```

Then run the packet sniffer from another terminal:

```bash
./.venv/bin/python sniffer.py
```

The sniffer captures 25 packets and displays parsed packet information.

## Packet Information

The parser can identify:

* IPv4 and IPv6
* TCP
* UDP
* DNS queries and answers
* Visible HTTP request and response headers

HTTP bodies are not returned by the parser.

## Filtering

The packet capture uses a Berkeley Packet Filter (BPF) to limit traffic.

Example:

```text
tcp port 8000
```
