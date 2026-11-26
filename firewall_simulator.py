#!/usr/bin/env python3
"""Evaluate synthetic packets against ordered firewall rules."""

from dataclasses import dataclass
from ipaddress import ip_address, ip_network


@dataclass(frozen=True)
class Rule:
    action: str
    source: str
    protocol: str
    destination_port: int | None
    reason: str

    def matches(self, packet: dict) -> bool:
        source_match = ip_address(packet["source"]) in ip_network(self.source)
        protocol_match = self.protocol == "any" or packet["protocol"] == self.protocol
        port_match = self.destination_port is None or packet["destination_port"] == self.destination_port
        return source_match and protocol_match and port_match


RULES = [
    Rule("deny", "192.168.1.50/32", "any", None, "blocked lab host"),
    Rule("allow", "192.168.1.0/24", "tcp", 443, "HTTPS from trusted lab subnet"),
    Rule("allow", "192.168.1.0/24", "tcp", 22, "SSH from trusted lab subnet"),
]


SAMPLE_PACKETS = [
    {"source": "192.168.1.25", "protocol": "tcp", "destination_port": 443},
    {"source": "192.168.1.50", "protocol": "tcp", "destination_port": 443},
    {"source": "192.168.1.25", "protocol": "tcp", "destination_port": 8080},
    {"source": "10.0.0.8", "protocol": "udp", "destination_port": 53},
]


def decide(packet: dict) -> tuple[str, str, str]:
    for number, rule in enumerate(RULES, start=1):
        if rule.matches(packet):
            return rule.action.upper(), rule.reason, str(number)
    return "DENY", "default deny", "default"


def main() -> None:
    print("Source          Protocol  Port  Decision  Rule     Reason")
    print("-" * 88)
    for packet in SAMPLE_PACKETS:
        action, reason, rule_number = decide(packet)
        print(f"{packet['source']:<15} {packet['protocol']:<8} "
              f"{packet['destination_port']:<5} {action:<8} "
              f"{rule_number:<8} {reason}")


if __name__ == "__main__":
    main()
