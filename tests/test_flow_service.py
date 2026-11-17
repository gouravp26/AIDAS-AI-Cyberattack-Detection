import sys
from pathlib import Path

from scapy.all import ICMP, IP, TCP, UDP

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "capture"))
from flow_tracker import FlowTracker  # type: ignore

# AIDAS Stage 6 - synthetic test for the port-based service identification.


def service_of(packet):
    tracker = FlowTracker()
    packet.time = 100.0
    tracker.process_packet(packet)
    return tracker.get_flows()[0]["service"]


def test_tcp_http():
    packet = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=50000, dport=80)
    assert service_of(packet) == "http"


def test_udp_dns_server_reply():
    # the first observed packet is the server's reply (source port 53)
    packet = IP(src="10.0.0.2", dst="10.0.0.1") / UDP(sport=53, dport=50000)
    assert service_of(packet) == "dns"


def test_https_is_ssl():
    packet = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=50001, dport=443)
    assert service_of(packet) == "ssl"


def test_unknown_ports():
    packet = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=50000, dport=51000)
    assert service_of(packet) == "-"


def test_ambiguous_ports():
    # port 80 means http and port 443 means ssl, so the answer is unclear
    packet = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=80, dport=443)
    assert service_of(packet) == "-"


def test_same_service_on_both_ports():
    packet = IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=53, dport=53)
    assert service_of(packet) == "dns"


def test_non_tcp_udp_protocol():
    packet = IP(src="10.0.0.1", dst="10.0.0.2") / ICMP()
    assert service_of(packet) == "-"


if __name__ == "__main__":
    tests = [
        value for name, value in sorted(globals().items())
        if name.startswith("test_") and callable(value)
    ]
    failed = 0
    for test in tests:
        try:
            test()
            print(f"{test.__name__:40s} PASS")
        except AssertionError:
            print(f"{test.__name__:40s} FAIL")
            failed += 1
    print()
    print("All checks passed" if failed == 0 else "SOME CHECKS FAILED")
    sys.exit(1 if failed else 0)