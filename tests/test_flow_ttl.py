import sys
from pathlib import Path

from scapy.all import IP, UDP, Raw

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "capture"))
from flow_tracker import FlowTracker


def udp_packet(src, sport, dst, dport, ttl, timestamp):
    packet = (
        IP(src=src, dst=dst, ttl=ttl)
        / UDP(sport=sport, dport=dport)
        / Raw(b"x" * 12)
    )
    packet.time = timestamp
    return packet


def check(name, actual, expected):
    passed = actual == expected

    print(
        f"{name:25s} actual={actual:<8} "
        f"expected={expected:<8} "
        f"{'PASS' if passed else 'FAIL'}"
    )

    return passed



def test_flow_calculations():
    results = []

    # Test 1: Two-way flow with different TTL values
    print("Test 1: Two-way flow")

    tracker = FlowTracker()

    tracker.process_packet(
        udp_packet("10.0.0.1", 5000, "10.0.0.2", 53, 64, 100.0)
    )

    tracker.process_packet(
        udp_packet("10.0.0.2", 53, "10.0.0.1", 5000, 128, 100.5)
    )

    # A later packet must not overwrite the first observed TTL.
    tracker.process_packet(
        udp_packet("10.0.0.1", 5000, "10.0.0.2", 53, 60, 101.0)
    )

    record = tracker.get_flows()[0]

    results += [
        check("sttl", record["sttl"], 64),
        check("dttl", record["dttl"], 128),
    ]

    # Test 2: Forward-only flow
    print("\nTest 2: Forward-only flow")

    tracker = FlowTracker()

    tracker.process_packet(
        udp_packet("10.0.0.3", 6000, "10.0.0.4", 80, 55, 200.0)
    )

    record = tracker.get_flows()[0]

    results += [
        check("sttl", record["sttl"], 55),
        check("dttl", record["dttl"], 0),
    ]

    # Test 3: Backward-only flow
    print("\nTest 3: Backward-only flow")

    tracker = FlowTracker()

    tracker.process_packet(
        udp_packet("10.0.0.6", 80, "10.0.0.5", 7000, 99, 300.0)
    )

    record = tracker.get_flows()[0]

    results += [
        check("sttl", record["sttl"], 99),
        check("dttl", record["dttl"], 0),
    ]

    print("\nAll checks passed" if all(results) else "\nSOME CHECKS FAILED")

    assert all(results), 'One or more flow checks failed'

if __name__ == "__main__":
    test_flow_calculations()
