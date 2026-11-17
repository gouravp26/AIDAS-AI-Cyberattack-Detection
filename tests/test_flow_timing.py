import sys
from pathlib import Path

from scapy.all import IP, UDP, Raw

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "capture"))
from flow_tracker import FlowTracker  # type: ignore

# AIDAS Stage 6 - synthetic test for sinpkt, dinpkt, sjit and djit (milliseconds).
# Expected values are computed by hand.


def udp_packet(src, sport, dst, dport, payload_len, timestamp):
    packet = IP(src=src, dst=dst) / UDP(sport=sport, dport=dport) / Raw(b"x" * payload_len)
    packet.time = timestamp
    return packet


def check(name, actual, expected):
    ok = abs(float(actual) - expected) < 1e-6
    print(f"{name:34s} actual={float(actual):<10} expected={expected:<10} {'PASS' if ok else 'FAIL'}")
    return ok



def test_flow_calculations():
    results = []

    # Test 1: forward packets at 100.0, 100.5, 102.0 -> gaps 500 ms and 1500 ms
    #   sinpkt = mean = 1000 ms; sjit = population std = 500 ms
    # backward packets at 100.25, 101.0 -> one gap of 750 ms
    #   dinpkt = 750 ms; djit = 0 (a single gap has no variation)
    print("Test 1: two-way flow")
    tracker = FlowTracker()
    for t, direction in [(100.0, "f"), (100.25, "b"), (100.5, "f"), (101.0, "b"), (102.0, "f")]:
        if direction == "f":
            tracker.process_packet(udp_packet("10.0.0.1", 5000, "10.0.0.2", 53, 12, t))
        else:
            tracker.process_packet(udp_packet("10.0.0.2", 53, "10.0.0.1", 5000, 72, t))
    record = tracker.get_flows()[0]
    results += [
        check("sinpkt (ms)", record["sinpkt"], 1000.0),
        check("sjit (ms)", record["sjit"], 500.0),
        check("dinpkt (ms)", record["dinpkt"], 750.0),
        check("djit (ms)", record["djit"], 0.0),
    ]

    # Test 2: equal gaps of 500 ms -> sinpkt 500 ms, sjit 0
    print()
    print("Test 2: equal gaps")
    tracker = FlowTracker()
    for t in (500.0, 500.5, 501.0):
        tracker.process_packet(udp_packet("10.0.0.3", 6000, "10.0.0.4", 80, 12, t))
    record = tracker.get_flows()[0]
    results += [
        check("sinpkt (ms)", record["sinpkt"], 500.0),
        check("sjit (ms)", record["sjit"], 0.0),
    ]

    # Test 3: one packet in each direction -> all four values are 0
    print()
    print("Test 3: one packet each way")
    tracker = FlowTracker()
    tracker.process_packet(udp_packet("10.0.0.5", 7000, "10.0.0.6", 80, 12, 200.0))
    tracker.process_packet(udp_packet("10.0.0.6", 80, "10.0.0.5", 7000, 12, 200.5))
    record = tracker.get_flows()[0]
    results += [
        check("sinpkt", record["sinpkt"], 0.0),
        check("dinpkt", record["dinpkt"], 0.0),
        check("sjit", record["sjit"], 0.0),
        check("djit", record["djit"], 0.0),
    ]

    print()
    print("All checks passed" if all(results) else "SOME CHECKS FAILED")
    assert all(results), 'One or more flow checks failed'

if __name__ == "__main__":
    test_flow_calculations()
