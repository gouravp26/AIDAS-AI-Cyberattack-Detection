import sys
from pathlib import Path

from scapy.all import IP, UDP, Raw

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "capture"))
from flow_tracker import FlowTracker  # type: ignore

# AIDAS Stage 6 - synthetic test for rate, sload and dload.
# Expected values are computed by hand from the empirical rules.


def udp_packet(src, sport, dst, dport, payload_len, timestamp):
    packet = IP(src=src, dst=dst) / UDP(sport=sport, dport=dport) / Raw(b"x" * payload_len)
    packet.time = timestamp
    return packet


def check(name, actual, expected):
    ok = abs(float(actual) - expected) < 1e-9
    print(f"{name:34s} actual={float(actual):<10} expected={expected:<10} {'PASS' if ok else 'FAIL'}")
    return ok



def test_flow_calculations():
    results = []

    # Test 1: two-way flow lasting 2 seconds.
    # Forward: 3 packets of 40 bytes (IP length) at t = 100.0, 100.5, 102.0
    # Backward: 2 packets of 100 bytes at t = 100.2, 101.0
    print("Test 1: two-way UDP flow")
    tracker = FlowTracker()
    for t, direction in [(100.0, "f"), (100.2, "b"), (100.5, "f"), (101.0, "b"), (102.0, "f")]:
        if direction == "f":
            tracker.process_packet(udp_packet("10.0.0.1", 5000, "10.0.0.2", 53, 12, t))
        else:
            tracker.process_packet(udp_packet("10.0.0.2", 53, "10.0.0.1", 5000, 72, t))
    record = tracker.get_flows()[0]
    results += [
        check("spkts", record["spkts"], 3),
        check("dpkts", record["dpkts"], 2),
        check("sbytes", record["sbytes"], 120),
        check("dbytes", record["dbytes"], 200),
        check("dur", record["dur"], 2.0),
        check("rate = (5-1)/2", record["rate"], 2.0),
        check("sload = 40*(3-1)*8/2", record["sload"], 320.0),
        check("dload = 100*(2-1)*8/2", record["dload"], 400.0),
    ]

    # Test 2: single-packet flow, duration 0 -> rate, sload and dload are all 0.
    print()
    print("Test 2: single-packet flow")
    tracker = FlowTracker()
    tracker.process_packet(udp_packet("10.0.0.3", 6000, "10.0.0.4", 80, 12, 300.0))
    record = tracker.get_flows()[0]
    results += [
        check("dur", record["dur"], 0.0),
        check("rate", record["rate"], 0.0),
        check("sload", record["sload"], 0.0),
        check("dload", record["dload"], 0.0),
    ]

    # Test 3: forward-only flow, 2 packets 1 second apart -> dload must be 0.
    print()
    print("Test 3: forward-only flow")
    tracker = FlowTracker()
    tracker.process_packet(udp_packet("10.0.0.5", 7000, "10.0.0.6", 80, 12, 200.0))
    tracker.process_packet(udp_packet("10.0.0.5", 7000, "10.0.0.6", 80, 12, 201.0))
    record = tracker.get_flows()[0]
    results += [
        check("dur", record["dur"], 1.0),
        check("rate = (2-1)/1", record["rate"], 1.0),
        check("sload = 40*(2-1)*8/1", record["sload"], 320.0),
        check("dload (no reply)", record["dload"], 0.0),
    ]

    print()
    print("All checks passed" if all(results) else "SOME CHECKS FAILED")
    assert all(results), 'One or more flow checks failed'

if __name__ == "__main__":
    test_flow_calculations()
