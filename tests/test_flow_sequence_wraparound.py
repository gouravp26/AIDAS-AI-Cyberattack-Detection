from scapy.all import IP, TCP, Raw
from capture.flow_tracker import FlowTracker


SEQ_MOD = 2 ** 32


def make_packet(src, dst, sport, dport, seq, payload, timestamp):

    packet = (
        IP(src=src, dst=dst)
        / TCP(
            sport=sport,
            dport=dport,
            seq=seq,
            flags="PA"
        )
        / Raw(load=payload)
    )

    packet.time = timestamp
    return packet


def test_tcp_sequence_wraparound():

    tracker = FlowTracker()

    # --------------------------------
    # FORWARD DIRECTION
    # --------------------------------

    # First packet crosses the 32-bit boundary.
    # FFFFFFFC + 5 bytes = 100000001 internally.

    tracker.process_packet(
        make_packet(
            "192.168.1.10", "192.168.1.20",
            50000, 80,
            0xFFFFFFFC,
            b"ABCDE",
            1.0
        )
    )

    # Continuation after wraparound.
    # Sequence number 1 should follow the previous segment.

    tracker.process_packet(
        make_packet(
            "192.168.1.10", "192.168.1.20",
            50000, 80,
            1,
            b"FGHI",
            1.1
        )
    )

    flow = list(tracker.flows.values())[0]

    assert flow["sloss"] == 0

    # Retransmission of bytes already observed.
    tracker.process_packet(
        make_packet(
            "192.168.1.10", "192.168.1.20",
            50000, 80,
            0xFFFFFFFE,
            b"CDE",
            1.2
        )
    )

    flow = list(tracker.flows.values())[0]

    assert flow["sloss"] == 1

    # --------------------------------
    # BACKWARD DIRECTION
    # --------------------------------

    tracker.process_packet(
        make_packet(
            "192.168.1.20", "192.168.1.10",
            80, 50000,
            0xFFFFFFFC,
            b"12345",
            1.3
        )
    )

    tracker.process_packet(
        make_packet(
            "192.168.1.20", "192.168.1.10",
            80, 50000,
            1,
            b"6789",
            1.4
        )
    )

    flow = list(tracker.flows.values())[0]

    assert flow["dloss"] == 0

    # Backward retransmission.
    tracker.process_packet(
        make_packet(
            "192.168.1.20", "192.168.1.10",
            80, 50000,
            0xFFFFFFFE,
            b"345",
            1.5
        )
    )

    flow = tracker.get_flows()[0]

    assert flow["sloss"] == 1
    assert flow["dloss"] == 1

    print("Forward retransmissions:", flow["sloss"])
    print("Backward retransmissions:", flow["dloss"])

    print("Forward sequence reference:",
          list(tracker.flows.values())[0]["_forward_seq_reference"])

    print("Backward sequence reference:",
          list(tracker.flows.values())[0]["_backward_seq_reference"])