from scapy.all import IP, TCP, Raw
from capture.flow_tracker import FlowTracker


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


def test_tcp_retransmission_detection():

    tracker = FlowTracker()

    # --------------------------------
    # FORWARD DIRECTION
    # --------------------------------

    # First segment: 1000-1005
    tracker.process_packet(
        make_packet(
            "192.168.1.10", "192.168.1.20",
            50000, 80, 1000, b"ABCDE", 1.0
        )
    )
    flow = list(tracker.flows.values())[0]

    print(
        "sloss:", flow["sloss"],
        "dloss:", flow["dloss"],
        "forward ranges:", flow["_forward_seq_ranges"],
        "backward ranges:", flow["_backward_seq_ranges"],
        "forward reference:", flow["_forward_seq_reference"],
        "backward reference:", flow["_backward_seq_reference"]
    )

    # Second segment: 1010-1015
    tracker.process_packet(
        make_packet(
            "192.168.1.10", "192.168.1.20",
            50000, 80, 1010, b"FGHIJ", 1.1
        )
    )
    flow = list(tracker.flows.values())[0]

    print(
        "sloss:", flow["sloss"],
        "dloss:", flow["dloss"],
        "forward ranges:", flow["_forward_seq_ranges"],
        "backward ranges:", flow["_backward_seq_ranges"],
        "forward reference:", flow["_forward_seq_reference"],
        "backward reference:", flow["_backward_seq_reference"]
    )

    # Out-of-order segment: 1005-1010
    # Should NOT count as retransmission.
    tracker.process_packet(
        make_packet(
            "192.168.1.10", "192.168.1.20",
            50000, 80, 1005, b"KLMNO", 1.2
        )
    )

    flow = list(tracker.flows.values())[0]

    print(
            "sloss:", flow["sloss"],
            "dloss:", flow["dloss"],
            "forward ranges:", flow["_forward_seq_ranges"],
            "backward ranges:", flow["_backward_seq_ranges"],
            "forward reference:", flow["_forward_seq_reference"],
            "backward reference:", flow["_backward_seq_reference"]
        )


    # Exact retransmission: 1000-1005
    tracker.process_packet(
        make_packet(
            "192.168.1.10", "192.168.1.20",
            50000, 80, 1000, b"ABCDE", 1.3
        )
    )

    flow = list(tracker.flows.values())[0]

    print(
            "sloss:", flow["sloss"],
            "dloss:", flow["dloss"],
            "forward ranges:", flow["_forward_seq_ranges"],
            "backward ranges:", flow["_backward_seq_ranges"],
            "forward reference:", flow["_forward_seq_reference"],
            "backward reference:", flow["_backward_seq_reference"]
        )


    # Partial overlap: 1003-1007
    tracker.process_packet(
        make_packet(
            "192.168.1.10", "192.168.1.20",
            50000, 80, 1003, b"DEFG", 1.4
        )
    )
    flow = list(tracker.flows.values())[0]

    print(
            "sloss:", flow["sloss"],
            "dloss:", flow["dloss"],
            "forward ranges:", flow["_forward_seq_ranges"],
            "backward ranges:", flow["_backward_seq_ranges"],
            "forward reference:", flow["_forward_seq_reference"],
            "backward reference:", flow["_backward_seq_reference"]
        )


    # --------------------------------
    # BACKWARD DIRECTION
    # --------------------------------

    # First backward segment: 5000-5005
    tracker.process_packet(
        make_packet(
            "192.168.1.20", "192.168.1.10",
            80, 50000, 5000, b"12345", 1.5
        )
    )
    flow = list(tracker.flows.values())[0]

    print(
            "sloss:", flow["sloss"],
            "dloss:", flow["dloss"],
            "forward ranges:", flow["_forward_seq_ranges"],
            "backward ranges:", flow["_backward_seq_ranges"],
            "forward reference:", flow["_forward_seq_reference"],
            "backward reference:", flow["_backward_seq_reference"]
        )


    # Second backward segment: 5005-5010
    tracker.process_packet(
        make_packet(
            "192.168.1.20", "192.168.1.10",
            80, 50000, 5005, b"67890", 1.6
        )
    )
    flow = list(tracker.flows.values())[0]

    print(
            "sloss:", flow["sloss"],
            "dloss:", flow["dloss"],
            "forward ranges:", flow["_forward_seq_ranges"],
            "backward ranges:", flow["_backward_seq_ranges"],
            "forward reference:", flow["_forward_seq_reference"],
            "backward reference:", flow["_backward_seq_reference"]
        )


    # Exact backward retransmission: 5000-5005
    tracker.process_packet(
        make_packet(
            "192.168.1.20", "192.168.1.10",
            80, 50000, 5000, b"12345", 1.7
        )
    )
    flow = list(tracker.flows.values())[0]

    print(
        "sloss:", flow["sloss"],
        "dloss:", flow["dloss"],
        "forward ranges:", flow["_forward_seq_ranges"],
        "backward ranges:", flow["_backward_seq_ranges"],
        "forward reference:", flow["_forward_seq_reference"],
        "backward reference:", flow["_backward_seq_reference"]
    )

    # Partial backward overlap: 5003-5007
    tracker.process_packet(
        make_packet(
            "192.168.1.20", "192.168.1.10",
            80, 50000, 5003, b"4567", 1.8
        )
    )
    flow = list(tracker.flows.values())[0]

    print(
            "sloss:", flow["sloss"],
            "dloss:", flow["dloss"],
            "forward ranges:", flow["_forward_seq_ranges"],
            "backward ranges:", flow["_backward_seq_ranges"],
            "forward reference:", flow["_forward_seq_reference"],
            "backward reference:", flow["_backward_seq_reference"]
        )


    # --------------------------------
    # VERIFY RESULTS
    # --------------------------------

    flows = tracker.get_flows()

    assert len(flows) == 1

    flow = flows[0]

    assert flow["sloss"] == 2
    assert flow["dloss"] == 2

    print("Forward retransmissions:", flow["sloss"])
    print("Backward retransmissions:", flow["dloss"])
