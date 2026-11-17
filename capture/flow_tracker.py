from scapy.all import IP, TCP, UDP
from time import time
from collections import deque
from capture.application_features import (
    initialize_application_features,
    process_application_packet,
    get_application_features,
)


class FlowTracker:
    SERVICE_PORTS = {
        ("tcp", 20): "ftp-data",
        ("tcp", 21): "ftp",
        ("tcp", 22): "ssh",
        ("tcp", 25): "smtp",
        ("tcp", 53): "dns",
        ("tcp", 80): "http",
        ("tcp", 110): "pop3",
        ("tcp", 443): "ssl",
        ("tcp", 6667): "irc",

        ("udp", 53): "dns",
        ("udp", 67): "dhcp",
        ("udp", 68): "dhcp",
        ("udp", 161): "snmp",
        ("udp", 162): "snmp",
        ("udp", 1812): "radius",
        ("udp", 1813): "radius",
    }
    def __init__(self, idle_timeout=60):

        self.flows = {}
        self.idle_timeout = idle_timeout
	        # Provisional rolling history of completed flow records.
        self.recent_flows = deque(maxlen=100)

    @staticmethod
    def identify_service(src_port, dst_port, proto):

        source_service = FlowTracker.SERVICE_PORTS.get(
            (proto, src_port)
        )

        destination_service = FlowTracker.SERVICE_PORTS.get(
            (proto, dst_port)
        )

        services = {
            service
            for service in (source_service, destination_service)
            if service is not None
        }

        # Return a service only when identification is unambiguous.
        if len(services) == 1:
            return services.pop()

        return "-"
    def update_tcp_retransmission(self, flow, direction, tcp):

        if tcp is None:
            return

        payload_length = len(tcp.payload)

        if payload_length == 0:
            return

        # TCP sequence numbers are 32-bit unsigned integers.
        SEQ_MOD = 2 ** 32

        flags = int(tcp.flags)

        # SYN consumes one sequence number.
        raw_seq = (
            int(tcp.seq) + (1 if flags & 0x02 else 0)
        ) % SEQ_MOD

        if direction == "forward":
            ranges_key = "_forward_seq_ranges"
            loss_key = "sloss"
            reference_key = "_forward_seq_reference"
        else:
            ranges_key = "_backward_seq_ranges"
            loss_key = "dloss"
            reference_key = "_backward_seq_reference"

        reference = flow[reference_key]

        # Convert the 32-bit sequence number into a continuous
        # internal sequence space, accounting for wraparound.
        if reference is None:
            seq_start = raw_seq
        else:
            base = (reference // SEQ_MOD) * SEQ_MOD

            candidates = [
                base + raw_seq - SEQ_MOD,
                base + raw_seq,
                base + raw_seq + SEQ_MOD,
            ]

            seq_start = min(
                candidates,
                key=lambda value: abs(value - reference)
            )

        seq_end = seq_start + payload_length

        ranges = flow[ranges_key]

        # Detect overlap with previously observed payload.
        retransmission = any(
            seq_start < existing_end
            and seq_end > existing_start
            for existing_start, existing_end in ranges
        )

        if retransmission:
            flow[loss_key] += 1

        # Merge overlapping or adjacent ranges.
        merged = []
        new_start = seq_start
        new_end = seq_end

        for existing_start, existing_end in ranges:

            if (
                existing_end < new_start
                or existing_start > new_end
            ):
                merged.append((existing_start, existing_end))

            else:
                new_start = min(new_start, existing_start)
                new_end = max(new_end, existing_end)

        merged.append((new_start, new_end))
        merged.sort()

        flow[ranges_key] = merged

        # Maintain the highest observed sequence endpoint.
        if reference is None:
            flow[reference_key] = seq_end
        else:
            flow[reference_key] = max(reference, seq_end)

    def process_packet(self, packet):

        if IP not in packet:
            return

        ip = packet[IP]

        # Identify protocol and ports
        if TCP in packet:
            proto = "tcp"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            tcp = packet[TCP]

        elif UDP in packet:
            proto = "udp"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            tcp = None

        else:
            proto = str(ip.proto)
            src_port = None
            dst_port = None
            tcp = None

        src = (ip.src, src_port)
        dst = (ip.dst, dst_port)

        # Canonical bidirectional flow key
        endpoints = tuple(sorted(
            [src, dst],
            key=lambda endpoint: (
                endpoint[0],
                -1 if endpoint[1] is None else endpoint[1]
            )
        ))

        flow_key = (proto, endpoints)

        timestamp = float(packet.time)
        packet_length = len(ip)

        # Create a new flow
        if flow_key not in self.flows:

            self.flows[flow_key] = {
                "proto": proto,
                "first_seen": timestamp,
                "last_seen": timestamp,
                "forward_source": src,
                "forward_destination": dst,

                # Basic statistics
                "spkts": 0,
                "dpkts": 0,
                "sbytes": 0,
                "dbytes": 0,

                # TTL statistics
                "_sttl": None,
                "_dttl": None,

                # Timing statistics
                "_forward_times": [],
                "_backward_times": [],
                "_forward_sizes": [],
                "_backward_sizes": [],

                # TCP retransmission tracking
                "_forward_seq_ranges": [],
                "_backward_seq_ranges": [],
                "_forward_seq_reference": None,
                "_backward_seq_reference": None,
                "sloss": 0,
                "dloss": 0,

                # TCP statistics
                "_swin": None,
                "_dwin": None,
                "_stcpb": None,
                "_dtcpb": None,

                # TCP handshake timestamps
                "_syn_time": None,
                "_synack_time": None,
                "_ack_time": None,
		                # Observed TCP connection-state evidence
                "_tcp_syn_seen": False,
                "_tcp_synack_seen": False,
                "_tcp_fin_forward": False,
                "_tcp_fin_backward": False,
                "_tcp_rst_seen": False,
            }
            initialize_application_features(self.flows[flow_key])
        flow = self.flows[flow_key]
        direction = (
            "forward"
            if src == flow["forward_source"]
            else "backward"
        )

        process_application_packet(flow, packet, direction)
        # Update directional statistics
        if src == flow["forward_source"]:
            self.update_tcp_retransmission(
                    flow, "forward", tcp
                )

            flow["spkts"] += 1
            flow["sbytes"] += packet_length

            if flow["_sttl"] is None:
                flow["_sttl"] = int(ip.ttl)

            flow["_forward_times"].append(timestamp)
            flow["_forward_sizes"].append(packet_length)

        else:
            self.update_tcp_retransmission(
                    flow, "backward", tcp
                )

            flow["dpkts"] += 1
            flow["dbytes"] += packet_length

            if flow["_dttl"] is None:
                flow["_dttl"] = int(ip.ttl)

            flow["_backward_times"].append(timestamp)
            flow["_backward_sizes"].append(packet_length)

        flow["last_seen"] = timestamp

        # TCP-specific processing
        if tcp is not None:

            flags = int(tcp.flags)
            # Observe TCP flags without assuming Argus state equivalence.
            if flags & 0x02:
                if flags & 0x10:
                    flow["_tcp_synack_seen"] = True
                else:
                    flow["_tcp_syn_seen"] = True

            if flags & 0x01:
                if src == flow["forward_source"]:
                    flow["_tcp_fin_forward"] = True
                else:
                    flow["_tcp_fin_backward"] = True

            if flags & 0x04:
                flow["_tcp_rst_seen"] = True

            syn = bool(flags & 0x02)
            ack = bool(flags & 0x10)

            if src == flow["forward_source"]:

                # First observed forward TCP window and sequence
                if flow["_swin"] is None:
                    flow["_swin"] = tcp.window

                if flow["_stcpb"] is None:
                    flow["_stcpb"] = tcp.seq

                # Initial SYN packet
                if syn and not ack:
                    if flow["_syn_time"] is None:
                        flow["_syn_time"] = timestamp

                # Final ACK packet
                elif ack and not syn:
                    if (
                        flow["_synack_time"] is not None
                        and flow["_ack_time"] is None
                        and timestamp >= flow["_synack_time"]
                    ):
                        flow["_ack_time"] = timestamp

            else:

                # First observed backward TCP window and sequence
                if flow["_dwin"] is None:
                    flow["_dwin"] = tcp.window

                if flow["_dtcpb"] is None:
                    flow["_dtcpb"] = tcp.seq

                # SYN-ACK packet
                if syn and ack:
                    if (
                        flow["_syn_time"] is not None
                        and flow["_synack_time"] is None
                        and timestamp >= flow["_syn_time"]
                    ):
                        flow["_synack_time"] = timestamp

    def calculate_timing_features(self, timestamps):
        # Returns (mean interpacket time, jitter) in MILLISECONDS.
        # Jitter = population standard deviation of the interpacket times.
        # Provisional: the dataset's values also include gaps across Argus records
        # and merge active/idle statistics, which this per-flow tracker cannot reproduce.

        if len(timestamps) < 2:
            return 0.0, 0.0

        intervals_ms = [
            (timestamps[i] - timestamps[i - 1]) * 1000.0
            for i in range(1, len(timestamps))
        ]

        mean_interval = sum(intervals_ms) / len(intervals_ms)

        variance = sum(
            (interval - mean_interval) ** 2 for interval in intervals_ms
        ) / len(intervals_ms)

        jitter = variance ** 0.5

        return mean_interval, jitter
    def calculate_connection_counts(self, flow):
        src_ip, src_port = flow["forward_source"]
        dst_ip, dst_port = flow["forward_destination"]

        service = self.identify_service(
            src_port,
            dst_port,
            flow["proto"],
        )

        current = {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "service": service,
        }

        history = list(self.recent_flows)[-99:] + [current]

        return {
            "ct_srv_src": sum(
                item["service"] == service
                and item["src_ip"] == src_ip
                for item in history
            ),

            "ct_dst_ltm": sum(
                item["dst_ip"] == dst_ip
                for item in history
            ),

            "ct_src_dport_ltm": sum(
                item["src_ip"] == src_ip
                and item["dst_port"] == dst_port
                for item in history
            ),

            "ct_dst_sport_ltm": sum(
                item["dst_ip"] == dst_ip
                and item["src_port"] == src_port
                for item in history
            ),

            "ct_dst_src_ltm": sum(
                item["dst_ip"] == dst_ip
                and item["src_ip"] == src_ip
                for item in history
            ),

            "ct_src_ltm": sum(
                item["src_ip"] == src_ip
                for item in history
            ),

            "ct_srv_dst": sum(
                item["service"] == service
                and item["dst_ip"] == dst_ip
                for item in history
            ),
        }
    def observe_connection_state(self, flow):
        """
        Summarize observed TCP state evidence.

        These labels describe packet observations.
        They are NOT guaranteed UNSW-NB15 Argus states.
        """

        if flow["proto"] != "tcp":
            return "NON_TCP"

        if flow["_tcp_rst_seen"]:
            return "RST_OBSERVED"

        if (
            flow["_tcp_fin_forward"]
            and flow["_tcp_fin_backward"]
        ):
            return "BOTH_FIN_OBSERVED"

        if (
            flow["_tcp_fin_forward"]
            or flow["_tcp_fin_backward"]
        ):
            return "FIN_OBSERVED"

        if flow["_tcp_synack_seen"]:
            return "SYNACK_OBSERVED"

        if flow["_tcp_syn_seen"]:
            return "SYN_OBSERVED"

        return "TCP_OBSERVED"

    def build_flow_record(self, flow):

        duration = flow["last_seen"] - flow["first_seen"]

        # Average packet sizes
        smean = (
            flow["sbytes"] / flow["spkts"]
            if flow["spkts"] > 0 else 0.0
        )

        dmean = (
            flow["dbytes"] / flow["dpkts"]
            if flow["dpkts"] > 0 else 0.0
        )

        # Rate and load: EMPIRICAL rules matched to UNSW-NB15 (not from the Argus source).
        # They are 0 when the duration is 0 or the direction has no packets,
        # which is how the dataset treats those rows.
        total_pkts = flow["spkts"] + flow["dpkts"]

        if duration > 0 and total_pkts > 0:
            rate = (total_pkts - 1) / duration
        else:
            rate = 0.0

        if duration > 0 and flow["spkts"] > 0:
            sload = smean * (flow["spkts"] - 1) * 8 / duration
        else:
            sload = 0.0

        if duration > 0 and flow["dpkts"] > 0:
            dload = dmean * (flow["dpkts"] - 1) * 8 / duration
        else:
            dload = 0.0

        # Inter-arrival times and jitter
        sinpkt, sjit = self.calculate_timing_features(
            flow["_forward_times"]
        )

        dinpkt, djit = self.calculate_timing_features(
            flow["_backward_times"]
        )

        # TCP handshake timing
        synack = None
        ackdat = None
        tcprtt = None

        if (
            flow["_syn_time"] is not None
            and flow["_synack_time"] is not None
        ):
            synack = (
                flow["_synack_time"] - flow["_syn_time"]
            )

        if (
            flow["_synack_time"] is not None
            and flow["_ack_time"] is not None
        ):
            ackdat = (
                flow["_ack_time"] - flow["_synack_time"]
            )

        if synack is not None and ackdat is not None:
            tcprtt = synack + ackdat

        return {
            "proto": flow["proto"],
            "first_seen": flow["first_seen"],
            "last_seen": flow["last_seen"],
            "forward_source": flow["forward_source"],
            "forward_destination": flow["forward_destination"],
	                # Same source/destination IP and port indicator
            "is_sm_ips_ports": int(
                flow["forward_source"][0] == flow["forward_destination"][0]
                and flow["forward_source"][1] is not None
                and flow["forward_destination"][1] is not None
                and flow["forward_source"][1] == flow["forward_destination"][1]
            ),

            # Basic statistics
            "spkts": flow["spkts"],
            "dpkts": flow["dpkts"],
            "sbytes": flow["sbytes"],
            "dbytes": flow["dbytes"],
            "dur": duration,

            # Service (port-based approximation; "-" when unknown or ambiguous)
            "service": self.identify_service(
                flow["forward_source"][1],
                flow["forward_destination"][1],
                flow["proto"],
            ),

                        # Diagnostic state evidence, not a model input.
            "observed_connection_state": self.observe_connection_state(flow),

            # TCP retransmission estimates
            "sloss": flow["sloss"],
            "dloss": flow["dloss"],

             # TTL statistics (first observed value per direction)
            "sttl": flow["_sttl"] if flow["_sttl"] is not None else 0,
            "dttl": flow["_dttl"] if flow["_dttl"] is not None else 0,

            # Rate and load (empirical rules, see build_flow_record)
            "rate": rate,
            "sload": sload,
            "dload": dload,

            # Packet-size statistics
            "smean": smean,
            "dmean": dmean,

            # Timing statistics
            "sinpkt": sinpkt,
            "dinpkt": dinpkt,
            "sjit": sjit,
            "djit": djit,

            # TCP window and sequence statistics
            "swin": flow["_swin"] if flow["_swin"] is not None else 0,
            "dwin": flow["_dwin"] if flow["_dwin"] is not None else 0,
            "stcpb": flow["_stcpb"] if flow["_stcpb"] is not None else 0,
            "dtcpb": flow["_dtcpb"] if flow["_dtcpb"] is not None else 0,

            # TCP handshake timing
            "synack": synack,
            "ackdat": ackdat,
            "tcprtt": tcprtt,
                        # Best-effort application-layer observations
            **get_application_features(flow),
	                # Provisional rolling connection statistics
            **self.calculate_connection_counts(flow),

        }

    def get_flows(self):

        return [
            self.build_flow_record(flow)
            for flow in self.flows.values()
        ]

    def expire_flows(self, current_time=None):

        if current_time is None:
            current_time = time()

        expired = []

        # Process expired flows in completion-time order.
        expired_items = sorted(
            (
                (key, flow)
                for key, flow in self.flows.items()
                if current_time - flow["last_seen"] >= self.idle_timeout
            ),
            key=lambda item: item[1]["last_seen"],
        )

        for key, flow in expired_items:

            record = self.build_flow_record(flow)

            expired.append(record)

            # Register this completed flow once.
            self.recent_flows.append({
                "src_ip": flow["forward_source"][0],
                "dst_ip": flow["forward_destination"][0],
                "src_port": flow["forward_source"][1],
                "dst_port": flow["forward_destination"][1],
                "service": record["service"],
            })

            del self.flows[key]

        return expired
