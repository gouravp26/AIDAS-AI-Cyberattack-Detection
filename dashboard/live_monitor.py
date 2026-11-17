import threading

from scapy.all import AsyncSniffer, conf, IP

from capture.flow_tracker import FlowTracker


class LiveMonitor:

    def __init__(self):
        self.tracker = FlowTracker()
        self.sniffer = None
        self.lock = threading.RLock()

        self.running = False
        self.packet_count = 0
        self.last_error = None
        self.interface_name = None

    # -----------------------------------------
    # PROCESS CAPTURED PACKETS
    # -----------------------------------------

    def process_packet(self, packet):

        if IP not in packet:
            return

        with self.lock:
            try:
                self.tracker.process_packet(packet)
                self.packet_count += 1

            except Exception as error:
                self.last_error = str(error)

    # -----------------------------------------
    # START LIVE CAPTURE
    # -----------------------------------------

    def start(self, interface_index=22):

        with self.lock:

            if self.running:
                return {
                    "success": False,
                    "message": "Capture is already running"
                }

            try:
                interface = conf.ifaces.dev_from_index(
                    int(interface_index)
                )

                self.tracker = FlowTracker()
                self.packet_count = 0
                self.last_error = None

                self.interface_name = interface.name

                self.sniffer = AsyncSniffer(
                    iface=interface,
                    filter="ip",
                    prn=self.process_packet,
                    store=False
                )

                self.sniffer.start()

                self.running = True

                return {
                    "success": True,
                    "message": "Live capture started",
                    "interface": self.interface_name
                }

            except Exception as error:

                self.running = False
                self.last_error = str(error)

                return {
                    "success": False,
                    "message": str(error)
                }

    # -----------------------------------------
    # STOP LIVE CAPTURE
    # -----------------------------------------

    def stop(self):

        with self.lock:

            if not self.running:
                return {
                    "success": False,
                    "message": "Capture is not running"
                }

            sniffer = self.sniffer

        try:

            sniffer.stop(join=True)

            with self.lock:
                self.running = False

            return {
                "success": True,
                "message": "Capture stopped"
            }

        except Exception as error:

            with self.lock:
                self.last_error = str(error)

            return {
                "success": False,
                "message": str(error)
            }

    # -----------------------------------------
    # GET CAPTURE STATUS
    # -----------------------------------------

    def get_status(self):

        with self.lock:

            sniffer_active = bool(
                self.sniffer is not None
                and self.sniffer.running
            )

            return {
                "running": self.running and sniffer_active,
                "packet_count": self.packet_count,
                "interface": self.interface_name,
                "last_error": self.last_error,
                "live_ml_validated": False
            }

    # -----------------------------------------
    # GET NETWORK FLOWS
    # -----------------------------------------

    def get_flows(self):

        with self.lock:

            flows = self.tracker.get_flows()

            result = []

            for flow in flows:

                source = flow.get(
                    "forward_source"
                ) or ("", "")

                destination = flow.get(
                    "forward_destination"
                ) or ("", "")

                result.append({

                    "src_ip": str(source[0]),

                    "dst_ip": str(destination[0]),

                    "src_port": source[1],

                    "dst_port": destination[1],

                    "proto": flow.get(
                        "proto", ""
                    ),

                    "service": flow.get(
                        "service", ""
                    ),

                    "spkts": flow.get(
                        "spkts", 0
                    ),

                    "dpkts": flow.get(
                        "dpkts", 0
                    ),

                    "sbytes": flow.get(
                        "sbytes", 0
                    ),

                    "dbytes": flow.get(
                        "dbytes", 0
                    ),

                    "dur": flow.get(
                        "dur", 0
                    ),

                    "observed_connection_state": flow.get(
                        "observed_connection_state", ""
                    )

                })

            return result


# -----------------------------------------
# GLOBAL MONITOR INSTANCE
# -----------------------------------------

monitor = LiveMonitor()