from scapy.all import sniff, conf, IP, TCP, UDP
from datetime import datetime


# AIDAS Live Network Capture
# Passive packet monitoring only


INTERFACE_INDEX = 22
PACKET_COUNT = 20


def process_packet(packet):

    if IP in packet:

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        source_ip = packet[IP].src
        destination_ip = packet[IP].dst
        protocol = packet[IP].proto
        packet_length = len(packet)
        ttl = packet[IP].ttl

        if TCP in packet:
            protocol_name = "TCP"
            source_port = packet[TCP].sport
            destination_port = packet[TCP].dport

        elif UDP in packet:
            protocol_name = "UDP"
            source_port = packet[UDP].sport
            destination_port = packet[UDP].dport

        else:
            protocol_name = str(protocol)
            source_port = "-"
            destination_port = "-"

        print("\n----------------------------------------")
        print("AIDAS - Network Packet Captured")
        print("----------------------------------------")

        print("Timestamp       :", timestamp)
        print("Source IP       :", source_ip)
        print("Destination IP  :", destination_ip)
        print("Protocol        :", protocol_name)
        print("Source Port     :", source_port)
        print("Destination Port:", destination_port)
        print("Packet Length   :", packet_length, "bytes")
        print("TTL             :", ttl)


def start_capture():

    interface = conf.ifaces.dev_from_index(INTERFACE_INDEX)

    print("========================================")
    print("       AIDAS LIVE NETWORK MONITOR")
    print("========================================")

    print("Interface:", interface.name)
    print("Maximum packets:", PACKET_COUNT)
    print("\nStarting passive packet capture...\n")

    sniff(
        iface=interface,
        filter="ip",
        prn=process_packet,
        count=PACKET_COUNT,
        store=False
    )

    print("\n========================================")
    print("Packet capture completed.")
    print("========================================")


if __name__ == "__main__":
    try:
        start_capture()

    except KeyboardInterrupt:
        print("\nCapture stopped by user.")

    except Exception as error:
        print("\nCapture error:", error)