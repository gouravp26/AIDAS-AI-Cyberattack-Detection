"""Best-effort passive HTTP/FTP feature extraction for AIDAS."""

from scapy.layers.inet import TCP
from scapy.packet import Raw


HTTP_METHODS = {
    b"GET", b"POST", b"PUT", b"DELETE",
    b"HEAD", b"OPTIONS", b"PATCH", b"TRACE", b"CONNECT",
}

FTP_COMMANDS = {
    b"USER", b"PASS", b"ACCT", b"CWD", b"CDUP",
    b"QUIT", b"REIN", b"PORT", b"PASV", b"TYPE",
    b"STRU", b"MODE", b"RETR", b"STOR", b"STOU",
    b"APPE", b"ALLO", b"REST", b"RNFR", b"RNTO",
    b"ABOR", b"DELE", b"RMD", b"MKD", b"PWD",
    b"LIST", b"NLST", b"SITE", b"SYST", b"STAT",
    b"HELP", b"NOOP", b"FEAT", b"OPTS", b"AUTH",
    b"PBSZ", b"PROT", b"EPSV", b"EPRT",
}


def initialize_application_features(flow):
    flow["_app_buffers"] = {"forward": b"", "backward": b""}
    flow["_app_next_seq"] = {"forward": None, "backward": None}
    flow["_http_methods"] = 0
    flow["_http_transactions"] = 0
    flow["_http_response_body_len"] = 0
    flow["_ftp_commands"] = 0
    flow["_ftp_login"] = 0
    flow["_ftp_user_seen"] = False
    flow["_ftp_pass_seen"] = False


def process_application_packet(flow, packet, direction):
    """
    Best-effort plaintext HTTP/FTP inspection.

    Supports in-order TCP payloads and contiguous retransmissions.
    Does not reconstruct out-of-order segments or encrypted traffic.
    """
    if TCP not in packet or Raw not in packet:
        return

    tcp = packet[TCP]
    payload = bytes(packet[Raw].load)

    if not payload:
        return

    src_port = flow["forward_source"][1]
    dst_port = flow["forward_destination"][1]
    ports = {src_port, dst_port}

    if 80 not in ports and 21 not in ports:
        return

    next_seq = flow["_app_next_seq"][direction]
    seq = int(tcp.seq)

    if next_seq is not None:
        overlap = next_seq - seq

        if overlap > 0:
            if overlap >= len(payload):
                return
            payload = payload[overlap:]

        elif overlap < 0:
            # Missing TCP segment: discard incomplete buffered message.
            flow["_app_buffers"][direction] = b""
            # The following payload may start mid-message.
            # Do not interpret it as a complete message.
            flow["_app_next_seq"][direction] = seq + len(payload)
            return

    flow["_app_next_seq"][direction] = seq + len(payload)

    buffer = flow["_app_buffers"][direction] + payload

    # Bound retained data to avoid unbounded memory growth.
    if len(buffer) > 65536:
        buffer = buffer[-65536:]

    if 80 in ports:
        buffer = process_http(flow, buffer, direction)

    elif 21 in ports:
        buffer = process_ftp(flow, buffer, direction)

    flow["_app_buffers"][direction] = buffer


def process_http(flow, buffer, direction):
    while b"\r\n\r\n" in buffer:
        headers, remainder = buffer.split(b"\r\n\r\n", 1)
        lines = headers.split(b"\r\n")

        if not lines:
            break

        first_line = lines[0]
        tokens = first_line.split()

        content_length = None

        for line in lines[1:]:
            if line.lower().startswith(b"content-length:"):
                try:
                    content_length = int(line.split(b":", 1)[1].strip())
                except ValueError:
                    content_length = None

        if content_length is not None and content_length > len(remainder):
            # Wait for the complete message.
            break

        body_length = content_length if content_length is not None else 0

        if tokens and tokens[0] in HTTP_METHODS:
            flow["_http_methods"] += 1
            flow["_http_transactions"] += 1

        elif first_line.startswith(b"HTTP/"):
            flow["_http_response_body_len"] += body_length

        buffer = remainder[body_length:]

    return buffer


def process_ftp(flow, buffer, direction):
    while b"\r\n" in buffer:
        line, buffer = buffer.split(b"\r\n", 1)
        tokens = line.strip().split(None, 1)

        if not tokens:
            continue

        command = tokens[0].upper()

        if command in FTP_COMMANDS:
            flow["_ftp_commands"] += 1

            if command == b"USER":
                flow["_ftp_user_seen"] = True

            elif command == b"PASS":
                flow["_ftp_pass_seen"] = True

        elif line.startswith(b"230 ") or line.startswith(b"230-"):
            if flow["_ftp_user_seen"]:
                flow["_ftp_login"] = 1

    return buffer


def get_application_features(flow):
    return {
        "trans_depth": flow["_http_transactions"],
        "response_body_len": flow["_http_response_body_len"],
        "is_ftp_login": flow["_ftp_login"],
        "ct_ftp_cmd": flow["_ftp_commands"],
        "ct_flw_http_mthd": flow["_http_methods"],
    }
