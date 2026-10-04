from scapy.all import sniff, wrpcap, IP, TCP, UDP, ICMP, ARP, DNS, DNSQR


# ============================================================
# Traffic Statistics
# ============================================================

stats = {
    "TCP": 0,
    "UDP": 0,
    "ICMP": 0,
    "ARP": 0,
    "DNS": 0,
    "Other IP": 0
}


# ============================================================
# Detailed Traffic Statistics
# ============================================================

tcp_destination_ports = {}
host_communication = {}


# ============================================================
# Anomaly Detection Statistics
# ============================================================

anomaly_stats = {
    "TCP port scans": 0,
    "ICMP anomalies": 0,
    "ARP anomalies": 0,
    "DNS anomalies": 0
}


# ============================================================
# Detection Thresholds
# ============================================================

PORT_SCAN_THRESHOLD = 10
ICMP_THRESHOLD = 20
DNS_THRESHOLD = 15


# ============================================================
# TCP Port Scan Detection
# ============================================================

port_scan_tracker = {}
alerted_scans = set()


def detect_port_scan(packet):

    if IP in packet and TCP in packet:

        if packet[TCP].flags == "S":

            src = packet[IP].src
            dst = packet[IP].dst
            dst_port = packet[TCP].dport

            connection = (src, dst)

            if connection not in port_scan_tracker:
                port_scan_tracker[connection] = set()

            port_scan_tracker[connection].add(dst_port)

            unique_ports = len(port_scan_tracker[connection])

            if (
                unique_ports == PORT_SCAN_THRESHOLD
                and connection not in alerted_scans
            ):

                alerted_scans.add(connection)

                anomaly_stats["TCP port scans"] += 1

                print(
                    f"\n[ALERT] Possible TCP port scan detected: "
                    f"{src} -> {dst} "
                    f"({unique_ports} unique TCP ports)\n"
                )


# ============================================================
# ICMP Anomaly Detection
# ============================================================

def detect_icmp_anomaly():

    if stats["ICMP"] == ICMP_THRESHOLD:

        anomaly_stats["ICMP anomalies"] += 1

        print(
            f"\n[ALERT] Possible ICMP traffic spike detected: "
            f"{stats['ICMP']} ICMP packets\n"
        )


# ============================================================
# ARP Anomaly Detection
# ============================================================

arp_ip_mac_tracker = {}
alerted_arp = set()


def detect_arp_anomaly(packet):

    if ARP in packet:

        if packet[ARP].op == 2:

            ip_address = packet[ARP].psrc
            mac_address = packet[ARP].hwsrc

            if ip_address not in arp_ip_mac_tracker:

                arp_ip_mac_tracker[ip_address] = mac_address

            else:

                known_mac = arp_ip_mac_tracker[ip_address]

                if (
                    known_mac != mac_address
                    and ip_address not in alerted_arp
                ):

                    alerted_arp.add(ip_address)

                    anomaly_stats["ARP anomalies"] += 1

                    print(
                        f"\n[ALERT] Possible ARP inconsistency detected: "
                        f"{ip_address} changed from "
                        f"{known_mac} to {mac_address}\n"
                    )


# ============================================================
# DNS Anomaly Detection
# ============================================================

dns_request_tracker = {}
alerted_dns = set()


def detect_dns_anomaly(packet):

    if DNS in packet and IP in packet and DNSQR in packet:

        if packet[DNS].qr == 0:

            src = packet[IP].src

            if src not in dns_request_tracker:
                dns_request_tracker[src] = 0

            dns_request_tracker[src] += 1

            request_count = dns_request_tracker[src]

            if (
                request_count == DNS_THRESHOLD
                and src not in alerted_dns
            ):

                alerted_dns.add(src)

                anomaly_stats["DNS anomalies"] += 1

                print(
                    f"\n[ALERT] Possible unusual DNS request "
                    f"pattern detected: "
                    f"{src} sent {request_count} DNS queries\n"
                )


# ============================================================
# Packet Analysis
# ============================================================

def analyze(packet):

    detect_port_scan(packet)
    detect_arp_anomaly(packet)
    detect_dns_anomaly(packet)


    # ----------------------------------------
    # ARP
    # ----------------------------------------

    if ARP in packet:

        stats["ARP"] += 1

        print(
            f"[ARP] {packet[ARP].psrc} -> "
            f"{packet[ARP].pdst}"
        )

        return


    # ----------------------------------------
    # IP
    # ----------------------------------------

    if IP in packet:

        src = packet[IP].src
        dst = packet[IP].dst

        connection = (src, dst)

        if connection not in host_communication:
            host_communication[connection] = 0

        host_communication[connection] += 1


        # ------------------------------------
        # TCP
        # ------------------------------------

        if TCP in packet:

            stats["TCP"] += 1

            dst_port = packet[TCP].dport

            if dst_port not in tcp_destination_ports:
                tcp_destination_ports[dst_port] = 0

            tcp_destination_ports[dst_port] += 1

            print(
                f"[TCP] {src}:{packet[TCP].sport} "
                f"-> {dst}:{packet[TCP].dport} "
                f"[{packet[TCP].flags}]"
            )


        # ------------------------------------
        # UDP
        # ------------------------------------

        elif UDP in packet:

            stats["UDP"] += 1

            if DNS in packet:

                print(
                    f"[DNS] {src}:{packet[UDP].sport} "
                    f"-> {dst}:{packet[UDP].dport}"
                )

            else:

                print(
                    f"[UDP] {src}:{packet[UDP].sport} "
                    f"-> {dst}:{packet[UDP].dport}"
                )


        # ------------------------------------
        # ICMP
        # ------------------------------------

        elif ICMP in packet:

            stats["ICMP"] += 1

            print(
                f"[ICMP] {src} -> {dst}"
            )

            detect_icmp_anomaly()


        # ------------------------------------
        # Other IP
        # ------------------------------------

        else:

            stats["Other IP"] += 1

            print(
                f"[IP] {src} -> {dst}"
            )


# ============================================================
# Generate Automated Analysis Report
# ============================================================

def generate_report(packets):

    # Recalculate DNS directly from captured packets.
    dns_count = sum(
        DNS in packet
        for packet in packets
    )

    stats["DNS"] = dns_count


    with open("analysis_report.txt", "w") as report:

        report.write(
            "=== Network Traffic Analysis Report ===\n\n"
        )

        report.write(
            f"Total packets: {len(packets)}\n\n"
        )


        # ----------------------------------------
        # Protocol Distribution
        # ----------------------------------------

        report.write(
            "=== Protocol Distribution ===\n"
        )

        for protocol, count in stats.items():

            report.write(
                f"{protocol:<12}: {count}\n"
            )


        # ----------------------------------------
        # Top TCP Destination Ports
        # ----------------------------------------

        report.write(
            "\n=== Top TCP Destination Ports ===\n"
        )

        if tcp_destination_ports:

            top_ports = sorted(
                tcp_destination_ports.items(),
                key=lambda item: item[1],
                reverse=True
            )[:10]

            for port, count in top_ports:

                report.write(
                    f"Port {port:<5}: "
                    f"{count} packets\n"
                )

        else:

            report.write(
                "No TCP traffic detected.\n"
            )


        # ----------------------------------------
        # Top Communicating Hosts
        # ----------------------------------------

        report.write(
            "\n=== Top Communicating Hosts ===\n"
        )

        if host_communication:

            top_hosts = sorted(
                host_communication.items(),
                key=lambda item: item[1],
                reverse=True
            )[:10]

            for (src, dst), count in top_hosts:

                report.write(
                    f"{src} -> {dst}: "
                    f"{count} packets\n"
                )

        else:

            report.write(
                "No IP communication detected.\n"
            )


        # ----------------------------------------
        # Anomaly Detection
        # ----------------------------------------

        report.write(
            "\n=== Anomaly Detection ===\n"
        )

        for anomaly, count in anomaly_stats.items():

            report.write(
                f"{anomaly:<24}: {count}\n"
            )


# ============================================================
# Start Packet Capture
# ============================================================

print("=== Network Packet Analyzer ===")
print("Capturing packets...")
print("Press Ctrl+C to stop.\n")


packets = []


try:

    packets = sniff(
        prn=analyze
    )


except KeyboardInterrupt:

    print("\nCapture stopped.")


finally:

    # Save PCAP first.
    wrpcap(
        "capture.pcap",
        packets
    )

    print(
        "\nSaved to capture.pcap"
    )


    # Generate report from captured packets.
    generate_report(
        packets
    )

    print(
        "Saved to analysis_report.txt"
    )


    # ----------------------------------------
    # Final Console Summary
    # ----------------------------------------

    print(
        "\n=== Traffic Analysis Summary ==="
    )

    for protocol, count in stats.items():

        print(
            f"{protocol:<12}: {count}"
        )


    print(
        "\n=== Anomaly Detection Summary ==="
    )

    for anomaly, count in anomaly_stats.items():

        print(
            f"{anomaly:<24}: {count}"
        )
