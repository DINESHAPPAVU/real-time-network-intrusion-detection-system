
import argparse
import sqlite3
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path

from scapy.all import IP, TCP, sniff

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "data" / "ids.db"

connections = defaultdict(deque)
last_alert = {}

def current_time():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

def get_connection():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.execute("PRAGMA journal_mode=WAL")
    return conn

def initialize_database():
    with get_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS traffic (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                source_ip TEXT,
                destination_ip TEXT,
                protocol TEXT,
                destination_port INTEGER,
                tcp_flags TEXT
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                source_ip TEXT,
                alert_type TEXT,
                severity TEXT,
                description TEXT
            )
        """)

def save_alert(source, alert_type, severity, description):
    with get_connection() as conn:
        conn.execute("""
            INSERT INTO alerts
            (timestamp, source_ip, alert_type, severity, description)
            VALUES (?, ?, ?, ?, ?)
        """, (
            current_time(),
            source,
            alert_type,
            severity,
            description
        ))

    print(f"[ALERT] {severity} | {source} | {description}")

def process_packet(packet, threshold, window):
    if IP not in packet:
        return

    ip = packet[IP]
    source = ip.src
    destination = ip.dst

    protocol = "OTHER"
    destination_port = None
    flags = ""

    if TCP in packet:
        tcp = packet[TCP]

        protocol = "TCP"
        destination_port = int(tcp.dport)
        flags = str(tcp.flags)

    elif packet.haslayer("UDP"):
        protocol = "UDP"

    with get_connection() as conn:
        conn.execute("""
            INSERT INTO traffic
            (timestamp, source_ip, destination_ip,
             protocol, destination_port, tcp_flags)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            current_time(),
            source,
            destination,
            protocol,
            destination_port,
            flags
        ))

    if TCP not in packet:
        return

    tcp_flags = int(packet[TCP].flags)

    # Identify TCP SYN packets without ACK
    is_syn = (tcp_flags & 0x02) and not (tcp_flags & 0x10)

    if not is_syn:
        return

    now = time.time()

    connections[source].append((now, destination_port))

    # Remove expired connection attempts
    while connections[source] and now - connections[source][0][0] > window:
        connections[source].popleft()

    unique_ports = {
        port for timestamp, port in connections[source]
    }

    # Detect possible port scanning
    if len(unique_ports) >= threshold:

        previous_alert = last_alert.get(source, 0)

        if now - previous_alert >= 30:

            severity = "HIGH" if len(unique_ports) >= threshold * 2 else "MEDIUM"

            description = (
                f"Possible TCP port scan detected. "
                f"{len(unique_ports)} unique destination ports "
                f"within {window} seconds."
            )

            save_alert(
                source,
                "PORT_SCAN",
                severity,
                description
            )

            last_alert[source] = now

def main():
    parser = argparse.ArgumentParser(
        description="Real-Time Network Intrusion Detection System"
    )

    parser.add_argument(
        "-i", "--interface",
        required=True,
        help="Network interface to monitor"
    )

    parser.add_argument(
        "-t", "--threshold",
        type=int,
        default=10
    )

    parser.add_argument(
        "-w", "--window",
        type=int,
        default=10
    )

    args = parser.parse_args()

    if args.threshold < 2 or args.window < 1:
        parser.error("Threshold must be at least 2 and window at least 1")

    initialize_database()

    print("=" * 55)
    print(" REAL-TIME NETWORK INTRUSION DETECTION SYSTEM")
    print("=" * 55)
    print(f"Interface : {args.interface}")
    print(f"Threshold : {args.threshold} ports")
    print(f"Time window: {args.window} seconds")
    print("Monitoring started. Press CTRL+C to stop.")
    print("=" * 55)

    try:
        sniff(
            iface=args.interface,
            filter="ip",
            prn=lambda packet: process_packet(
                packet, args.threshold, args.window
            ),
            store=False,
            promisc=False
        )

    except KeyboardInterrupt:
        print("\nIDS monitoring stopped.")

    except Exception as error:
        print(f"\nIDS error: {error}")
        raise

if __name__ == "__main__":
    main()


