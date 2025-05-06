from scapy.all import IP, UDP, Raw, send
import sys
import time
import socket
import select
import threading
import queue
import logging
from src.tools.logger import Logger

log = Logger(log_file='SP_Log.log', log_level=logging.DEBUG)

# Thread-safe queues for inter-thread communication
outgoing_messages = queue.Queue()  # For messages to send out
incoming_messages = queue.Queue()  # For received messages


def network_thread(router_Number, queue_number):
    # Set up the socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock_ip = '172.16.0.'+str(router_Number)
    sock_port = 5000+queue_number
    sock.bind((sock_ip, sock_port))
    sock.setblocking(False)  # Make socket non-blocking

    inputs = [sock]  # Sockets to monitor for input
    outputs = []     # Sockets to monitor for output capability

    while True:
        # Check if we need to monitor for output capability
        if not outgoing_messages.empty() and sock not in outputs:
            outputs.append(sock)

        # Use select to monitor sockets without blocking
        readable, writable, exceptional = select.select(inputs, outputs, inputs, 0.1)

        # Handle readable sockets (incoming data)
        for s in readable:
            if s is sock:
                try:
                    data, addr = sock.recvfrom(1024)
                    #log.log(f"Received {len(data)} bytes {data} from {addr}", logging.INFO)
                    # Put received message in queue for processing thread
                    incoming_messages.put((data, addr))
                except Exception as e:
                    log.log(f"Error receiving data: {e}", logging.WARNING)

        # Handle writable sockets (ready to send)
        for s in writable:
            if s is sock and not outgoing_messages.empty():
                try:
                    message, destination = outgoing_messages.get_nowait()
                    sock.sendto(message, destination)
                    log.log(f"Sent {message} to {destination}", logging.INFO)
                    outgoing_messages.task_done()
                except queue.Empty:
                    # If we've sent all messages, stop monitoring for output
                    outputs.remove(sock)
                except Exception as e:
                    log.log(f"Error sending to {destination}: {e}", logging.WARNING)
                    outgoing_messages.task_done()

        # Handle exceptional conditions
        for s in exceptional:
            log.log(f"Exception condition on {s}", logging.ERROR)


class Intra_Sys_Com():
    def __init__(self, router_id):
        self.router_id = router_id
        self.listen_ip = '172.16.0.'+str(router_id)

    def udp_send_receive(self, target_ips, target_port, message):
        """
        Send UDP packets and receive responses using separate sockets.
        Works correctly when sending to self (same IP).
        """
        # Ensure port is an integer
        target_port = int(target_port)

        print(f"UDP Packet Tool - Target: {target_ips}:{target_port}")

        # Create separate socket for receiving
        recv_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # Set SO_REUSEADDR to allow binding to a port that might be in use
        recv_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # Bind to the same port we're targeting (so we can receive our own packets)
        recv_socket.bind(('172.16.0.1', target_port))
        recv_socket.setblocking(0)  # Non-blocking mode

        # Create separate socket for sending
        send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        try:
            # Prepare and send packet using standard socket (not Scapy)
            if target_ips != None:
                for target_ip in target_ips:
                    full_message = f"{message} (Source: router {self.router_id})"
                    send_socket.sendto(full_message.encode('utf-8'), (target_ip, target_port))
                    print(f"Sent to {target_ip}:{target_port} - {full_message}")

            # Check for any incoming packets (with timeout)
            ready = select.select([recv_socket], [], [], 0.1)  # Short timeout
            if ready[0]:
                try:
                    data, addr = recv_socket.recvfrom(4096)
                    print(f"Received from {addr[0]}:{addr[1]} - Length: {len(data)} bytes")
                    try:
                        decoded = data.decode('utf-8')
                        print(f"  Data: {decoded}")
                    except UnicodeDecodeError:
                        print(f"  Data (hex): {data.hex()}")
                except socket.error as e:
                    print(f"Socket error: {e}")

            # Wait before sending next packet
            # time.sleep(1)

        except KeyboardInterrupt:
            print("\nProgram stopped by user")
        finally:
            recv_socket.close()
            send_socket.close()


def main():

    target_ip = "172.16.0.1"

    target_port = 5565

    # Default message if not provided
    message = "Hello UDP!"

    # Start sending and receiving packets
    poopie = Intra_Sys_Com(1)
    poopie.udp_send_receive(target_ip, target_port, message)


if __name__ == "__main__":
    main()
