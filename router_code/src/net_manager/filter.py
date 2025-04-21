#!/usr/bin/env python3
import socket
import struct
import time
from netfilterqueue import NetfilterQueue
from scapy.all import IP
#from src.net_manager.intra_sys_coms import Intra_Sys_Com
from src.route_setup.route_setup import RouterSetup
from src.net_manager.buffer import PacketBuffer
from src.net_manager.rules import Rules
import threading
import queue
from src.net_manager.intra_sys_coms import network_thread, outgoing_messages, incoming_messages
import logging
from src.tools.logger import Logger
import subprocess
from src.net_manager.arp_protection import set_arp_protection_level
log = Logger(log_file='SP_Log.log', log_level=logging.DEBUG)

class Filter():
    def __init__(self, queue_num, router_id, pacify = False):
        
        try:
            # Start the network thread
            self.router_id = router_id
            self.network_thread = threading.Thread(
                target=network_thread,
                daemon=True,
                args=(router_id, queue_num))
            self.network_thread.start()

            self.pacify = pacify
            set_arp_protection_level(1)
            subprocess.run([
            'sudo', 'ip', 'neigh', 'flush', 'all'
            ], check=True)
            
            #self.coms = Intra_Sys_Com(router_id)
            # Create a new NetfilterQueue object
            self.nfqueue = NetfilterQueue()
            # Bind to queue number 1
            # Make sure your iptables rule uses the same queue number
            self.nfqueue.bind(queue_num, self.print_and_check)
            log.log(f"[*] Waiting for packets in NFQUEUE {queue_num}...", logging.INFO)
            print("[*] Press Ctrl+C to exit")

            freq = 0.2
            self.period = 1/freq

            self.packer_buffer = PacketBuffer()
            self.rules = Rules()
            self.time_last_exec = time.time()
            # Run the packet processing loop
            self.nfqueue.run()
        
        except socket.error as e:
            log.log(f"\n[!] Socket error: {e}", logging.ERROR)
            log.log("[!] Are you running as root?", logging.ERROR)
        except Exception as e:
            log.log(f"\n[!] Error: {e}", logging.ERROR)
        finally:
            # Unbind from the queue when done
            try:
                self.nfqueue.unbind()
            except:
                pass            

    # Example: Sending a message
    def send_example(self, dest, message_txt = ""):
        message = message_txt.encode()
        #message = "Hello, UDP world!".encode()
        destination = (dest, 5002) 
        outgoing_messages.put((message, destination))
        log.log(f"Queued message to {destination}", logging.INFO)

    # Example: Reading received messages
    def read_messages(self):
        messages = []
        while True:
            try:
                data, addr = incoming_messages.get_nowait()
                log.log(f"Processing message from {addr}: {data}", logging.INFO)
                messages.append(str(data))
                incoming_messages.task_done()
            except queue.Empty:
                log.log("No messages to process", logging.INFO)
                break

        return messages




    def print_and_check(self, pkt):
        """
        Callback function that prints packet info and accepts the packet
        to be forwarded through iptables
        """       
        # Convert the packet payload to a scapy IP packet for easier parsing
        ip_packet = IP(pkt.get_payload())
        if self.pacify:
            flag = ""
            # If TCP or UDP, print port information
            if ip_packet.haslayer('TCP'):
                tcp_layer = ip_packet['TCP']            # Now you can access TCP properties

                # Check for SYN flag
                if tcp_layer.flags & 0x02:  # 0x02 is the SYN flag
                    #print("SYN flag is set")
                    flag = "SYN"
                    
            self.packer_buffer.add_packet(ip_packet)
            time_current = time.time()

            if time_current - self.time_last_exec > self.period:
                
                self.time_last_exec = time_current
                in_messages = self.read_messages()
                self.rules.clear_rules(time_current)
                #for messages in in_messages:
                    #print(str(in_messages))
                self.rules.add_rules(in_messages)
                results, new_rules = self.packer_buffer.analyze_packet_patterns()
                #self.rules.add_rules_arp()
                for out_message in new_rules:
                    dest = "172.16.0."+str(self.router_id)
                    self.send_example(dest, out_message)
                #self.send_example("src/10.1.0.55/None/5")
                
            
            # Accept the packet - this puts it back into the iptables flow to be forwarded
            if self.rules.blocking_rules(ip_packet.src, ip_packet.dst, flag):
                pkt.accept()
                #log.log("Packet accepted for forwarding", logging.INFO)
            else:
                pkt.drop()
                #log.log("Packet rejected for forwarding", logging.INFO)
        else:
            pkt.accept()

