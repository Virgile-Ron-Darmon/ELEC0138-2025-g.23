import threading
import time
from src.net_manager.rules import Rule
import logging
from src.tools.logger import Logger
from collections import Counter, defaultdict
import subprocess
import re
from src.net_manager.arp_protection import set_arp_protection_level

log = Logger(log_file='SP_Log.log', log_level=logging.DEBUG)

class PacketBuffer:
    def __init__(self, max_size=1000, processing_interval=0.5):
        self.buffer = []
        self.max_size = max_size
        self.processing_interval = processing_interval
        self.last_processed = time.time()
        self.current_mac = get_mac_addresses()
        self.past_mac = self.current_mac
        
    
    def add_packet(self, packet):
        """Add packet to buffer, process if needed"""
    
        self.buffer.append(packet)
        
        # Process buffer if it's full or enough time has passed
        current_time = time.time()
        if (len(self.buffer)) >= self.max_size:
            #current_time - self.last_processed > self.processing_interval):
            #self.process_buffer()
            pass
        

    def process_buffer(self):
        """Process all packets in buffer"""
        packets_to_process = self.buffer.copy()
        self.buffer = []
        self.last_processed = time.time()
        
        log.log(f"===== Starting Buffer Analysis - {len(packets_to_process)} packets to analyse =====", logging.INFO)
        try:
            # Apply batch processing logic
            for packet in packets_to_process:
                pass
                #self.process_packet(packet)

            
        finally:
            pass


    def analyze_packet_patterns(self):
        total_packets = len(self.buffer)
        log.log(f"=====> {total_packets} Packets in Buffer", logging.DEBUG)

        results = {}

        # Pattern 1: TCP SYN to port 22 (SSH)
        ssh_syn_connections = set()
        ssh_syn_packets = 0

        # SSH brute force detection
        ssh_attempts_by_source = defaultdict(Counter)
        ssh_brute_force_threshold = 5  # Adjust based on your environment
        ssh_brute_force_packets = 0
        ssh_brute_force_sources = set()

        # Pattern 2: SYN flood detection
        syn_counts_by_destination = defaultdict(int)
        syn_flood_threshold = 10  # Adjust this threshold as needed

        # Pattern 3: Unique MAC addresses
        mac_addresses = set()

        for ip_packet in self.buffer:
            flag = None
            # If TCP or UDP, print port information
            if ip_packet.haslayer('TCP'):
                tcp_layer = ip_packet['TCP']            # Now you can access TCP properties

                # Check for SYN flag
                if tcp_layer.flags & 0x02:  # 0x02 is the SYN flag
                    #print("SYN flag is set")
                    flag = "SYN"
                    #print("trallalero Tralala")

                    if ip_packet.dport == 22:
                        connection = (ip_packet.src, ip_packet.dst)
                        ssh_syn_connections.add(connection)
                        ssh_syn_packets += 1

                        # SSH brute force detection
                        ssh_attempts_by_source[ip_packet.src][ip_packet.dst] += 1

                        # Check if this source has made multiple attempts to the same destination
                        if ssh_attempts_by_source[ip_packet.src][ip_packet.dst] >= ssh_brute_force_threshold:
                            ssh_brute_force_sources.add(ip_packet.src)
                            ssh_brute_force_packets += 1

                    syn_counts_by_destination[ip_packet.dst] += 1

        # Find destinations receiving many SYNs (potential SYN flood targets)
        potential_syn_flood_targets = {
            dst: count for dst, count in syn_counts_by_destination.items()
            if count >= syn_flood_threshold
        }

        # Calculate total SYN flood packets
        syn_flood_packets = sum(count for dst, count in potential_syn_flood_targets.items())

        # Calculate percentages
        results['ssh_syn_percentage'] = (ssh_syn_packets / total_packets) * 100 if total_packets > 0 else 0
        results['syn_flood_percentage'] = (syn_flood_packets / total_packets) * 100 if total_packets > 0 else 0

        # Results dictionary
        results['total_packets'] = total_packets
        results['ssh_syn_connections'] = ssh_syn_connections
        results['ssh_syn_count'] = ssh_syn_packets
        results['ssh_attempts_by_source'] = ssh_attempts_by_source
        results['ssh_brute_force_sources'] = ssh_brute_force_sources
        results['ssh_brute_force_count'] = ssh_brute_force_packets
        results['ssh_brute_force_percentage'] = (ssh_brute_force_packets / total_packets) * 100 if total_packets > 0 else 0
        results['potential_syn_flood_targets'] = potential_syn_flood_targets
        results['unique_mac_count'] = len(mac_addresses)
        results['mac_percentage'] = (len(mac_addresses) / (total_packets * 2)) * 100 if total_packets > 0 else 0
        self.print_analysis_report(results)
        self.buffer = self.buffer[-1000:]

        new_rules = []

        if results['ssh_syn_connections']:
            for src in sorted(results['ssh_brute_force_sources']):
                targets = results['ssh_attempts_by_source'][src].most_common()
                for dst, count in targets:
                        
                    if count>=5:
                        rule_str = 'src/'+str(src)+'/SYN/30'
                        new_rules.append(rule_str)
                        print(rule_str)

        if results['potential_syn_flood_targets']:
            sorted_targets = sorted(results['potential_syn_flood_targets'].items(),
                                key=lambda x: x[1], reverse=True)
            for dst, count in sorted_targets:
                if count>20:
                    rule_str = 'dst/'+str(dst)+'//10'
                    new_rules.append(rule_str)
                    print(rule_str)
        
        #def add_rules_arp(self):
        self.current_mac = get_mac_addresses()

        print(f"\n3. MAC Address Analysis:")
        print(f"   - {self.current_mac} unique MAC addresses")
        mac_delta = self.current_mac-self.past_mac
        print(f"   - {mac_delta} new MAC addresses")

        rule_str = 'arp///20'
        if self.current_mac > 1024:
            new_rules.append(rule_str)
            if self.current_mac > 1536:
                new_rules.append(rule_str)
                #if self.current_mac > 1536:
                    #new_rules.append(rule_str)

        if mac_delta > 64:
            new_rules.append(rule_str)
            if mac_delta > 128:
                new_rules.append(rule_str)
                if mac_delta > 256:
                    new_rules.append(rule_str)
            #new_rule = Rule('arp', '', '', '', "20")
            #new_rule.ttl = 20
            #self.all_rules.append(new_rule)
            log.log(f"===== Added Rule - arp 30", logging.DEBUG)
        self.past_mac = self.current_mac
        

        
                

        return results, new_rules


    @staticmethod
    def print_analysis_report(results):
        print(f"Total packets analyzed: {results['total_packets']}")
        print("\n--- Pattern Analysis Results ---")

        print(f"\n1. SSH Connection Attempts (TCP SYN to port 22):")
        print(f"   - {results['ssh_syn_count']} packets ({results['ssh_syn_percentage']:.2f}% of total)")
        print(f"   - {len(results['ssh_syn_connections'])} unique source-destination pairs")
        if results['ssh_syn_connections']:
            print("   - Top 5 source-destination pairs:")
            for src, dst in list(results['ssh_syn_connections'])[:5]:
                print(f"     * {src} → {dst}")

        print(f"\n1b. Potential SSH Brute Force Attacks:")
        print(f"   - {results['ssh_brute_force_count']} packets ({results['ssh_brute_force_percentage']:.2f}% of total)")
        print(f"   - {len(results['ssh_brute_force_sources'])} sources attempting brute force")

        # List ALL SSH brute force attackers
        if results['ssh_brute_force_sources']:
            print("\n   FULL LIST OF SSH BRUTE FORCE ATTACKERS:")
            for src in sorted(results['ssh_brute_force_sources']):
                targets = results['ssh_attempts_by_source'][src].most_common()
                targets_str = ", ".join([f"{dst} ({count} attempts)" for dst, count in targets])
                print(f"     * {src} → {targets_str}")

        print(f"\n2. Potential SYN Flood Targets:")
        print(f"   - {len(results['potential_syn_flood_targets'])} potential targets")
        print(f"   - {results['syn_flood_percentage']:.2f}% of traffic is potential SYN flood")

        # List ALL DoS targets
        if results['potential_syn_flood_targets']:
            print("\n   FULL LIST OF DOS TARGET IPs:")
            sorted_targets = sorted(results['potential_syn_flood_targets'].items(),
                                key=lambda x: x[1], reverse=True)
            for dst, count in sorted_targets:
                print(f"     * {dst}: {count} SYN packets")

        # Additional insights
        if results['ssh_syn_percentage'] > 5:
            print("\n⚠️ High percentage of SSH connection attempts detected!")

        if results['ssh_brute_force_percentage'] > 1:
            print("\n⚠️ Possible SSH brute force attack detected!")

        if results['syn_flood_percentage'] > 10:
            print("\n⚠️ Possible SYN flood attack in progress!")

        if results['unique_mac_count'] > 100:
            print("\n⚠️ Unusually high number of MAC addresses detected!")


    # Example usage
    # packets = [...]  # Your packet list here
    # results = analyze_packet_patterns(packets)
    # print_analysis_report(results)







def get_mac_addresses():
    """Get all MAC addresses from the current ARP table"""
    try:
        # Direct approach using shell commands to count unique MAC addresses
        cmd = "cat /proc/net/arp | tail -n +2 | awk '{print $4}' | sort -u | wc -l"
        output = subprocess.check_output(cmd, shell=True, timeout=10, universal_newlines=True)
        return int(output.strip())
    except (subprocess.SubprocessError, ValueError) as e:
        log.log(f"Error counting MAC addresses: {e}", logging.ERROR)
        
        # Fallback method if the command pipeline fails
        try:
            cmd = "ip neigh show | awk '{print $5}' | sort -u | wc -l"
            output = subprocess.check_output(cmd, shell=True, timeout=10, universal_newlines=True)
            return int(output.strip())
        except (subprocess.SubprocessError, ValueError) as e:
            log.log(f"Error with fallback method: {e}", logging.ERROR)
            return 0