import subprocess
import logging

def set_arp_protection_level(level):
    """
    Configure the Linux kernel with ARP protection measures based on threat level.

    Args:
        level: Integer from 1-4 representing protection level
               1 = Normal/Baseline Protection
               2 = Elevated Awareness
               3 = High Alert
               4 = Under ARP Attack

    Returns:
        bool: True if successful, False otherwise
    """
    if level not in [1, 2, 3, 4]:
        return False

    try:
        # Get all network interfaces
        result = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True, check=True)
        interfaces = []
        for line in result.stdout.split('\n'):
            if ': ' in line and not line.startswith(' '):
                # Extract interface name (remove number and colon)
                interface = line.split(': ')[1].split(':')[0]
                if interface != 'lo':  # Skip loopback
                    interfaces.append(interface)

        # Configure protection based on level
        if level == 1:
            # Level 1: Normal/Baseline Protection
            arp_rate_limit = 30
            gc_stale_time = 60
            gc_thresh1 = 128
            gc_thresh2 = 512
            gc_thresh3 = 1024
            rp_filter = 1
        elif level == 2:
            # Level 2: Elevated Awareness
            arp_rate_limit = 15
            gc_stale_time = 45
            gc_thresh1 = 256
            gc_thresh2 = 768
            gc_thresh3 = 1536
            rp_filter = 1
        elif level == 3:
            # Level 3: High Alert
            arp_rate_limit = 5
            gc_stale_time = 30
            gc_thresh1 = 512
            gc_thresh2 = 1024
            gc_thresh3 = 2048
            rp_filter = 1
        else:  # level == 4
            # Level 4: Under ARP Attack
            arp_rate_limit = 2
            gc_stale_time = 15
            gc_thresh1 = 1024
            gc_thresh2 = 2048
            gc_thresh3 = 4096
            rp_filter = 1
            #subprocess.run([
            #'sudo', 'ip', 'neigh', 'flush', 'all'
        #], check=True)
            

        # Configure kernel ARP settings
        subprocess.run([
            'sudo', 'sysctl', '-w',
            f'net.ipv4.neigh.default.gc_stale_time={gc_stale_time}'
        ], check=True)

        subprocess.run([
            'sudo', 'sysctl', '-w',
            f'net.ipv4.neigh.default.gc_thresh1={gc_thresh1}'
        ], check=True)

        subprocess.run([
            'sudo', 'sysctl', '-w',
            f'net.ipv4.neigh.default.gc_thresh2={gc_thresh2}'
        ], check=True)

        subprocess.run([
            'sudo', 'sysctl', '-w',
            f'net.ipv4.neigh.default.gc_thresh3={gc_thresh3}'
        ], check=True)

        # Configure Reverse Path Filtering
        subprocess.run([
            'sudo', 'sysctl', '-w',
            f'net.ipv4.conf.all.rp_filter={rp_filter}'
        ], check=True)

        subprocess.run([
            'sudo', 'sysctl', '-w',
            f'net.ipv4.conf.default.rp_filter={rp_filter}'
        ], check=True)

        return True

    except subprocess.CalledProcessError as e:
        return False
