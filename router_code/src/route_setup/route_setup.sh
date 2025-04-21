#!/bin/bash
# ip route flush all
# systemctl restart NetworkManager
# Script to set up iptables rules for routers 1-4
# Usage: ./setup_iptables.sh <router_number>

# Check if script is run as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit 1
fi

# Check if router number is provided
if [ $# -ne 1 ]; then
  echo "Usage: $0 <router_number>"
  echo "Where router_number is 1, 2, 3, or 4"
  exit 1
fi

# Validate router number
ROUTER=$1
if ! [[ "$ROUTER" =~ ^[1-4]$ ]]; then
  echo "Error: Router number must be 1, 2, 3, or 4"
  exit 1
fi

echo "Setting up iptables for Router $ROUTER..."

# Clear existing rules
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X

# Default policies
iptables -P INPUT ACCEPT
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Allow established connections
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow loopback
iptables -A INPUT -i lo -j ACCEPT

# Allow SSH (for management)
iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# Create chains for NFQUEUE
iptables -N NFQUEUE_PACKETS_1
iptables -N NFQUEUE_PACKETS_2

# Function to get the appropriate link IP
get_link_ip() {
  local src=$1
  local dst=$2

  # Order the router numbers to get the correct subnet
  if [ "$src" -lt "$dst" ]; then
    echo "192.168.$src$dst.$dst"
  else
    echo "192.168.$dst$src.$dst"
  fi
}

# Set up forwarding rules based on router number

case $ROUTER in
  1)
    # Router 1 connections: 10.1.0.0/16 and links to routers 2, 3, 4
    echo "Configuring Router 1 specific rules..."

    # Special rule for 10.1.0.0/16 to NFQUEUE 2
    iptables -A FORWARD -s 10.1.0.0/16 -j NFQUEUE_PACKETS_2
    iptables -A FORWARD -d 10.1.0.0/16 -j NFQUEUE_PACKETS_2

    # No need for additional rules for 10.1.0.0/16 as they're all handled by NFQUEUE 2

    iptables -A FORWARD -s 10.2.0.0/16 -j NFQUEUE_PACKETS_1
    iptables -A FORWARD -d 10.2.0.0/16 -j NFQUEUE_PACKETS_1
    iptables -A FORWARD -s 10.3.0.0/16 -j NFQUEUE_PACKETS_1
    iptables -A FORWARD -d 10.3.0.0/16 -j NFQUEUE_PACKETS_1
    iptables -A FORWARD -s 10.4.0.0/16 -j NFQUEUE_PACKETS_1
    iptables -A FORWARD -d 10.4.0.0/16 -j NFQUEUE_PACKETS_1

    # Direct links to other routers
    iptables -A FORWARD -s 192.168.12.0/24 -j NFQUEUE_PACKETS_1
    iptables -A FORWARD -d 192.168.12.0/24 -j NFQUEUE_PACKETS_1

    iptables -A FORWARD -s 192.168.13.0/24 -j NFQUEUE_PACKETS_1
    iptables -A FORWARD -d 192.168.13.0/24 -j NFQUEUE_PACKETS_1

    iptables -A FORWARD -s 192.168.14.0/24 -j NFQUEUE_PACKETS_1
    iptables -A FORWARD -d 192.168.14.0/24 -j NFQUEUE_PACKETS_1

    # Add routes to other 10.x.0.0/16 networks
    ip route add 10.2.0.0/16 via $(get_link_ip 1 2)
    ip route add 10.3.0.0/16 via $(get_link_ip 1 3)
    ip route add 10.4.0.0/16 via $(get_link_ip 1 4)
    ;;

  2)
    # Router 2 connections: 10.2.0.0/16 and links to routers 1, 3, 4
    echo "Configuring Router 2 specific rules..."

    # Special rule for 10.2.0.0/16 to NFQUEUE 2
    iptables -A FORWARD -s 10.2.0.0/16 -j NFQUEUE_PACKETS_2
    iptables -A FORWARD -d 10.2.0.0/16 -j NFQUEUE_PACKETS_2

    # No need for additional rules for 10.2.0.0/16 as they're all handled by NFQUEUE 2

    iptables -A FORWARD -s 10.1.0.0/16 -j NFQUEUE_PACKETS_1
    iptables -A FORWARD -d 10.1.0.0/16 -j NFQUEUE_PACKETS_1
    iptables -A FORWARD -s 10.3.0.0/16 -j NFQUEUE_PACKETS_1
    iptables -A FORWARD -d 10.3.0.0/16 -j NFQUEUE_PACKETS_1
    iptables -A FORWARD -s 10.4.0.0/16 -j NFQUEUE_PACKETS_1
    iptables -A FORWARD -d 10.4.0.0/16 -j NFQUEUE_PACKETS_1

    # Direct links to other routers
    iptables -A FORWARD -s 192.168.12.0/24 -j NFQUEUE_PACKETS_1
    iptables -A FORWARD -d 192.168.12.0/24 -j NFQUEUE_PACKETS_1

    iptables -A FORWARD -s 192.168.23.0/24 -j NFQUEUE_PACKETS_1
    iptables -A FORWARD -d 192.168.23.0/24 -j NFQUEUE_PACKETS_1

    iptables -A FORWARD -s 192.168.24.0/24 -j NFQUEUE_PACKETS_1
    iptables -A FORWARD -d 192.168.24.0/24 -j NFQUEUE_PACKETS_1

    # Add routes to other 10.x.0.0/16 networks
    ip route add 10.1.0.0/16 via $(get_link_ip 2 1)
    ip route add 10.3.0.0/16 via $(get_link_ip 2 3)
    ip route add 10.4.0.0/16 via $(get_link_ip 2 4)
    ;;

  3)
    # Router 3 connections: 10.3.0.0/16 and links to routers 1, 2, 4
    echo "Configuring Router 3 specific rules..."

    # Special rule for 10.3.0.0/16 to NFQUEUE 2
    iptables -A FORWARD -s 10.3.0.0/16 -j NFQUEUE_PACKETS_2
    iptables -A FORWARD -d 10.3.0.0/16 -j NFQUEUE_PACKETS_2

    # No need for additional rules for 10.3.0.0/16 as they're all handled by NFQUEUE 2

    iptables -A FORWARD -s 10.1.0.0/16 -j NFQUEUE_PACKETS_1
    iptables -A FORWARD -d 10.1.0.0/16 -j NFQUEUE_PACKETS_1
    iptables -A FORWARD -s 10.2.0.0/16 -j NFQUEUE_PACKETS_1
    iptables -A FORWARD -d 10.2.0.0/16 -j NFQUEUE_PACKETS_1
    iptables -A FORWARD -s 10.4.0.0/16 -j NFQUEUE_PACKETS_1
    iptables -A FORWARD -d 10.4.0.0/16 -j NFQUEUE_PACKETS_1

    # Direct links to other routers
    iptables -A FORWARD -s 192.168.13.0/24 -j NFQUEUE_PACKETS_1
    iptables -A FORWARD -d 192.168.13.0/24 -j NFQUEUE_PACKETS_1

    iptables -A FORWARD -s 192.168.23.0/24 -j NFQUEUE_PACKETS_1
    iptables -A FORWARD -d 192.168.23.0/24 -j NFQUEUE_PACKETS_1

    iptables -A FORWARD -s 192.168.34.0/24 -j NFQUEUE_PACKETS_1
    iptables -A FORWARD -d 192.168.34.0/24 -j NFQUEUE_PACKETS_1

    # Add routes to other 10.x.0.0/16 networks
    ip route add 10.1.0.0/16 via $(get_link_ip 3 1)
    ip route add 10.2.0.0/16 via $(get_link_ip 3 2)
    ip route add 10.4.0.0/16 via $(get_link_ip 3 4)
    ;;

  4)
    # Router 4 connections: 10.4.0.0/16 and links to routers 1, 2, 3
    echo "Configuring Router 4 specific rules..."

    # Special rule for 10.4.0.0/16 to NFQUEUE 2
    iptables -A FORWARD -s 10.4.0.0/16 -j NFQUEUE_PACKETS_2
    iptables -A FORWARD -d 10.4.0.0/16 -j NFQUEUE_PACKETS_2

    # No need for additional rules for 10.4.0.0/16 as they're all handled by NFQUEUE 2

    iptables -A FORWARD -s 10.1.0.0/16 -j NFQUEUE_PACKETS_1
    iptables -A FORWARD -d 10.1.0.0/16 -j NFQUEUE_PACKETS_1
    iptables -A FORWARD -s 10.2.0.0/16 -j NFQUEUE_PACKETS_1
    iptables -A FORWARD -d 10.2.0.0/16 -j NFQUEUE_PACKETS_1
    iptables -A FORWARD -s 10.3.0.0/16 -j NFQUEUE_PACKETS_1
    iptables -A FORWARD -d 10.3.0.0/16 -j NFQUEUE_PACKETS_1

    # Direct links to other routers
    iptables -A FORWARD -s 192.168.14.0/24 -j NFQUEUE_PACKETS_1
    iptables -A FORWARD -d 192.168.14.0/24 -j NFQUEUE_PACKETS_1

    iptables -A FORWARD -s 192.168.24.0/24 -j NFQUEUE_PACKETS_1
    iptables -A FORWARD -d 192.168.24.0/24 -j NFQUEUE_PACKETS_1

    iptables -A FORWARD -s 192.168.34.0/24 -j NFQUEUE_PACKETS_1
    iptables -A FORWARD -d 192.168.34.0/24 -j NFQUEUE_PACKETS_1

    # Add routes to other 10.x.0.0/16 networks
    ip route add 10.1.0.0/16 via $(get_link_ip 4 1)
    ip route add 10.2.0.0/16 via $(get_link_ip 4 2)
    ip route add 10.3.0.0/16 via $(get_link_ip 4 3)
    ;;
esac

# Configure the NFQUEUE chains
iptables -A NFQUEUE_PACKETS_1 -j NFQUEUE --queue-num 1
iptables -A NFQUEUE_PACKETS_2 -j NFQUEUE --queue-num 2

# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# Display current routes
echo "Current routes:"
ip route show | grep "^10\."

# Save the rules (works on most Linux distributions)
if command -v netfilter-persistent &> /dev/null; then
    netfilter-persistent save
elif [ -x /etc/init.d/iptables ]; then
    /etc/init.d/iptables save
elif command -v iptables-save &> /dev/null; then
    iptables-save > /etc/iptables/rules.v4 || iptables-save > /etc/iptables.rules
else
    echo "Warning: Could not find a way to persistently save iptables rules."
    echo "Rules will be lost on reboot. Consider installing iptables-persistent."
    echo "Current rules saved to /tmp/iptables-rules.backup"
    iptables-save > /tmp/iptables-rules.backup
fi

echo "iptables setup completed for Router $ROUTER"
echo "Traffic from/to 10.x.0.0/16 networks will be forwarded to NFQUEUE 2"
echo "All other traffic will be forwarded to NFQUEUE 1"
echo "Routes to all 10.x.0.0/16 networks have been added"
