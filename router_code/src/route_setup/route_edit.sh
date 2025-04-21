#!/bin/bash

# Script to modify routes between routers
# Usage: ./modify_route.sh <router_number> <target_network> <destination_router>
# Example: ./modify_route.sh 1 3 4 - Change Router 1's route to network 10.3.0.0/16 to go via Router 4

# Check if script is run as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit 1
fi

# Check if all arguments are provided
if [ $# -ne 3 ]; then
  echo "Usage: $0 <router_number> <target_network> <destination_router>"
  echo "  <router_number>: Router to modify (1-4)"
  echo "  <target_network>: Target network number (1-4) - the 10.X.0.0/16 network"
  echo "  <destination_router>: New next-hop router (1-4)"
  exit 1
fi

# Validate router numbers
ROUTER=$1
TARGET_NET=$2
DEST_ROUTER=$3

# Validate all inputs are numbers between 1-4
for arg in "$ROUTER" "$TARGET_NET" "$DEST_ROUTER"; do
  if ! [[ "$arg" =~ ^[1-4]$ ]]; then
    echo "Error: All arguments must be numbers between 1 and 4"
    exit 1
  fi
done

# Ensure router is not routing to itself
if [ "$TARGET_NET" -eq "$ROUTER" ]; then
  echo "Error: Router $ROUTER cannot have a route to its own network 10.$TARGET_NET.0.0/16"
  exit 1
fi

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

# Get the new gateway IP
NEW_GATEWAY=$(get_link_ip $ROUTER $DEST_ROUTER)

echo "Modifying route on Router $ROUTER"
echo "Changing route to 10.$TARGET_NET.0.0/16 via $NEW_GATEWAY"

# Check if the route exists
if ip route show | grep -q "10.$TARGET_NET.0.0/16"; then
  # Replace the existing route
  ip route replace 10.$TARGET_NET.0.0/16 via $NEW_GATEWAY
  echo "Route updated."
else
  # Add a new route
  ip route add 10.$TARGET_NET.0.0/16 via $NEW_GATEWAY
  echo "Route added."
fi

# Verify the route
echo "Current route:"
ip route show | grep "10.$TARGET_NET.0.0/16"
