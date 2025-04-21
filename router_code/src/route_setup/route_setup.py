#!/usr/bin/env python3

import subprocess
import re
import sys
import os
import socket
import fcntl
import struct
import argparse

class RouterSetup:
    def __init__(self, script_path_1=None, script_path_2=None):
        """
        Initialize the RouterSetup class

        Args:
            script_path (str, optional): Path to the route_setup.sh script.
                                        If None, tries to find it in the current directory.
        """
        self.check_root()

        # Set default script path if not provided
        if script_path_1 is None:
            self.script_path_1 = os.path.join(os.path.dirname(os.path.abspath(__file__)), "route_setup.sh")
        else:
            self.script_path_1 = os.path.abspath(script_path_1)

        if script_path_2 is None:
            self.script_path_2 = os.path.join(os.path.dirname(os.path.abspath(__file__)), "route_edit.sh")
        else:
            self.script_path_2 = os.path.abspath(script_path_2)

        # Detect router number
        self.router_number = self.detect_router_number()

    def check_root(self):
        """Check if script is run as root"""
        if os.geteuid() != 0:
            print("Please run as root")
            sys.exit(1)

    def get_interfaces(self):
        """Get list of all network interfaces"""
        interfaces = []
        try:
            with open('/proc/net/dev', 'r') as f:
                for line in f:
                    if ':' in line:
                        iface = line.split(':')[0].strip()
                        if iface != 'lo':  # Exclude loopback
                            interfaces.append(iface)
        except Exception as e:
            print(f"Error getting interfaces: {e}")
            sys.exit(1)

        return interfaces

    def get_ip_address(self, interface):
        """
        Get IP address of a specific interface

        Args:
            interface (str): Network interface name

        Returns:
            str or None: IP address if found, None otherwise
        """
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            return socket.inet_ntoa(fcntl.ioctl(
                s.fileno(),
                0x8915,  # SIOCGIFADDR
                struct.pack('256s', interface[:15].encode())
            )[20:24])
        except Exception:
            return None

    def detect_router_number(self):
        """
        Detect router number based on 10.x.0.1 IP pattern

        Returns:
            int: Router number (1-4)
        """
        interfaces = self.get_interfaces()

        for iface in interfaces:
            ip = self.get_ip_address(iface)
            if ip:
                match = re.match(r'10\.([1-4])\.0\.1', ip)
                if match:
                    return int(match.group(1))

        print("Could not detect router number automatically.")
        print("No interface with IP matching pattern 10.x.0.1 (where x is 1-4) found.")
        sys.exit(1)
    def return_router_number(self):
        return self.router_number
    def verify_script(self):
        """
        Verify the bash script exists and is executable

        Returns:
            bool: True if script is valid and executable
        """
        scripts = [self.script_path_1, self.script_path_2]
        for script in scripts:
        # Check if script exists
            if not os.path.isfile(script):
                print(f"Error: Could not find script at {script}")
                return False

            # Check if script is executable
            if not os.access(script, os.X_OK):
                print(f"Making {script} executable...")
                try:
                    os.chmod(script, 0o755)
                except Exception as e:
                    print(f"Error setting executable permission: {e}")
                    return False

            return True

    def run_bash_script(self, script, destination=None, path=None):
        """
        Run the route_setup.sh script with the detected router number

        Returns:
            bool: True if successful, False otherwise
        """

        # Run the script with the router number as argument
        print(f"Running {script} with router number {self.router_number}")
        try:
            if (destination != None) and (path != None):
                subprocess.run([script, str(self.router_number), str(destination), str(path)], check=True)
            else:
                subprocess.run([script, str(self.router_number)], check=True)
            print(f"Successfully configured router {self.router_number}")
            return True
        except subprocess.CalledProcessError as e:
            print(f"Error executing bash script: {e}")
            return False

    def setup(self):
        """
        Main setup method - runs the bash script with detected router number

        Returns:
            bool: True if successful, False otherwise
        """
        return self.run_bash_script(self.script_path_1)
    
    def edit(self, destination, path):
        """
        Main setup method - runs the bash script with detected router number

        Returns:
            bool: True if successful, False otherwise
        """
        return self.run_bash_script(self.script_path_2, destination, path)


'''
def main():
    """Main function"""

    # Create RouterSetup instance with specified or default script path
    #router_setup = RouterSetup(script_path=args.script_path)
    router_setup = RouterSetup()

    # Print detected router information
    print(f"Detected router number: {router_setup.router_number}")

    # Run the setup
    router_setup.setup()
    router_setup.edit(1, 4)

    # Exit with appropriate status code
    #sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
'''