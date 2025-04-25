#!/usr/bin/env python3
"""
Main controller module for the ELEC0138 network security framework.

Coordinates configuration loading, router setup, packet buffering,
filter initialization, and policy enforcement to protect against
network-based threats.
"""
import logging
import random
import time
import numpy as np
import yaml
import threading
import netifaces
import ipaddress
from src.tools.logger import Logger
from src.net_manager.filter import Filter
from src.route_setup.route_setup import RouterSetup

log = Logger(log_file='SP_Log.log', log_level=logging.DEBUG)


class Controller:
    """Main controller class coordinating all security system operations.

    This class handles:
        - Configuration loading
        - Network routing setup
        - User interaction for filter parameters
        - Filter initialization and lifecycle management
    """

    def load_config(self, file_path):
        """Load and validate system configuration from a YAML file.

        If the file is missing or contains invalid YAML, a default configuration
        is created and saved back to the given file path.

        Args:
            file_path (str): Path to the configuration YAML file.

        Returns:
            None
        """
        default_config = {
            'test': '1234',
        }

        try:
            with open(file_path, 'r') as file:
                config = yaml.safe_load(file) or {}

                if not isinstance(config, dict):
                    raise ValueError("Config file does not contain a valid YAML dictionary")
                log.log("Config loaded successfully", logging.INFO)

        except FileNotFoundError:
            log.log("Config file not found", logging.WARNING)
            log.log("Creating config.yaml with default values", logging.INFO)
            config = default_config

            with open(file_path, "w") as file:
                yaml.safe_dump(default_config, file, default_flow_style=False)
            log.log("Default config created and loaded", logging.INFO)

        except (yaml.YAMLError, ValueError) as e:
            log.log(f"Error loading config: {e}", logging.ERROR)
            log.log("Loading default configuration", logging.INFO)
            config = default_config

        # Set system variable from config
        self.config_test = config.get('test', '4567')

    def __init__(self):
        """Initialize the Controller.

        - Load system configuration
        - Set up network routing
        - Prepare for filtering and processing
        """
        log.log("===== Initialising System =====", logging.INFO)
        config_file = './config.yaml'
        self.load_config(config_file)

        # Set up routing manager
        self.route_manager = RouterSetup()
        self.route_manager.setup()

        # Placeholder for packet filter instance
        self.filer = None

    def run(self):
        """Execute the main system workflow.

        Prompts the user for:
          - Queue number selection (1 or 2)
          - Router pacify option (yes/no)

        Then initializes the packet filter with the chosen parameters
        and enters the processing loop.

        Returns:
            None
        """
        log.log("===== Starting System =====", logging.INFO)

        # Prompt for queue number
        while True:
            try:
                queue_num = int(input("Queue Number (1 or 2): "))
                if queue_num in (1, 2):
                    break
                print("Invalid input, please enter 1 or 2.")
            except ValueError:
                print("Invalid input, please enter a number.")

        # Prompt for pacify option
        while True:
            try:
                pacify_input = input("Pacify router? (y/n): ").strip().lower()
                if pacify_input in ('y', 'n'):
                    pacify = (pacify_input == 'n')
                    break
                print("Invalid input, please enter 'y' or 'n'.")
            except Exception:
                print("Invalid input, please try again.")

        # Initialize packet filter with user parameters
        self.filer_2 = Filter(
            queue_num,
            self.route_manager.return_router_number(),
            pacify
        )

        log.log("===== System Terminated =====", logging.INFO)
