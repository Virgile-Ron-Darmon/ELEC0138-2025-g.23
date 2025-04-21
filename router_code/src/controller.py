"""
Main controller module for the financial data analysis system.
Orchestrates data loading, processing, model training, and visualization
components of the application.
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


class Controller():
    """
    Main controller class coordinating all system operations.

    Handles configuration loading, database connections, data processing,
    model training, and visualization generation for the entire system.
    """
    
    def load_config(self, file_path):
        """
        Loads and validates system configuration from a YAML file.

        Args:
            file_path (str): Path to the configuration YAML file

        Creates default configuration if file is missing or invalid.
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

        # system variables
        self.config_test = config.get('test', '4567')



    def __init__(self):
        log.log("===== Initialising System =====", logging.INFO)
        # Path to the configuration file
        config_file = './config.yaml'
        self.load_config(config_file)
        self.route_manager = RouterSetup()
        self.route_manager.setup()
        #self.filer_1 = Filter(1)
        self.filer = None
        






    def run(self):
        """
        Executes the main system workflow.

        Orchestrates the entire process including network filtering,
        data processing, and analysis components.
        """
        log.log("===== Starting System =====", logging.INFO)

        while True:
            try:
                Queue_Num = int(input("Queue Number (1 or 2): "))
                if Queue_Num == 1 or Queue_Num == 2:
                    break
                else:
                    print("invalid input")
            except:
                print("invalid input")
        while True:
            try:
                pacify = str(input("Pacify router ? (y or n): "))
                if pacify == "y" or pacify == "Y":
                    pacify = False
                    break
                elif pacify == "n" or pacify == "N":
                    pacify = True
                    break
                else:
                    print("invalid input")
            except:
                print("invalid input")
        self.filer_2 = Filter(Queue_Num, self.route_manager.return_router_number(), pacify)
        
        log.log("===== System Terminated =====", logging.INFO)
