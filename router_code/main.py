"""
Main entry point for the ELEC0138 network security framework.

Initializes and runs the Controller component to launch
the complete threat detection and mitigation workflow.
"""
import logging
from src.controller import Controller
from src.tools.logger import Logger

# Initialize module-level logger
log = Logger(log_file='SP_Log.log', log_level=logging.DEBUG)


def main():
    """Instantiate and execute the network security controller.

    This function:
      1. Logs the start of the framework.
      2. Creates a Controller instance that sets up routing, filters,
         and configuration.
      3. Starts the main threat analysis and mitigation loop.

    Returns:
        None
    """
    log.log("Starting ELEC0138 network security framework", logging.INFO)
    controller = Controller()

    # Launch the main security workflow
    controller.run()


if __name__ == '__main__':
    main()
