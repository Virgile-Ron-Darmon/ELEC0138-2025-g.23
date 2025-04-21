"""
Main entry point for the financial data analysis system.
Initializes and runs the controller component to execute
the complete data analysis pipeline.
"""
import logging
from src.controller import Controller
from src.tools.logger import Logger
log = Logger(log_file='SP_Log.log', log_level=logging.DEBUG)


def main():
    """
    Main function initializing and running the system.
    
    Creates a Controller instance and executes the main workflow,
    handling the complete pipeline from data loading through visualization.
    """
    log.log("Instantiating and running the Controller class", logging.INFO)
    controller = Controller()

    # Run the controller
    controller.run()

if __name__ == '__main__':
    main()