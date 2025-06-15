#!/usr/bin/env python3

import logging
from datetime import datetime
from typing import Dict, Any, Optional
import json
from pathlib import Path

class TerminusLogger:
    def __init__(self, log_file: str = "terminus_logs.txt"):
        self.log_file = log_file
        self._setup_logger()
        
    def _setup_logger(self):
        """Set up the logger with file handler."""
        # Create logs directory if it doesn't exist
        log_path = Path(self.log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S',
            handlers=[
                logging.FileHandler(self.log_file),
                logging.StreamHandler()  # Also log to console
            ]
        )
        self.logger = logging.getLogger('terminus')
    
    def log_command_execution(self, 
                            task: str,
                            os_type: str,
                            command: str,
                            stdout: str = "",
                            stderr: str = "",
                            success: bool = True,
                            error: Optional[str] = None) -> None:
        """
        Log a command execution with its results.
        
        Args:
            task (str): The original task description
            os_type (str): The operating system type
            command (str): The executed command
            stdout (str): Command's standard output
            stderr (str): Command's standard error
            success (bool): Whether the command was successful
            error (Optional[str]): Any error message
        """
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'task': task,
            'os': os_type,
            'command': command,
            'stdout': stdout,
            'stderr': stderr,
            'success': success,
            'error': error
        }
        
        # Log as JSON for better parsing
        self.logger.info(json.dumps(log_entry))
    
    def log_dangerous_command(self,
                            task: str,
                            os_type: str,
                            command: str,
                            pattern: str) -> None:
        """
        Log a blocked dangerous command.
        
        Args:
            task (str): The original task description
            os_type (str): The operating system type
            command (str): The dangerous command
            pattern (str): The matched dangerous pattern
        """
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'type': 'dangerous_command_blocked',
            'task': task,
            'os': os_type,
            'command': command,
            'pattern': pattern
        }
        
        self.logger.warning(json.dumps(log_entry))
    
    def log_api_request(self,
                       endpoint: str,
                       method: str,
                       status_code: int,
                       request_data: Dict[str, Any],
                       response_data: Dict[str, Any]) -> None:
        """
        Log an API request and its response.
        
        Args:
            endpoint (str): The API endpoint
            method (str): The HTTP method
            status_code (int): The response status code
            request_data (Dict[str, Any]): The request data
            response_data (Dict[str, Any]): The response data
        """
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'type': 'api_request',
            'endpoint': endpoint,
            'method': method,
            'status_code': status_code,
            'request': request_data,
            'response': response_data
        }
        
        self.logger.info(json.dumps(log_entry)) 