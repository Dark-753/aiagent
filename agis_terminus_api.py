#!/usr/bin/env python3

from flask import Flask, request, jsonify
from agis_terminus import AGISTerminus
from terminus_logger import TerminusLogger
import json

app = Flask(__name__)
agent = AGISTerminus()
logger = TerminusLogger()

@app.route('/execute-task', methods=['POST'])
def execute_task():
    try:
        # Get JSON data from request
        data = request.get_json()
        
        if not data:
            response = {'error': 'No JSON data provided'}
            logger.log_api_request('/execute-task', 'POST', 400, {}, response)
            return jsonify(response), 400
            
        # Validate required fields
        if 'task' not in data:
            response = {'error': 'Missing required field: task'}
            logger.log_api_request('/execute-task', 'POST', 400, data, response)
            return jsonify(response), 400
            
        # Get task and OS (default to detected OS if not specified)
        task = data['task']
        os_type = data.get('os', agent.os_type)
        
        # Generate commands
        command = agent.get_terminal_commands(task, os_type)
        
        if not command:
            response = {'error': 'Failed to generate valid command'}
            logger.log_api_request('/execute-task', 'POST', 500, data, response)
            return jsonify(response), 500
            
        # Check for dangerous commands
        is_dangerous, pattern = agent._is_dangerous_command(command)
        if is_dangerous:
            response = {
                'error': 'Potentially dangerous command detected',
                'command': command,
                'dangerous_pattern': pattern,
                'status': 'blocked'
            }
            logger.log_dangerous_command(task, os_type, command, pattern)
            logger.log_api_request('/execute-task', 'POST', 403, data, response)
            return jsonify(response), 403
            
        # Execute commands and collect results
        results = []
        command_list = [cmd.strip() for cmd in command.split('\n') if cmd.strip()]
        
        for cmd in command_list:
            try:
                # Execute the command
                stdout, stderr = agent._execute_command(cmd)
                success = stderr == ''
                
                # Log the command execution
                logger.log_command_execution(
                    task=task,
                    os_type=os_type,
                    command=cmd,
                    stdout=stdout,
                    stderr=stderr,
                    success=success
                )
                
                # Add command result to results list
                results.append({
                    'command': cmd,
                    'stdout': stdout,
                    'stderr': stderr,
                    'success': success
                })
                
            except Exception as e:
                error_msg = str(e)
                logger.log_command_execution(
                    task=task,
                    os_type=os_type,
                    command=cmd,
                    error=error_msg,
                    success=False
                )
                results.append({
                    'command': cmd,
                    'error': error_msg,
                    'success': False
                })
        
        # Prepare success response
        response = {
            'status': 'success',
            'os': os_type,
            'task': task,
            'commands': command,
            'results': results
        }
        
        # Log the API request
        logger.log_api_request('/execute-task', 'POST', 200, data, response)
        
        return jsonify(response)
        
    except Exception as e:
        error_msg = f'An error occurred: {str(e)}'
        response = {'error': error_msg}
        logger.log_api_request('/execute-task', 'POST', 500, data if 'data' in locals() else {}, response)
        return jsonify(response), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True) 