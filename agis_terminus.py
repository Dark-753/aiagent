#!/usr/bin/env python3

import os
import sys
import platform
import subprocess
import re
from typing import Tuple, Optional, List, Set
import openai
from anthropic import Anthropic
from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.panel import Panel
from rich.markdown import Markdown
from rich.syntax import Syntax
from voice_input import VoiceInput
from terminus_logger import TerminusLogger

class AGISTerminus:
    def __init__(self):
        self.console = Console()
        self.os_type = self._detect_os()
        self.openai_client = openai.OpenAI()  # Initialize OpenAI client
        self.anthropic_client = Anthropic()   # Initialize Anthropic client
        self.voice_input = VoiceInput()      # Initialize voice input
        self.logger = TerminusLogger()       # Initialize logger
        
        # Define dangerous command patterns
        self.dangerous_patterns: Set[str] = {
            # File system operations
            r'rm\s+-rf', r'rm\s+-r\s+-f', r'rm\s+--force\s+--recursive',
            r'del\s+/[sqa]', r'del\s+/[sqa]\s+/[sqa]',  # Windows delete with force flags
            r'format\s+', r'diskpart\s+', r'chkdsk\s+/f',
            r':(){.*};:',  # Fork bomb
            r'mkfs\s+', r'mkfs\.',  # Format filesystem
            r'dd\s+if=/dev/zero', r'dd\s+if=/dev/urandom',  # Disk wiping
            
            # System operations
            r'shutdown\s+', r'halt\s+', r'poweroff\s+', r'reboot\s+',
            r'systemctl\s+(?:stop|restart|disable)',
            
            # Network operations
            r'iptables\s+-F', r'iptables\s+--flush',
            r'netsh\s+advfirewall\s+set\s+allprofiles\s+state\s+off',
            
            # User management
            r'userdel\s+-r', r'userdel\s+--remove',
            r'net\s+user\s+.*\s+/delete',
            
            # Package management
            r'apt-get\s+remove\s+--purge', r'yum\s+remove\s+--noautoremove',
            r'pip\s+uninstall\s+--yes',
            
            # Database operations
            r'drop\s+database', r'drop\s+table',
            
            # Shell operations
            r'>\s*/dev/sd[a-z]', r'>\s*/dev/hd[a-z]',  # Direct disk writing
            r'chmod\s+-R\s+777', r'chmod\s+-R\s+000',
            r'chown\s+-R\s+root:root',
        }
        
    def _is_dangerous_command(self, command: str) -> Tuple[bool, Optional[str]]:
        """
        Check if a command contains dangerous patterns.
        
        Args:
            command (str): The command to check
            
        Returns:
            Tuple[bool, Optional[str]]: (is_dangerous, matched_pattern)
        """
        command = command.lower()
        for pattern in self.dangerous_patterns:
            if re.search(pattern, command):
                return True, pattern
        return False, None
    
    def _detect_os(self) -> str:
        """Detect the operating system type."""
        system = platform.system().lower()
        if system == "windows":
            return "windows"
        elif system == "darwin":
            return "macos"
        elif system == "linux":
            return "linux"
        else:
            return "unknown"
    
    def get_terminal_commands(self, task: str, os_type: str) -> str:
        """
        Generate terminal commands using GPT-3.5-turbo for the specified OS.
        
        Args:
            task (str): The user's task description
            os_type (str): The target operating system ('windows', 'macos', or 'linux')
            
        Returns:
            str: The generated command
        """
        prompt = f"""You are a terminal command generator. Generate a single, valid command for {os_type} to accomplish the following task.
IMPORTANT: Return ONLY the command itself, with no explanations or additional text.
Task: {task}"""

        try:
            response = self.openai_client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": "You are a terminal command generator. Return only the command, no explanations."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,  # Lower temperature for more focused outputs
                max_tokens=150    # Limit response length
            )
            
            # Extract and clean the command
            command = response.choices[0].message.content.strip()
            return command
            
        except Exception as e:
            self.console.print(f"[red]Error generating command: {str(e)}[/red]")
            return ""
    
    def _execute_multiline_commands(self, commands: str) -> None:
        """
        Execute multiple commands one by one and display their output.
        
        Args:
            commands (str): Multiline string containing commands to execute
        """
        # Split commands by newline and filter out empty lines
        command_list = [cmd.strip() for cmd in commands.split('\n') if cmd.strip()]
        
        for i, cmd in enumerate(command_list, 1):
            # Check for dangerous commands
            is_dangerous, pattern = self._is_dangerous_command(cmd)
            if is_dangerous:
                self.console.print(f"\n[bold red]⚠️  WARNING: Potentially dangerous command detected![/bold red]")
                self.console.print(f"[red]Command contains dangerous pattern: {pattern}[/red]")
                self.console.print(Syntax(cmd, "bash", theme="monokai"))
                
                if not Confirm.ask("\n[yellow]This command could be destructive. Do you still want to execute it?[/yellow]"):
                    self.console.print("[yellow]Command execution skipped.[/yellow]")
                    continue
            
            self.console.print(f"\n[bold blue]Executing command {i}/{len(command_list)}:[/bold blue]")
            self.console.print(Syntax(cmd, "bash", theme="monokai"))
            
            try:
                # Execute the command and capture output
                result = subprocess.run(
                    cmd,
                    shell=True,
                    text=True,
                    capture_output=True,
                    check=False  # Don't raise exception on non-zero exit
                )
                
                # Print stdout if any
                if result.stdout:
                    self.console.print("\n[bold green]Output:[/bold green]")
                    self.console.print(result.stdout)
                
                # Print stderr if any
                if result.stderr:
                    self.console.print("\n[bold red]Errors:[/bold red]")
                    self.console.print(result.stderr)
                
                # Print exit code
                exit_color = "green" if result.returncode == 0 else "red"
                self.console.print(f"\n[bold {exit_color}]Exit code: {result.returncode}[/bold {exit_color}]")
                
                # Log the command execution
                self.logger.log_command_execution(
                    task="",  # Task will be filled in process_task
                    os_type=self.os_type,
                    command=cmd,
                    stdout=result.stdout,
                    stderr=result.stderr,
                    success=result.returncode == 0
                )
                
            except Exception as e:
                error_msg = str(e)
                self.console.print(f"\n[bold red]Error executing command: {error_msg}[/bold red]")
                self.logger.log_command_execution(
                    task="",  # Task will be filled in process_task
                    os_type=self.os_type,
                    command=cmd,
                    error=error_msg,
                    success=False
                )
            
            # Add a separator between commands
            if i < len(command_list):
                self.console.print("\n" + "="*50)
    
    def _get_llm_command(self, task: str) -> str:
        """Get command suggestions from LLMs."""
        return self.get_terminal_commands(task, self.os_type)
    
    def process_task(self, task: str) -> None:
        """Process the user's task and execute appropriate commands."""
        self.console.print(f"\n[bold blue]Operating System detected:[/bold blue] {self.os_type}")
        self.console.print(f"[bold blue]Processing task:[/bold blue] {task}")
        
        # Get command from LLM
        command = self._get_llm_command(task)
        
        if not command:
            self.console.print("[red]Failed to generate a valid command.[/red]")
            return
        
        # Show proposed commands
        self.console.print("\n[bold yellow]Proposed command(s):[/bold yellow]")
        self.console.print(Syntax(command, "bash", theme="monokai"))
        
        # Check for dangerous commands before asking for confirmation
        is_dangerous, pattern = self._is_dangerous_command(command)
        if is_dangerous:
            self.console.print(f"\n[bold red]⚠️  WARNING: Potentially dangerous command detected![/bold red]")
            self.console.print(f"[red]Command contains dangerous pattern: {pattern}[/red]")
            self.logger.log_dangerous_command(task, self.os_type, command, pattern)
            if not Confirm.ask("\n[yellow]This command could be destructive. Do you still want to proceed?[/yellow]"):
                self.console.print("[yellow]Command execution cancelled.[/yellow]")
                return
        
        # Ask for confirmation
        if Confirm.ask("\nDo you want to execute these commands?"):
            self.console.print("\n[bold green]Executing commands...[/bold green]")
            self._execute_multiline_commands(command)
        else:
            self.console.print("[yellow]Command execution cancelled by user.[/yellow]")

def main():
    # Initialize the agent
    agent = AGISTerminus()
    console = Console()
    
    # Display welcome message
    welcome_text = """
    # Welcome to AGIS-Terminus! 🤖
    
    Your AI-powered terminal assistant that helps you execute commands safely.
    Supports both text and voice input!
    
    Type 'exit' to quit.
    """
    console.print(Panel(Markdown(welcome_text), title="AGIS-Terminus", border_style="blue"))
    
    # Main interaction loop
    while True:
        try:
            # Get task from user (voice or text)
            task = agent.voice_input.get_task()
            
            if task is None:
                continue
                
            if task.lower() == 'exit':
                console.print("[yellow]Goodbye! 👋[/yellow]")
                break
                
            agent.process_task(task)
            
        except KeyboardInterrupt:
            console.print("\n[yellow]Operation cancelled by user.[/yellow]")
            break
        except Exception as e:
            console.print(f"[red]An error occurred: {str(e)}[/red]")

if __name__ == "__main__":
    main() 