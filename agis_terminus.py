#!/usr/bin/env python3

import os
import sys
import platform
import subprocess
import re
import mimetypes
import struct
from typing import Tuple, Optional, List, Set, Dict
import requests
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
        self.voice_input = VoiceInput()      # Initialize voice input
        self.logger = TerminusLogger()       # Initialize logger
        
        # Initialize file analysis tools
        self.text_extensions = {'.txt', '.py', '.js', '.html', '.css', '.json', '.md', '.log', '.csv', '.xml', '.bat', '.ps1', '.cmd', '.ini', '.conf', '.config', '.yaml', '.yml'}
        self.binary_extensions = {'.exe', '.dll', '.so', '.dylib', '.bin', '.dat', '.zip', '.rar', '.7z', '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.ico', '.mp3', '.mp4', '.avi', '.mov'}
        
        # File signatures (magic numbers) for common file types
        self.file_signatures = {
            b'PK\x03\x04': 'ZIP archive',
            b'\x25\x50\x44\x46': 'PDF document',
            b'\xFF\xD8\xFF': 'JPEG image',
            b'\x89PNG\r\n\x1a\n': 'PNG image',
            b'GIF87a': 'GIF image',
            b'GIF89a': 'GIF image',
            b'BM': 'BMP image',
            b'\x00\x00\x01\x00': 'ICO image',
            b'ID3': 'MP3 audio',
            b'\xFF\xFB': 'MP3 audio',
            b'\xFF\xF3': 'MP3 audio',
            b'\xFF\xF2': 'MP3 audio',
            b'RIFF': 'WAV audio',
            b'OggS': 'OGG audio',
            b'\x1A\x45\xDF\xA3': 'WebM video',
            b'\x00\x00\x00\x20\x66\x74\x79\x70': 'MP4 video',
            b'\x52\x49\x46\x46': 'AVI video',
            b'\x00\x00\x01\xBA': 'MPEG video',
            b'\x00\x00\x01\xB3': 'MPEG video',
            b'MZ': 'Windows executable',
            b'\x7F\x45\x4C\x46': 'ELF executable',
            b'\xCA\xFE\xBA\xBE': 'Java class file',
            b'\xD0\xCF\x11\xE0': 'Microsoft Office document',
            b'\x50\x4B\x03\x04\x14\x00\x06\x00': 'Microsoft Office document (2007+)'
        }
        
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
        Generate terminal commands using a simple rule-based approach for the specified OS.
        Args:
            task (str): The user's task description
            os_type (str): The target operating system ('windows', 'macos', or 'linux')
        Returns:
            str: The generated command
        """
        task = task.lower()
        
        # Common command mappings
        command_map = {
            'windows': {
                'list files': 'dir',
                'list directories': 'dir',
                'show files': 'dir',
                'show directories': 'dir',
                'create directory': 'mkdir',
                'make directory': 'mkdir',
                'remove directory': 'rmdir',
                'delete directory': 'rmdir',
                'remove file': 'del',
                'delete file': 'del',
                'copy file': 'copy',
                'move file': 'move',
                'rename file': 'ren',
                'show current directory': 'cd',
                'change directory': 'cd',
                'clear screen': 'cls',
                'show system info': 'systeminfo',
                'show network info': 'ipconfig',
                'show processes': 'tasklist',
                'kill process': 'taskkill /F /IM',
                'show disk space': 'wmic logicaldisk get size,freespace,caption',
                'show memory': 'wmic OS get FreePhysicalMemory,TotalVisibleMemorySize /Value',
                'show cpu info': 'wmic cpu get name',
                'show os version': 'ver',
                'show date': 'date',
                'show time': 'time',
                'ping': 'ping',
                'tracert': 'tracert',
                'netstat': 'netstat',
                'execute': 'start',
                'run': 'start',
                'open': 'start',
                'aos': 'start aos.exe'  # Special case for AOS file
            },
            'linux': {
                'list files': 'ls',
                'list directories': 'ls',
                'show files': 'ls',
                'show directories': 'ls',
                'create directory': 'mkdir',
                'make directory': 'mkdir',
                'remove directory': 'rm -r',
                'delete directory': 'rm -r',
                'remove file': 'rm',
                'delete file': 'rm',
                'copy file': 'cp',
                'move file': 'mv',
                'rename file': 'mv',
                'show current directory': 'pwd',
                'change directory': 'cd',
                'clear screen': 'clear',
                'show system info': 'uname -a',
                'show network info': 'ifconfig',
                'show processes': 'ps aux',
                'kill process': 'kill',
                'show disk space': 'df -h',
                'show memory': 'free -h',
                'show cpu info': 'lscpu',
                'show os version': 'cat /etc/os-release',
                'show date': 'date',
                'show time': 'date',
                'ping': 'ping',
                'tracert': 'traceroute',
                'netstat': 'netstat',
                'execute': './',
                'run': './',
                'open': './',
                'aos': './aos'  # Special case for AOS file
            },
            'macos': {
                'list files': 'ls',
                'list directories': 'ls',
                'show files': 'ls',
                'show directories': 'ls',
                'create directory': 'mkdir',
                'make directory': 'mkdir',
                'remove directory': 'rm -r',
                'delete directory': 'rm -r',
                'remove file': 'rm',
                'delete file': 'rm',
                'copy file': 'cp',
                'move file': 'mv',
                'rename file': 'mv',
                'show current directory': 'pwd',
                'change directory': 'cd',
                'clear screen': 'clear',
                'show system info': 'system_profiler SPSoftwareDataType',
                'show network info': 'ifconfig',
                'show processes': 'ps aux',
                'kill process': 'kill',
                'show disk space': 'df -h',
                'show memory': 'vm_stat',
                'show cpu info': 'sysctl -n machdep.cpu.brand_string',
                'show os version': 'sw_vers',
                'show date': 'date',
                'show time': 'date',
                'ping': 'ping',
                'tracert': 'traceroute',
                'netstat': 'netstat',
                'execute': 'open',
                'run': 'open',
                'open': 'open',
                'aos': 'open aos'  # Special case for AOS file
            }
        }
        
        # Get the appropriate command map for the OS
        os_commands = command_map.get(os_type, command_map['windows'])
        
        # Check for exact matches first
        for key, cmd in os_commands.items():
            if key in task:
                return cmd
        
        # If no exact match, try to find the closest match
        words = task.split()
        for word in words:
            for key, cmd in os_commands.items():
                if word in key:
                    return cmd
        
        # If no match found, return a default command based on the OS
        if os_type == 'windows':
            return 'dir'  # Default to listing files on Windows
        else:
            return 'ls'   # Default to listing files on Unix-like systems
    
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
    
    def _detect_file_type(self, filepath: str) -> str:
        """
        Detect file type using file signatures and extension.
        
        Args:
            filepath (str): Path to the file
            
        Returns:
            str: Detected file type
        """
        try:
            # First check file extension
            _, ext = os.path.splitext(filepath)
            ext = ext.lower()
            
            # Try to read file signature
            with open(filepath, 'rb') as f:
                header = f.read(16)  # Read first 16 bytes
                
                # Check against known signatures
                for signature, file_type in self.file_signatures.items():
                    if header.startswith(signature):
                        return file_type
                
                # If no signature match, try to detect if it's text
                try:
                    header.decode('utf-8')
                    return 'Text file'
                except UnicodeDecodeError:
                    return 'Binary file'
                    
        except Exception:
            return 'Unknown file type'
    
    def analyze_file(self, filepath: str) -> Dict:
        """
        Analyze a file and return its properties and content information.
        
        Args:
            filepath (str): Path to the file to analyze
            
        Returns:
            Dict: Dictionary containing file analysis results
        """
        try:
            # Get basic file information
            stats = os.stat(filepath)
            file_size = stats.st_size
            created_time = stats.st_ctime
            modified_time = stats.st_mtime
            
            # Get file extension
            _, ext = os.path.splitext(filepath)
            ext = ext.lower()
            
            # Detect file type
            file_type = self._detect_file_type(filepath)
            mime_type = mimetypes.guess_type(filepath)[0] or 'application/octet-stream'
            
            # Initialize analysis result
            analysis = {
                'path': filepath,
                'size': file_size,
                'created': created_time,
                'modified': modified_time,
                'extension': ext,
                'mime_type': mime_type,
                'file_type': file_type,
                'is_text': ext in self.text_extensions,
                'is_binary': ext in self.binary_extensions,
                'content_preview': None,
                'line_count': 0,
                'encoding': None
            }
            
            # Try to read file content if it's a text file
            if analysis['is_text']:
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        content = f.read()
                        analysis['line_count'] = len(content.splitlines())
                        analysis['content_preview'] = content[:1000]  # First 1000 chars
                        analysis['encoding'] = 'utf-8'
                except UnicodeDecodeError:
                    try:
                        with open(filepath, 'r', encoding='latin-1') as f:
                            content = f.read()
                            analysis['line_count'] = len(content.splitlines())
                            analysis['content_preview'] = content[:1000]
                            analysis['encoding'] = 'latin-1'
                    except Exception as e:
                        analysis['error'] = f"Could not read file content: {str(e)}"
            
            return analysis
            
        except Exception as e:
            return {'error': f"Error analyzing file: {str(e)}"}
    
    def display_file_analysis(self, analysis: Dict) -> None:
        """
        Display file analysis results in a formatted way.
        
        Args:
            analysis (Dict): File analysis results
        """
        if 'error' in analysis:
            self.console.print(f"[red]Error: {analysis['error']}[/red]")
            return
            
        # Create a formatted display of the analysis
        info = f"""
        [bold blue]File Analysis Results:[/bold blue]
        
        [bold]Path:[/bold] {analysis['path']}
        [bold]Size:[/bold] {analysis['size']} bytes
        [bold]Created:[/bold] {analysis['created']}
        [bold]Modified:[/bold] {analysis['modified']}
        [bold]Extension:[/bold] {analysis['extension']}
        [bold]MIME Type:[/bold] {analysis['mime_type']}
        [bold]File Type:[/bold] {analysis['file_type']}
        [bold]Type:[/bold] {'Text' if analysis['is_text'] else 'Binary' if analysis['is_binary'] else 'Unknown'}
        """
        
        if analysis['is_text']:
            info += f"""
            [bold]Line Count:[/bold] {analysis['line_count']}
            [bold]Encoding:[/bold] {analysis['encoding']}
            
            [bold]Content Preview:[/bold]
            """
            self.console.print(Panel(info, title="File Analysis", border_style="blue"))
            if analysis['content_preview']:
                self.console.print(Syntax(analysis['content_preview'], "text", theme="monokai"))
        else:
            self.console.print(Panel(info, title="File Analysis", border_style="blue"))
    
    def process_task(self, task: str) -> None:
        """Process the user's task and execute appropriate commands."""
        self.console.print(f"\n[bold blue]Operating System detected:[/bold blue] {self.os_type}")
        self.console.print(f"[bold blue]Processing task:[/bold blue] {task}")
        
        # Check if the task is about file analysis
        if any(word in task.lower() for word in ['analyze', 'show', 'display', 'info', 'information', 'details']):
            # Extract file path from task
            words = task.split()
            for i, word in enumerate(words):
                if os.path.exists(word):
                    analysis = self.analyze_file(word)
                    self.display_file_analysis(analysis)
                    return
                elif i > 0 and os.path.exists(f"{words[i-1]} {word}"):
                    analysis = self.analyze_file(f"{words[i-1]} {word}")
                    self.display_file_analysis(analysis)
                    return
        
        # Get command from command generator
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