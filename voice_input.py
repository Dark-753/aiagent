#!/usr/bin/env python3

import speech_recognition as sr
from rich.console import Console
from rich.prompt import Prompt
from typing import Optional, Tuple

class VoiceInput:
    def __init__(self):
        self.recognizer = sr.Recognizer()
        self.console = Console()
        
    def listen_for_task(self) -> Tuple[bool, Optional[str]]:
        """
        Listen for voice input and convert it to text.
        
        Returns:
            Tuple[bool, Optional[str]]: (success, text or error message)
        """
        try:
            with sr.Microphone() as source:
                self.console.print("\n[yellow]Adjusting for ambient noise...[/yellow]")
                self.recognizer.adjust_for_ambient_noise(source, duration=1)
                
                self.console.print("\n[bold green]Listening...[/bold green]")
                audio = self.recognizer.listen(source, timeout=10, phrase_time_limit=10)
                
                self.console.print("[yellow]Processing speech...[/yellow]")
                text = self.recognizer.recognize_google(audio)
                return True, text
                
        except sr.WaitTimeoutError:
            return False, "No speech detected within timeout period"
        except sr.UnknownValueError:
            return False, "Could not understand audio"
        except sr.RequestError as e:
            return False, f"Could not request results from speech recognition service: {str(e)}"
        except Exception as e:
            return False, f"Error during voice input: {str(e)}"
    
    def get_input_mode(self) -> bool:
        """
        Ask user if they want to use voice input.
        
        Returns:
            bool: True if voice input is selected, False for text input
        """
        while True:
            mode = Prompt.ask(
                "\n[bold blue]Choose input mode[/bold blue]",
                choices=["text", "voice"],
                default="text"
            )
            return mode == "voice"
    
    def get_task(self) -> Optional[str]:
        """
        Get task from user using either voice or text input.
        
        Returns:
            Optional[str]: The task text or None if there was an error
        """
        if self.get_input_mode():
            success, result = self.listen_for_task()
            if success:
                self.console.print(f"\n[bold green]Recognized task:[/bold green] {result}")
                return result
            else:
                self.console.print(f"\n[bold red]Voice input failed:[/bold red] {result}")
                # Fall back to text input
                self.console.print("[yellow]Falling back to text input...[/yellow]")
                return Prompt.ask("\n[bold blue]Enter your task[/bold blue]")
        else:
            return Prompt.ask("\n[bold blue]Enter your task[/bold blue]") 