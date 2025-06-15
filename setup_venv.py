#!/usr/bin/env python3

import os
import sys
import subprocess
import platform
from pathlib import Path

def create_venv():
    """Create and set up the virtual environment."""
    venv_name = "terminus_venv"
    
    # Create virtual environment
    print(f"Creating virtual environment: {venv_name}")
    subprocess.run([sys.executable, "-m", "venv", venv_name], check=True)
    
    # Determine the pip path based on OS
    if platform.system() == "Windows":
        pip_path = os.path.join(venv_name, "Scripts", "pip")
        activate_path = os.path.join(venv_name, "Scripts", "activate")
    else:
        pip_path = os.path.join(venv_name, "bin", "pip")
        activate_path = os.path.join(venv_name, "bin", "activate")
    
    # Upgrade pip
    print("Upgrading pip...")
    subprocess.run([pip_path, "install", "--upgrade", "pip"], check=True)
    
    # Install requirements
    print("Installing requirements...")
    subprocess.run([pip_path, "install", "-r", "requirements.txt"], check=True)
    
    print("\nVirtual environment setup complete!")
    print("\nTo activate the virtual environment:")
    if platform.system() == "Windows":
        print(f"    {venv_name}\\Scripts\\activate")
    else:
        print(f"    source {venv_name}/bin/activate")
    
    print("\nTo run AGIS-Terminus:")
    print("    python agis_terminus.py")

if __name__ == "__main__":
    try:
        create_venv()
    except subprocess.CalledProcessError as e:
        print(f"Error during setup: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}")
        sys.exit(1) 