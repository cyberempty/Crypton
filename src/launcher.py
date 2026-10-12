#!/usr/bin/env python3

import sys
import os
import subprocess
import platform
import shutil
from pathlib import Path

sys.dont_write_bytecode = True


def get_app_path():
    """Get the application path"""
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def get_script_path():
    """Get the main script path"""
    base = os.path.dirname(os.path.abspath(__file__))
    script = os.path.join(base, "app.py")
    return script


def get_python_cmd():
    """Get the appropriate Python command for no-terminal execution"""
    if getattr(sys, 'frozen', False):
        return [sys.executable]
    
    system = platform.system()
    
    if system == "Windows":
        # Use pythonw.exe to hide terminal
        pythonw = shutil.which("pythonw.exe")
        if pythonw:
            return [pythonw]
        return [sys.executable]
    else:
        # Mac/Linux
        python3 = shutil.which("python3")
        if python3:
            return [python3]
        return [sys.executable]


def main():
    """Launch the application"""
    # Get the script path
    script_path = get_script_path()
    
    if not os.path.exists(script_path):
        print(f"Error: Script not found: {script_path}")
        if platform.system() == "Windows":
            input("Press any key to exit...")
        sys.exit(1)
    
    # Get Python command
    python_cmd = get_python_cmd()
    
    try:
        # Set environment to disable __pycache__
        env = os.environ.copy()
        env['PYTHONDONTWRITEBYTECODE'] = '1'
        
        # Add current directory to Python path
        app_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if 'PYTHONPATH' in env:
            env['PYTHONPATH'] = app_dir + os.pathsep + env['PYTHONPATH']
        else:
            env['PYTHONPATH'] = app_dir
        
        # Launch the application completely hidden
        if platform.system() == "Windows":
            # Windows: use CREATE_NO_WINDOW
            subprocess.Popen(
                python_cmd + [script_path] + sys.argv[1:],
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=env
            )
        else:
            # Mac/Linux: launch in background
            subprocess.Popen(
                python_cmd + [script_path] + sys.argv[1:],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL,
                env=env,
                start_new_session=True
            )
        
        # Launcher exits immediately
        sys.exit(0)
        
    except Exception as e:
        print(f"Error: {e}")
        if platform.system() == "Windows":
            input("Press any key to exit...")
        sys.exit(1)


if __name__ == "__main__":
    main()
