#!/usr/bin/env python3
import os
import sys
import subprocess
import platform

VENV_DIR = os.path.expanduser("~/.venv")

def run(cmd):
    """Run a shell command and stream output."""
    print(f"Running: {' '.join(cmd)}")
    result = subprocess.run(cmd)
    if result.returncode != 0:
        print(f"[ERROR] Command failed: {' '.join(cmd)}")
        sys.exit(1)

def main():
    print("=== ICS Environment Setup Script ===")
    print(f"Python version detected: {platform.python_version()}")
    print("Creating virtual environment...")

    run([sys.executable, "-m", "venv", VENV_DIR])

    if platform.system() == "Windows":
        activate_path = os.path.join(VENV_DIR, "Scripts", "activate")
        pip_path = os.path.join(VENV_DIR, "Scripts", "pip")
    else:
        activate_path = os.path.join(VENV_DIR, "bin", "activate")
        pip_path = os.path.join(VENV_DIR, "bin", "pip")

    print(f"Virtual environment created at: {VENV_DIR}")
    print("Installing required packages...")

    #packages needed to install
    required_packages = [
        "pycomm3",
        "xmltodict"
        "pyray"
    ]

    for pkg in required_packages:
        run([pip_path, "install", pkg])

    print("\n=== Setup Complete ===")
    print("To activate the environment:")
    if platform.system() == "Windows":
        print(f"    {VENV_DIR}\\Scripts\\activate")
    else:
        print(f"    source ~/ics_env/bin/activate")

    print("\nOnce activated, run your ICS scripts normally.")
    print("Example:")
    print("    python plc_monitor.py")
    print("\nEnvironment is ready.")

if __name__ == "__main__":
    main()
