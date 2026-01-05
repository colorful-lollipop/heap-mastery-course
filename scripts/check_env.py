#!/usr/bin/env python3
"""
Python Environment Checker for Heap Mastery Course
Checks and optionally installs missing dependencies
"""

import sys
import subprocess
import importlib
from pathlib import Path

RED = '\033[0;31m'
GREEN = '\033[0;32m'
YELLOW = '\033[1;33m'
BLUE = '\033[0;34m'
NC = '\033[0m'

def check_command(cmd):
    """Check if a command exists in PATH"""
    try:
        subprocess.run(['which', cmd], capture_output=True, check=True)
        return True
    except subprocess.CalledProcessError:
        return False

def check_python_module(module):
    """Check if a Python module is installed"""
    try:
        importlib.import_module(module)
        return True
    except ImportError:
        return False

def get_module_version(module):
    """Get version of a Python module"""
    try:
        mod = importlib.import_module(module)
        if hasattr(mod, '__version__'):
            return mod.__version__
        # Special handling for pwntools
        if module == 'pwntools':
            try:
                from pwn import __version__
                return __version__
            except:
                pass
        return 'installed'
    except:
        return None

def install_python_package(package):
    """Install a Python package using pip"""
    try:
        subprocess.run(
            [sys.executable, '-m', 'pip', 'install', package, '-q'],
            check=True,
            capture_output=True
        )
        return True
    except subprocess.CalledProcessError:
        return False

def main():
    print("=" * 50)
    print("  Heap Mastery Course - Python Env Check")
    print("=" * 50)
    print()

    checks = [
        # System commands
        ('Python3', 'check_command', 'python3'),
        ('GCC', 'check_command', 'gcc'),
        ('GDB', 'check_command', 'gdb'),
        ('Make', 'check_command', 'make'),
        ('CMake', 'check_command', 'cmake'),
    ]

    python_modules = [
        ('pwntools', 'pwn'),  # Import name is 'pwn', not 'pwntools'
        ('capstone', 'capstone'),
        ('unicorn', 'unicorn'),
    ]

    print(f"{BLUE}[1/2] Checking system dependencies...{NC}")
    for name, check_type, value in checks:
        if check_type == 'check_command':
            if check_command(value):
                version = subprocess.run([value, '--version'],
                                       capture_output=True, text=True)
                version_str = version.stdout.split('\n')[0]
                print(f"{GREEN}[✓]{NC} {name}: {version_str}")
            else:
                print(f"{RED}[✗]{NC} {name}: not found")

    print()
    print(f"{BLUE}[2/2] Checking Python packages...{NC}")
    missing_packages = []
    for name, module in python_modules:
        if check_python_module(module):
            version = get_module_version(module)
            print(f"{GREEN}[✓]{NC} {name}: {version}")
        else:
            print(f"{YELLOW}[!]{NC} {name}: not found")
            missing_packages.append(name)

    # Install missing packages
    critical_missing = []
    if missing_packages:
        print()
        print(f"{YELLOW}[!] Missing Python packages: {', '.join(missing_packages)}{NC}")

        # Check if we're in interactive mode
        if len(sys.argv) > 1 and sys.argv[1] == '--install':
            print(f"{BLUE}[*] Installing missing packages...{NC}")
            for pkg in missing_packages:
                print(f"  Installing {pkg}...")
                if install_python_package(pkg):
                    print(f"  {GREEN}[✓]{NC} {pkg} installed")
                    # Re-check after installation
                    if check_python_module(pkg):
                        print(f"     {GREEN}Verified: {pkg} is now available{NC}")
                    else:
                        print(f"     {YELLOW}Warning: {pkg} installed but not importable{NC}")
                else:
                    print(f"  {RED}[✗]{NC} {pkg} failed to install")
        else:
            print(f"  Run: {sys.argv[0]} --install")

    # Re-check critical packages after potential installation
    for pkg_name, module in [('pwntools', 'pwn')]:  # Import name is 'pwn'
        if not check_python_module(module):
            critical_missing.append(pkg_name)

    print()
    print("=" * 50)

    # Return error if any critical package is still missing
    if critical_missing:
        print(f"{RED}[!] Critical packages still missing: {', '.join(critical_missing)}{NC}")
        return 1
    else:
        print(f"{GREEN}[✓] All critical dependencies OK{NC}")
        return 0

if __name__ == '__main__':
    sys.exit(main())
