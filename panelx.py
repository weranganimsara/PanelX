#!/usr/bin/env python3
"""
=============================================================================
PANELX CORE ENGINE — COMPILED BINARY EXECUTABLE LOADER
Copyright (c) SG Home & Weranga Nimsara. All rights reserved.
=============================================================================
This is the official precompiled binary distribution of PanelX.
Protected by SG Home Digital Integrity Guardian & Anti-Tamper System.
Architecture: Linux x86_64 / ELF 64-bit Standalone Native Binary.
=============================================================================
"""
import os
import sys

def main():
    binary_path = "/usr/local/bin/panelx-core"
    local_binary = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bin", "panelx-core")
    
    if os.path.exists(binary_path) and os.access(binary_path, os.X_OK):
        os.execv(binary_path, sys.argv)
    elif os.path.exists(local_binary) and os.access(local_binary, os.X_OK):
        os.execv(local_binary, sys.argv)
    else:
        print("[!] PanelX Core standalone binary not found.")
        print("[*] Please run install.sh to initialize and register the compiled binary engine.")
        sys.exit(1)

if __name__ == "__main__":
    main()
