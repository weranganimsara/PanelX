#!/usr/bin/env python3
"""
=============================================================================
PANELX — Enterprise Linux Server & VPN Management Control Panel (v2.0)
"Powered by SG Home"
=============================================================================
This file serves as the main entrypoint and backward-compatibility wrapper,
launching the high-performance async production engine from panelx_server.py.
=============================================================================
"""

import sys
import os

# Ensure current directory is on python search path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

try:
    from panelx_server import *
except ImportError as e:
    # If fastapi or uvicorn isn't installed yet, warn user
    print(f"[PANELX WARNING] FastAPI / Uvicorn dependency missing: {e}")
    print("[PANELX] Please run 'bash update_panelx.sh' to install required packages.")
    sys.exit(1)

if __name__ == "__main__":
    run_server()
