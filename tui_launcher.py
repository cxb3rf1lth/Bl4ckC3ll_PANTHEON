#!/usr/bin/env python3
"""
TUI Launcher for Bl4ckC3ll_PANTHEON
Advanced Terminal User Interface entry point
"""

import sys
import os
from pathlib import Path

# Ensure TUI directory is in path
TUI_DIR = Path(__file__).parent / "tui"
sys.path.insert(0, str(TUI_DIR))

def launch_tui():
    """Launch the advanced TUI interface"""
    try:
        from tui.app import PantheonTUI
        
        # Initialize and run the TUI application
        app = PantheonTUI()
        app.run()
        
    except ImportError as e:
        print(f"Error: Failed to import TUI components: {e}")
        print("Please ensure textual is installed: pip install textual")
        sys.exit(1)
    except Exception as e:
        print(f"Error launching TUI: {e}")
        sys.exit(1)

if __name__ == "__main__":
    launch_tui()