"""
Main TUI Application for Bl4ckC3ll_PANTHEON
Advanced Terminal User Interface with real-time monitoring and professional layout
"""

from textual.app import App
from textual.containers import Container, Horizontal, Vertical
from textual.widgets import (
    Header, Footer, Static, Button, Input, Log, 
    DataTable, ProgressBar, Tree, TabbedContent, TabPane
)
from textual.binding import Binding
from textual import on
import asyncio
import time
from datetime import datetime
import threading

# Import screens locally to avoid circular import issues
import sys
import os
from pathlib import Path

# Add parent directory to path for relative imports
sys.path.append(str(Path(__file__).parent.parent))


class PantheonTUI(App):
    """Advanced TUI for Bl4ckC3ll_PANTHEON Security Testing Framework"""
    
    CSS_PATH = "styles.css"
    TITLE = "Bl4ckC3ll PANTHEON - Advanced Security Testing Framework"
    SUB_TITLE = "Professional Penetration Testing & Vulnerability Assessment"
    
    BINDINGS = [
        Binding("ctrl+q", "quit", "Quit"),
        Binding("ctrl+d", "toggle_dark", "Toggle Dark Mode"),
        Binding("f1", "show_help", "Help"),
        Binding("f2", "targets", "Targets"),
        Binding("f3", "scan", "Scan"),
        Binding("f4", "reports", "Reports"),
        Binding("f5", "settings", "Settings"),
        Binding("ctrl+r", "refresh", "Refresh"),
        Binding("ctrl+s", "save_config", "Save Config"),
    ]
    
    def __init__(self):
        super().__init__()
        self.scan_runner = None
        self.system_monitor = None
        
    def compose(self):
        """Create the main layout"""
        yield Header()
        
        with TabbedContent(initial="dashboard"):
            with TabPane("Dashboard", id="dashboard"):
                from .screens.main_dashboard import MainDashboard
                yield MainDashboard()
                
            with TabPane("Targets", id="targets"):  
                from .screens.targets import TargetsScreen
                yield TargetsScreen()
                
            with TabPane("Scanner", id="scanner"):
                from .screens.scan_runner import ScanRunner
                yield ScanRunner()
                
            with TabPane("Reports", id="reports"):
                from .screens.reports import ReportsScreen
                yield ReportsScreen()
                
            with TabPane("Settings", id="settings"):
                from .screens.settings import SettingsScreen
                yield SettingsScreen()
                
        yield Footer()
        
    def on_mount(self):
        """Initialize the application"""
        self.title = self.TITLE
        self.sub_title = self.SUB_TITLE
        
        # Start system monitoring
        self.start_system_monitor()
        
    def start_system_monitor(self):
        """Start background system monitoring"""
        def monitor_loop():
            while True:
                # Update system stats, scan progress, etc.
                time.sleep(1)
                
        self.system_monitor = threading.Thread(target=monitor_loop, daemon=True)
        self.system_monitor.start()
        
    def action_quit(self):
        """Quit the application"""
        self.exit()
        
    def action_toggle_dark(self):
        """Toggle dark mode"""
        self.dark = not self.dark
        
    def action_show_help(self):
        """Show help screen"""
        self.push_screen("help")
        
    def action_targets(self):
        """Switch to targets tab"""
        self.query_one(TabbedContent).active = "targets"
        
    def action_scan(self):
        """Switch to scanner tab"""  
        self.query_one(TabbedContent).active = "scanner"
        
    def action_reports(self):
        """Switch to reports tab"""
        self.query_one(TabbedContent).active = "reports"
        
    def action_settings(self):
        """Switch to settings tab"""
        self.query_one(TabbedContent).active = "settings"
        
    def action_refresh(self):
        """Refresh current view"""
        # Refresh the active tab content
        pass
        
    def action_save_config(self):
        """Save current configuration"""
        # Save settings to config file
        pass


if __name__ == "__main__":
    app = PantheonTUI()
    app.run()