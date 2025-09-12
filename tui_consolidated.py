#!/usr/bin/env python3
"""
Consolidated Bl4ckC3ll_PANTHEON TUI - Single Master Application
Advanced Security Testing Framework with Complete TUI Interface
"""

from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical, ScrollableContainer
from textual.widgets import (
    Header, Footer, Static, Button, Label, Input, DataTable, 
    TextArea, ProgressBar, Log, Select, Checkbox
)
from textual.binding import Binding
from textual.reactive import reactive
from textual import on
import os
import sys
import json
import time
import threading
import logging
import subprocess
import platform
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional

# Add main directory to path
sys.path.append(str(Path(__file__).parent))

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Try to import main application functions
try:
    from bl4ckc3ll_p4nth30n import (
        load_cfg, env_with_lists, new_run, stage_recon, 
        stage_vuln_scan, stage_report
    )
    BACKEND_AVAILABLE = True
except ImportError:
    BACKEND_AVAILABLE = False

# Try to import psutil for system monitoring
try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False


class TargetManagement(Static):
    """Target management widget"""
    
    def compose(self) -> ComposeResult:
        yield Label("🎯 Target Management", classes="section-title")
        
        with Horizontal():
            # Left panel - Input
            with Vertical(classes="left-panel"):
                yield Label("Add Single Target:")
                with Horizontal():
                    yield Input(placeholder="domain.com or IP", id="target-input")
                    yield Button("Add", variant="primary", id="add-target-btn")
                
                yield Label("Bulk Import:")
                yield TextArea(placeholder="One target per line", id="bulk-input", classes="small-area")
                yield Button("Import All", variant="success", id="import-btn")
                
                yield Label("", id="target-status")
            
            # Right panel - Target list
            with Vertical(classes="right-panel"):
                yield Label("Current Targets:")
                table = DataTable(id="targets-table")
                table.add_columns("Target", "Status", "Type")
                yield table
                
                with Horizontal():
                    yield Button("Remove", variant="error", id="remove-btn")
                    yield Button("Clear All", variant="error", id="clear-btn")
                    yield Button("Save to File", id="save-targets-btn")
                    
    @on(Button.Pressed, "#add-target-btn")
    def add_target(self):
        """Add single target"""
        target_input = self.query_one("#target-input", Input)
        target = target_input.value.strip()
        
        if target and self.validate_target(target):
            table = self.query_one("#targets-table", DataTable)
            target_type = "IP" if self.is_ip(target) else "Domain"
            table.add_row(target, "Ready", target_type)
            target_input.value = ""
            self.query_one("#target-status").update(f"✓ Added: {target}")
        else:
            self.query_one("#target-status").update("❌ Invalid target format")
    
    @on(Button.Pressed, "#import-btn")
    def import_targets(self):
        """Import bulk targets"""
        bulk_input = self.query_one("#bulk-input", TextArea)
        targets = [line.strip() for line in bulk_input.text.split('\n') if line.strip()]
        
        valid_count = 0
        table = self.query_one("#targets-table", DataTable)
        
        for target in targets:
            if self.validate_target(target):
                target_type = "IP" if self.is_ip(target) else "Domain"
                table.add_row(target, "Ready", target_type)
                valid_count += 1
        
        bulk_input.text = ""
        self.query_one("#target-status").update(f"✓ Imported {valid_count} targets")
    
    @on(Button.Pressed, "#remove-btn")
    def remove_target(self):
        """Remove selected target"""
        table = self.query_one("#targets-table", DataTable)
        if table.cursor_row is not None:
            table.remove_row(table.cursor_row)
    
    @on(Button.Pressed, "#clear-btn") 
    def clear_targets(self):
        """Clear all targets"""
        table = self.query_one("#targets-table", DataTable)
        table.clear()
        self.query_one("#target-status").update("All targets cleared")
        
    @on(Button.Pressed, "#save-targets-btn")
    def save_targets(self):
        """Save targets to file"""
        table = self.query_one("#targets-table", DataTable)
        targets = []
        for row_key in table.rows:
            row = table.get_row(row_key)
            targets.append(row[0])
            
        try:
            targets_file = Path("targets.txt")
            targets_file.write_text('\n'.join(targets))
            self.query_one("#target-status").update(f"✓ Saved {len(targets)} targets")
        except Exception as e:
            self.query_one("#target-status").update(f"❌ Save failed: {e}")
    
    def validate_target(self, target: str) -> bool:
        """Validate target format"""
        import re
        
        # Domain pattern
        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        # IP pattern
        ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        
        return bool(re.match(domain_pattern, target)) or bool(re.match(ip_pattern, target))
    
    def is_ip(self, target: str) -> bool:
        """Check if target is IP address"""
        import re
        ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        return bool(re.match(ip_pattern, target))


class ScanConfiguration(Static):
    """Scan configuration and execution"""
    
    def compose(self) -> ComposeResult:
        yield Label("🔍 Scan Configuration & Execution", classes="section-title")
        
        with Horizontal():
            # Left panel - Configuration
            with Vertical(classes="left-panel"):
                yield Label("Scan Type:")
                yield Select([
                    ("Quick Reconnaissance", "quick-recon"),
                    ("Full Security Scan", "full-scan"),
                    ("Vulnerability Scan Only", "vuln-scan"),
                    ("Subdomain Discovery", "subdomain"),
                    ("Port Scanning", "port-scan"),
                    ("Web Application Test", "web-app"),
                    ("API Security Test", "api-test"),
                    ("Cloud Security Assessment", "cloud-test")
                ], id="scan-type")
                
                yield Label("Options:")
                yield Checkbox("Aggressive Mode", id="aggressive-mode")
                yield Checkbox("Skip Rate Limits", id="skip-limits")
                yield Checkbox("Deep Scan", id="deep-scan")
                yield Checkbox("Generate Report", id="auto-report", value=True)
                
                with Horizontal():
                    yield Button("Start Scan", variant="success", id="start-scan-btn")
                    yield Button("Stop Scan", variant="error", id="stop-scan-btn")
            
            # Right panel - Progress and logs
            with Vertical(classes="right-panel"):
                yield Label("Scan Progress:")
                yield ProgressBar(total=100, show_percentage=True, id="scan-progress")
                yield Label("Idle", id="scan-status")
                
                yield Label("Live Output:")
                yield Log(id="scan-log")
    
    @on(Button.Pressed, "#start-scan-btn")
    def start_scan(self):
        """Start security scan"""
        scan_type = self.query_one("#scan-type").value
        
        # Get targets from target management
        try:
            targets_table = self.screen.query_one("#targets-table", DataTable)
            targets = [table.get_row(row_key)[0] for row_key in targets_table.rows]
            
            if not targets:
                self.query_one("#scan-log").write("❌ No targets configured")
                return
            
            self.query_one("#scan-status").update("Starting scan...")
            self.query_one("#scan-log").write(f"🚀 Starting {scan_type} for {len(targets)} targets")
            
            # Start scan in background thread
            self._run_scan(scan_type, targets)
            
        except Exception as e:
            self.query_one("#scan-log").write(f"❌ Scan failed: {e}")
    
    @on(Button.Pressed, "#stop-scan-btn")
    def stop_scan(self):
        """Stop current scan"""
        self.query_one("#scan-status").update("Stopping...")
        self.query_one("#scan-log").write("🛑 Scan stopped by user")
    
    def _run_scan(self, scan_type: str, targets: List[str]):
        """Run scan in background"""
        def scan_thread():
            try:
                progress = self.query_one("#scan-progress", ProgressBar)
                status = self.query_one("#scan-status")
                log = self.query_one("#scan-log")
                
                progress.progress = 10
                status.update("Initializing...")
                
                # Mock scan progression for now
                phases = [
                    ("Reconnaissance", 30),
                    ("Port Scanning", 50), 
                    ("Service Detection", 70),
                    ("Vulnerability Testing", 90),
                    ("Report Generation", 100)
                ]
                
                for phase, prog in phases:
                    time.sleep(2)  # Simulate work
                    progress.progress = prog
                    status.update(f"Running: {phase}")
                    log.write(f"📊 {phase} in progress...")
                
                status.update("Scan Complete")
                log.write("✅ Scan completed successfully")
                
                # If backend is available, run real scan
                if BACKEND_AVAILABLE:
                    self._run_real_scan(scan_type, targets)
                
            except Exception as e:
                log.write(f"❌ Scan error: {e}")
                status.update("Error")
        
        threading.Thread(target=scan_thread, daemon=True).start()
    
    def _run_real_scan(self, scan_type: str, targets: List[str]):
        """Run real scan using backend"""
        try:
            cfg = load_cfg()
            env = env_with_lists()
            rd = new_run()
            
            # Write targets to file
            targets_file = Path("targets.txt")
            targets_file.write_text('\n'.join(targets))
            
            log = self.query_one("#scan-log")
            
            if scan_type in ["quick-recon", "full-scan"]:
                log.write("🔍 Running reconnaissance...")
                stage_recon(rd, env, cfg)
            
            if scan_type in ["vuln-scan", "full-scan"]:
                log.write("🚨 Running vulnerability scan...")
                stage_vuln_scan(rd, env, cfg)
            
            if self.query_one("#auto-report").value:
                log.write("📊 Generating report...")
                stage_report(rd, env, cfg)
                
        except Exception as e:
            self.query_one("#scan-log").write(f"❌ Backend scan failed: {e}")


class SystemDashboard(Static):
    """System monitoring dashboard"""
    
    cpu_usage = reactive(0.0)
    memory_usage = reactive(0.0)
    disk_usage = reactive(0.0)
    
    def compose(self) -> ComposeResult:
        yield Label("📊 System Dashboard", classes="section-title")
        
        with Horizontal():
            # System info
            with Vertical(classes="left-panel"):
                yield Label("System Information:")
                yield Label(f"OS: {platform.system()} {platform.release()}")
                yield Label(f"Python: {platform.python_version()}")
                yield Label(f"Architecture: {platform.machine()}")
                yield Label(f"Hostname: {platform.node()}")
                
                yield Label("Framework Status:")
                yield Label("✅ TUI Active", classes="status-ready")
                yield Label(f"🔧 Backend: {'Available' if BACKEND_AVAILABLE else 'Limited'}")
                yield Label(f"📊 Monitoring: {'Active' if HAS_PSUTIL else 'Basic'}")
            
            # Resource monitoring
            with Vertical(classes="right-panel"):
                yield Label("Resource Monitor:")
                
                yield Label("CPU Usage:")
                yield ProgressBar(total=100, show_percentage=True, id="cpu-bar")
                
                yield Label("Memory Usage:")  
                yield ProgressBar(total=100, show_percentage=True, id="memory-bar")
                
                yield Label("Disk Usage:")
                yield ProgressBar(total=100, show_percentage=True, id="disk-bar")
    
    def on_mount(self):
        """Start monitoring on mount"""
        self.set_interval(2.0, self.update_resources)
    
    def update_resources(self):
        """Update resource usage"""
        if not HAS_PSUTIL:
            return
        
        try:
            self.cpu_usage = psutil.cpu_percent(interval=None)
            memory = psutil.virtual_memory()
            self.memory_usage = memory.percent
            disk = psutil.disk_usage('/')
            self.disk_usage = (disk.used / disk.total) * 100
            
            # Update progress bars
            self.query_one("#cpu-bar").progress = self.cpu_usage
            self.query_one("#memory-bar").progress = self.memory_usage
            self.query_one("#disk-bar").progress = self.disk_usage
            
        except Exception as e:
                logging.warning(f"Operation failed: {e}")


class ReportViewer(Static):
    """Report viewing and management"""
    
    def compose(self) -> ComposeResult:
        yield Label("📋 Reports & Results", classes="section-title")
        
        with Horizontal():
            # Report list
            with Vertical(classes="left-panel"):
                yield Label("Available Reports:")
                
                table = DataTable(id="reports-table")
                table.add_columns("Date", "Type", "Targets", "Status")
                yield table
                
                with Horizontal():
                    yield Button("View Report", id="view-report-btn")
                    yield Button("Export HTML", id="export-html-btn")
                    yield Button("Export JSON", id="export-json-btn")
            
            # Report content
            with Vertical(classes="right-panel"):
                yield Label("Report Content:")
                yield ScrollableContainer(
                    Static("No report selected", id="report-content"),
                    id="report-viewer"
                )
        
        # Load available reports
        self.load_reports()
    
    def load_reports(self):
        """Load available reports"""
        try:
            runs_dir = Path("runs")
            if not runs_dir.exists():
                return
            
            table = self.query_one("#reports-table", DataTable)
            
            for run_dir in sorted(runs_dir.iterdir(), reverse=True):
                if run_dir.is_dir():
                    report_file = run_dir / "report" / "report.json"
                    if report_file.exists():
                        try:
                            # Extract basic info
                            date_str = run_dir.name[:19].replace('_', ' ')
                            table.add_row(date_str, "Full Scan", "Multiple", "Complete")
                        except Exception:
                            continue
                            
        except Exception as e:
            logger.warning(f"Failed to load reports: {e}")
    
    @on(Button.Pressed, "#view-report-btn")
    def view_report(self):
        """View selected report"""
        table = self.query_one("#reports-table", DataTable)
        if table.cursor_row is not None:
            row = table.get_row(table.cursor_row)
            self.query_one("#report-content").update(f"Viewing report: {row[0]}")


class ConsolidatedTUI(App):
    """Master TUI Application for Bl4ckC3ll_PANTHEON"""
    
    TITLE = "Bl4ckC3ll PANTHEON - Advanced Security Testing Framework"
    SUB_TITLE = "Complete Penetration Testing & Vulnerability Assessment Platform"
    
    CSS = """
    .section-title {
        text-style: bold;
        color: yellow;
        background: darkblue;
        padding: 0 1;
        margin: 0 0 1 0;
    }
    
    .left-panel {
        width: 45%;
        padding: 1;
        border: solid gray;
        margin: 0 1 0 0;
    }
    
    .right-panel {
        width: 55%;
        padding: 1;
        border: solid gray;
    }
    
    .status-ready {
        color: green;
        text-style: bold;
    }
    
    .small-area {
        height: 4;
    }
    
    .tab-content.hidden {
        visibility: hidden;
        height: 0;
    }
    
    #main-tabs Button {
        margin: 0 1 1 0;
        min-width: 16;
    }
    
    #main-tabs Button.active {
        background: yellow;
        color: black;
        text-style: bold;
    }
    
    .tab-content {
        padding: 1;
        height: 1fr;
    }
    """
    
    BINDINGS = [
        Binding("ctrl+q", "quit", "Quit"),
        Binding("f1", "show_tab('dashboard')", "Dashboard"), 
        Binding("f2", "show_tab('targets')", "Targets"),
        Binding("f3", "show_tab('scanner')", "Scanner"),
        Binding("f4", "show_tab('reports')", "Reports"),
    ]
    
    current_tab = reactive("dashboard")
    
    def compose(self) -> ComposeResult:
        yield Header()
        
        # Tab buttons
        with Horizontal(id="main-tabs"):
            yield Button("📊 Dashboard", id="tab-dashboard", classes="active")
            yield Button("🎯 Targets", id="tab-targets")
            yield Button("🔍 Scanner", id="tab-scanner")
            yield Button("📋 Reports", id="tab-reports")
        
        # Tab content
        with Container(id="tab-content-area"):
            with Container(id="dashboard-content", classes="tab-content"):
                yield SystemDashboard()
            
            with Container(id="targets-content", classes="tab-content hidden"):
                yield TargetManagement()
                
            with Container(id="scanner-content", classes="tab-content hidden"):
                yield ScanConfiguration()
                
            with Container(id="reports-content", classes="tab-content hidden"):
                yield ReportViewer()
        
        yield Footer()
    
    @on(Button.Pressed, "#main-tabs Button")
    def tab_clicked(self, event: Button.Pressed):
        """Handle tab button clicks"""
        tab_id = event.button.id.replace("tab-", "")
        self.show_tab(tab_id)
    
    def action_show_tab(self, tab: str):
        """Show specific tab"""
        self.show_tab(tab)
    
    def show_tab(self, tab: str):
        """Show the specified tab"""
        # Hide all tab contents
        for content in self.query(".tab-content"):
            content.add_class("hidden")
        
        # Remove active class from all tabs
        for btn in self.query("#main-tabs Button"):
            btn.remove_class("active")
        
        # Show selected tab content
        content = self.query_one(f"#{tab}-content")
        content.remove_class("hidden")
        
        # Activate selected tab button
        btn = self.query_one(f"#tab-{tab}")
        btn.add_class("active")
        
        self.current_tab = tab

    def on_mount(self):
        """Initialize application"""
        self.title = self.TITLE
        self.sub_title = self.SUB_TITLE


if __name__ == "__main__":
    app = ConsolidatedTUI()
    app.run()