# Bl4ckC3ll_PANTHEON Advanced TUI Interface

## Overview

The advanced Terminal User Interface (TUI) provides a modern, professional interface for Bl4ckC3ll_PANTHEON security testing framework. Built with Textual, it offers real-time monitoring, interactive controls, and a multi-panel dashboard for comprehensive security assessments.

## Features

### 🎛️ Professional Dashboard
- **System Information Panel**: Real-time OS, Python, and hardware information
- **Resource Monitor**: Live CPU, memory, and disk usage with progress bars  
- **Status Overview**: Framework status, scan history, and tool availability
- **Quick Actions**: One-click access to common scanning operations
- **Recent Activity**: Live activity log with timestamps and status

### 🎯 Target Management
- **Interactive Target Input**: Add single targets with validation
- **Bulk Import**: Import multiple targets from text input or files
- **Target Validation**: Real-time domain and IP address validation
- **Target Statistics**: Live counts and categorization of targets
- **Export/Import**: Save and load target lists

### 🔍 Advanced Scanner Interface
- **Scan Configuration**: Interactive scan type selection (Quick, Full, Recon, Vuln, API, Cloud)
- **Real-time Progress**: Live progress bars with phase tracking
- **Scan Controls**: Start, stop, pause, and resume operations
- **Live Logs**: Real-time log streaming during scans
- **Status Monitoring**: Detailed scan status and elapsed time tracking

### 📊 Reports Management
- **Report Browser**: Interactive list of all generated reports
- **Report Viewer**: Detailed report display with executive summaries
- **Filter & Search**: Filter reports by risk level, date, and other criteria
- **Export Options**: Export reports in HTML, PDF, and other formats
- **Risk Assessment**: Visual risk level indicators and vulnerability breakdowns

### ⚙️ Settings Management
- **Tabbed Configuration**: Organized settings across multiple categories
- **General Settings**: Framework-wide configuration options
- **Nuclei Configuration**: Advanced vulnerability scanner settings
- **Scanning Options**: Reconnaissance and discovery tool settings
- **Report Settings**: Output format and generation options
- **Advanced Options**: Resource management and plugin configuration
- **Configuration Management**: Save, load, reset, and export configurations

### 🛠️ Advanced Features
- **Keyboard Shortcuts**: Full keyboard navigation and shortcuts
- **Mouse Support**: Click, drag, and interact with all interface elements
- **Real-time Updates**: Live data refresh without screen flicker
- **Professional Styling**: Modern color schemes and typography
- **Responsive Layout**: Adapts to different terminal sizes
- **Multi-tab Interface**: Organized workflow with tabbed panels
- **Backend Integration**: Seamless connection to existing scan engines

## Usage

### Launching the TUI

#### From Main CLI
```bash
python3 bl4ckc3ll_p4nth30n.py
# Select option 18: [TUI] Launch Advanced TUI Interface
```

#### Direct Launch
```bash
python3 tui_launcher.py
```

### Navigation

#### Keyboard Shortcuts
- `Ctrl+Q`: Quit application
- `Ctrl+D`: Toggle dark/light mode
- `F1`: Show help
- `F2`: Switch to Targets tab
- `F3`: Switch to Scanner tab
- `F4`: Switch to Reports tab
- `F5`: Switch to Settings tab
- `Ctrl+R`: Refresh current view
- `Ctrl+S`: Save configuration

#### Mouse Navigation
- Click tabs to switch between panels
- Click buttons to execute actions
- Use scroll wheels in log and report viewers
- Drag to select text in input fields

### Workflow

#### 1. Configure Targets
1. Switch to **Targets** tab (F2)
2. Add targets using single input or bulk import
3. Validate and review target list
4. Export target list for backup

#### 2. Run Security Scan
1. Switch to **Scanner** tab (F3)
2. Select scan type and options
3. Enter target or use existing target list
4. Click "Start Scan" and monitor progress
5. View live logs for detailed status

#### 3. Review Results
1. Switch to **Reports** tab (F4)
2. Browse available reports
3. Select and view detailed report
4. Filter by risk level or date
5. Export report in preferred format

#### 4. Adjust Settings
1. Switch to **Settings** tab (F5)
2. Configure framework options
3. Adjust Nuclei and scanning parameters
4. Set report generation preferences
5. Save configuration changes

## Technical Details

### Architecture
- **Frontend**: Textual-based TUI with reactive components
- **Backend Integration**: Connects to existing bl4ckc3ll_p4nth30n.py functions
- **Threading**: Background scan execution with progress callbacks
- **State Management**: Reactive widgets with live data binding

### File Structure
```
tui/
├── __init__.py                 # TUI package initialization
├── app.py                      # Main TUI application class
├── backend_integration.py      # Backend connection layer
├── styles.css                  # Professional styling
├── screens/                    # Screen components
│   ├── main_dashboard.py       # Dashboard with system info
│   ├── targets.py              # Target management interface
│   ├── scan_runner.py          # Interactive scanning interface
│   ├── reports.py              # Report browsing and viewing
│   └── settings.py             # Configuration management
└── widgets/                    # Reusable UI components
    ├── system_monitor.py       # Real-time system monitoring
    ├── scan_progress.py        # Scan progress tracking
    └── log_viewer.py           # Live log display
```

### Dependencies
- `textual>=0.70.0`: Modern TUI framework
- `psutil>=5.9.0`: System monitoring (optional)
- All existing bl4ckc3ll_p4nth30n.py dependencies

### Requirements
- Python 3.8+
- Terminal with Unicode support
- 80x24 minimum terminal size (120x40 recommended)

## Professional Enhancements

### No Emojis Policy
The TUI interface uses professional text-based indicators instead of emojis:
- `[TARGET]` instead of 🎯
- `[RECON]` instead of 🔍  
- `[ALERT]` instead of 🚨
- `[SECURITY]` instead of 🛡️
- `[REPORT]` instead of 📊

### Real-time Features
- Live system resource monitoring
- Real-time scan progress with phase tracking
- Instant configuration validation
- Live log streaming during operations
- Automatic status updates

### Advanced Integration
- Seamless backend function calls
- Thread-safe scan execution
- Progress callback system
- Error handling and recovery
- Configuration persistence

## Troubleshooting

### Common Issues

1. **TUI fails to launch**
   - Install textual: `pip install textual`
   - Check Python version (3.8+ required)

2. **Missing system monitoring**
   - Install psutil: `pip install psutil`
   - System monitoring will fallback gracefully

3. **Backend integration errors**
   - Ensure bl4ckc3ll_p4nth30n.py is in parent directory
   - Check import paths and dependencies

4. **Display issues**
   - Ensure terminal supports Unicode
   - Increase terminal size (minimum 80x24)
   - Try different terminal emulator

### Performance Tips
- Use terminal with hardware acceleration
- Increase terminal buffer size for log viewing
- Close unused tabs for better performance
- Monitor system resources during large scans

## Contributing

The TUI is designed to be modular and extensible:
- Add new screens in `tui/screens/`
- Create reusable widgets in `tui/widgets/`  
- Extend backend integration for new features
- Follow existing code patterns and styling

## License

Same license as Bl4ckC3ll_PANTHEON main project.