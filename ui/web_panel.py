"""
Web scanning panel
"""
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QLineEdit, QCheckBox, QTextEdit, QProgressBar, QGroupBox,
    QFormLayout, QTableWidget, QTableWidgetItem, QHeaderView,
    QMessageBox, QTabWidget
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
import asyncio
import logging
from modules.web_scanner import WebScanner
from modules.vuln_database import VulnerabilityDatabase

logger = logging.getLogger(__name__)


class WebScannerWorker(QThread):
    """Worker thread for web scanning"""
    progress = pyqtSignal(str)
    finished = pyqtSignal(dict)
    error = pyqtSignal(str)
    
    def __init__(self, domain: str, options: dict):
        super().__init__()
        self.domain = domain
        self.options = options
    
    def run(self):
        try:
            scanner = WebScanner()
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            result = loop.run_until_complete(
                scanner.scan_domain(self.domain, self.options)
            )
            self.finished.emit(result)
        except Exception as e:
            self.error.emit(str(e))


class WebScannerPanel(QWidget):
    """Web scanner panel"""
    
    def __init__(self):
        super().__init__()
        self.scanner = WebScanner()
        self.results = {}
        self.init_ui()
    
    def init_ui(self):
        """Initialize UI"""
        main_layout = QVBoxLayout()
        
        # Input section
        input_group = QGroupBox("Target Configuration")
        input_layout = QFormLayout()
        
        self.domain_input = QLineEdit()
        self.domain_input.setPlaceholderText("e.g., example.com")
        input_layout.addRow(QLabel("Target Domain:"), self.domain_input)
        
        input_group.setLayout(input_layout)
        main_layout.addWidget(input_group)
        
        # Options section
        options_group = QGroupBox("Scan Options")
        options_layout = QVBoxLayout()
        
        self.enum_subdomains_check = QCheckBox("Enumerate Subdomains (crt.sh, DNSDumpster)")
        self.enum_subdomains_check.setChecked(True)
        self.enum_subdomains_check.stateChanged.connect(self.on_enum_toggle)
        options_layout.addWidget(self.enum_subdomains_check)
        
        self.bust_dirs_check = QCheckBox("Directory Busting")
        self.bust_dirs_check.setChecked(True)
        options_layout.addWidget(self.bust_dirs_check)
        
        self.bust_files_check = QCheckBox("File Busting")
        self.bust_files_check.setChecked(True)
        options_layout.addWidget(self.bust_files_check)
        
        self.identify_tech_check = QCheckBox("Identify Technologies")
        self.identify_tech_check.setChecked(True)
        options_layout.addWidget(self.identify_tech_check)
        
        self.search_vulns_check = QCheckBox("Search Vulnerabilities (may take time)")
        self.search_vulns_check.setChecked(False)
        options_layout.addWidget(self.search_vulns_check)
        
        options_group.setLayout(options_layout)
        main_layout.addWidget(options_group)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        self.scan_button = QPushButton("▶ Start Web Scan")
        self.scan_button.clicked.connect(self.start_scan)
        button_layout.addWidget(self.scan_button)
        
        self.stop_button = QPushButton("⏹ Stop")
        self.stop_button.setEnabled(False)
        button_layout.addWidget(self.stop_button)
        
        button_layout.addStretch()
        main_layout.addLayout(button_layout)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        main_layout.addWidget(self.progress_bar)
        
        # Results tabs
        self.results_tabs = QTabWidget()
        
        # Subdomains tab
        self.subdomains_table = QTableWidget()
        self.subdomains_table.setColumnCount(2)
        self.subdomains_table.setHorizontalHeaderLabels(["Subdomain", "Status"])
        self.subdomains_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.results_tabs.addTab(self.subdomains_table, "Subdomains")
        
        # Directories tab
        self.dirs_table = QTableWidget()
        self.dirs_table.setColumnCount(3)
        self.dirs_table.setHorizontalHeaderLabels(["Directory", "URL", "Status"])
        self.dirs_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.results_tabs.addTab(self.dirs_table, "Directories")
        
        # Files tab
        self.files_table = QTableWidget()
        self.files_table.setColumnCount(4)
        self.files_table.setHorizontalHeaderLabels(["File", "URL", "Status", "Size"])
        self.files_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.results_tabs.addTab(self.files_table, "Files")
        
        # Technologies tab
        self.tech_text = QTextEdit()
        self.tech_text.setReadOnly(True)
        self.results_tabs.addTab(self.tech_text, "Technologies")
        
        # Vulnerabilities tab
        self.vulns_table = QTableWidget()
        self.vulns_table.setColumnCount(3)
        self.vulns_table.setHorizontalHeaderLabels(["Exploit ID", "Title", "URL"])
        self.vulns_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.results_tabs.addTab(self.vulns_table, "Vulnerabilities")
        
        main_layout.addWidget(self.results_tabs)
        
        # Status text
        self.status_text = QTextEdit()
        self.status_text.setReadOnly(True)
        self.status_text.setMaximumHeight(100)
        main_layout.addWidget(self.status_text)
        
        self.setLayout(main_layout)
        self.worker = None
    
    def on_enum_toggle(self):
        """Handle subdomain enumeration toggle"""
        if self.enum_subdomains_check.isChecked():
            self.bust_dirs_check.setEnabled(True)
            self.bust_files_check.setEnabled(True)
        else:
            self.bust_dirs_check.setEnabled(True)
            self.bust_files_check.setEnabled(True)
    
    def start_scan(self):
        """Start web scan"""
        domain = self.domain_input.text().strip()
        
        if not domain:
            QMessageBox.warning(self, "Input Error", "Please enter a target domain")
            return
        
        options = {
            "enum_subdomains": self.enum_subdomains_check.isChecked(),
            "bust_directories": self.bust_dirs_check.isChecked(),
            "bust_files": self.bust_files_check.isChecked(),
            "identify_tech": self.identify_tech_check.isChecked(),
            "search_vulns": self.search_vulns_check.isChecked()
        }
        
        self.scan_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.progress_bar.setVisible(True)
        self.status_text.append(f"Starting scan for {domain}...")
        
        self.worker = WebScannerWorker(domain, options)
        self.worker.finished.connect(self.on_scan_finished)
        self.worker.error.connect(self.on_scan_error)
        self.worker.start()
    
    def on_scan_finished(self, results):
        """Handle scan completion"""
        self.results = results
        self.scan_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.progress_bar.setVisible(False)
        
        self.status_text.append("✓ Scan completed!")
        self.display_results(results)
    
    def on_scan_error(self, error):
        """Handle scan error"""
        self.scan_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.progress_bar.setVisible(False)
        self.status_text.append(f"✗ Error: {error}")
        QMessageBox.critical(self, "Scan Error", error)
    
    def display_results(self, results):
        """Display scan results"""
        # Clear tables
        self.subdomains_table.setRowCount(0)
        self.dirs_table.setRowCount(0)
        self.files_table.setRowCount(0)
        self.vulns_table.setRowCount(0)
        self.tech_text.clear()
        
        # Display subdomains
        for subdomain in results.get("subdomains", []):
            row = self.subdomains_table.rowCount()
            self.subdomains_table.insertRow(row)
            self.subdomains_table.setItem(row, 0, QTableWidgetItem(subdomain))
            self.subdomains_table.setItem(row, 1, QTableWidgetItem("Found"))
        
        # Display directories
        for dir_info in results.get("directories", []):
            row = self.dirs_table.rowCount()
            self.dirs_table.insertRow(row)
            self.dirs_table.setItem(row, 0, QTableWidgetItem(dir_info.get("path", "")))
            self.dirs_table.setItem(row, 1, QTableWidgetItem(dir_info.get("url", "")))
            self.dirs_table.setItem(row, 2, QTableWidgetItem(str(dir_info.get("status", ""))))
        
        # Display files
        for file_info in results.get("files", []):
            row = self.files_table.rowCount()
            self.files_table.insertRow(row)
            self.files_table.setItem(row, 0, QTableWidgetItem(file_info.get("file", "")))
            self.files_table.setItem(row, 1, QTableWidgetItem(file_info.get("url", "")))
            self.files_table.setItem(row, 2, QTableWidgetItem(str(file_info.get("status", ""))))
            self.files_table.setItem(row, 3, QTableWidgetItem(str(file_info.get("size", ""))))
        
        # Display technologies
        tech = results.get("technologies", {})
        tech_text = "Identified Technologies:\n\n"
        tech_text += f"Frameworks: {', '.join(tech.get('frameworks', []))}\n"
        tech_text += f"CMS: {', '.join(tech.get('cms', []))}\n"
        tech_text += f"Servers: {', '.join(tech.get('servers', []))}\n"
        self.tech_text.setText(tech_text)
        
        # Display vulnerabilities
        for vuln in results.get("vulnerabilities", []):
            row = self.vulns_table.rowCount()
            self.vulns_table.insertRow(row)
            self.vulns_table.setItem(row, 0, QTableWidgetItem(vuln.get("id", "")))
            self.vulns_table.setItem(row, 1, QTableWidgetItem(vuln.get("title", "")))
            self.vulns_table.setItem(row, 2, QTableWidgetItem(vuln.get("url", "")))
        
        self.status_text.append(f"Found {len(results.get('subdomains', []))} subdomains")
        self.status_text.append(f"Found {len(results.get('directories', []))} directories")
        self.status_text.append(f"Found {len(results.get('files', []))} files")
    
    def get_results(self):
        """Get current results"""
        return self.results