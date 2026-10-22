"""
OS enumeration panel
"""
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QLineEdit, QCheckBox, QTextEdit, QProgressBar, QGroupBox,
    QFormLayout, QTableWidget, QTableWidgetItem, QHeaderView,
    QMessageBox, QTabWidget, QSpinBox, QComboBox
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
import asyncio
import logging
from modules.os_enumerator import OSEnumerator

logger = logging.getLogger(__name__)


class OSEnumeratorWorker(QThread):
    """Worker thread for OS enumeration"""
    progress = pyqtSignal(str)
    finished = pyqtSignal(dict)
    error = pyqtSignal(str)
    
    def __init__(self, host: str, options: dict):
        super().__init__()
        self.host = host
        self.options = options
    
    def run(self):
        try:
            enumerator = OSEnumerator()
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            result = loop.run_until_complete(
                enumerator.enumerate_host(self.host, self.options)
            )
            self.finished.emit(result)
        except Exception as e:
            self.error.emit(str(e))


class OSEnumeratorPanel(QWidget):
    """OS enumeration panel"""
    
    def __init__(self):
        super().__init__()
        self.enumerator = OSEnumerator()
        self.results = {}
        self.init_ui()
    
    def init_ui(self):
        """Initialize UI"""
        main_layout = QVBoxLayout()
        
        # Input section
        input_group = QGroupBox("Target Configuration")
        input_layout = QFormLayout()
        
        self.host_input = QLineEdit()
        self.host_input.setPlaceholderText("e.g., 192.168.1.1 or example.com")
        input_layout.addRow(QLabel("Target Host/IP:"), self.host_input)
        
        input_group.setLayout(input_layout)
        main_layout.addWidget(input_group)
        
        # Options section
        options_group = QGroupBox("Enumeration Options")
        options_layout = QVBoxLayout()
        
        self.scan_ports_check = QCheckBox("Scan Common Ports")
        self.scan_ports_check.setChecked(True)
        options_layout.addWidget(self.scan_ports_check)
        
        self.full_scan_check = QCheckBox("Full Port Scan (1-65535) - Slow!")
        self.full_scan_check.setChecked(False)
        options_layout.addWidget(self.full_scan_check)
        
        self.identify_os_check = QCheckBox("Identify OS & Services")
        self.identify_os_check.setChecked(True)
        options_layout.addWidget(self.identify_os_check)
        
        self.search_vulns_check = QCheckBox("Search Service Vulnerabilities")
        self.search_vulns_check.setChecked(True)
        options_layout.addWidget(self.search_vulns_check)
        
        options_group.setLayout(options_layout)
        main_layout.addWidget(options_group)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        self.scan_button = QPushButton("▶ Start OS Enumeration")
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
        
        # Open Ports tab
        self.ports_table = QTableWidget()
        self.ports_table.setColumnCount(4)
        self.ports_table.setHorizontalHeaderLabels(["Port", "Service", "State", "Version"])
        self.ports_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.results_tabs.addTab(self.ports_table, "Open Ports")
        
        # Services tab
        self.services_table = QTableWidget()
        self.services_table.setColumnCount(2)
        self.services_table.setHorizontalHeaderLabels(["Service", "Known Vulnerabilities"])
        self.services_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.results_tabs.addTab(self.services_table, "Services & Vulns")
        
        # Recommendations tab
        self.recommendations_text = QTextEdit()
        self.recommendations_text.setReadOnly(True)
        self.results_tabs.addTab(self.recommendations_text, "Recommendations")
        
        main_layout.addWidget(self.results_tabs)
        
        # Status text
        self.status_text = QTextEdit()
        self.status_text.setReadOnly(True)
        self.status_text.setMaximumHeight(100)
        main_layout.addWidget(self.status_text)
        
        self.setLayout(main_layout)
        self.worker = None
    
    def start_scan(self):
        """Start OS enumeration"""
        host = self.host_input.text().strip()
        
        if not host:
            QMessageBox.warning(self, "Input Error", "Please enter a target host or IP")
            return
        
        options = {
            "scan_ports": self.scan_ports_check.isChecked(),
            "full_scan": self.full_scan_check.isChecked(),
            "identify_os": self.identify_os_check.isChecked(),
            "search_vulns": self.search_vulns_check.isChecked()
        }
        
        self.scan_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.status_text.append(f"Starting enumeration for {host}...")
        
        self.worker = OSEnumeratorWorker(host, options)
        self.worker.finished.connect(self.on_scan_finished)
        self.worker.error.connect(self.on_scan_error)
        self.worker.start()
    
    def on_scan_finished(self, results):
        """Handle enumeration completion"""
        self.results = results
        self.scan_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.progress_bar.setVisible(False)
        
        self.status_text.append("✓ Enumeration completed!")
        self.display_results(results)
    
    def on_scan_error(self, error):
        """Handle enumeration error"""
        self.scan_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.progress_bar.setVisible(False)
        self.status_text.append(f"✗ Error: {error}")
        QMessageBox.critical(self, "Enumeration Error", error)
    
    def display_results(self, results):
        """Display enumeration results"""
        # Clear tables
        self.ports_table.setRowCount(0)
        self.services_table.setRowCount(0)
        self.recommendations_text.clear()
        
        # Display open ports
        for port_info in results.get("open_ports", []):
            row = self.ports_table.rowCount()
            self.ports_table.insertRow(row)
            self.ports_table.setItem(row, 0, QTableWidgetItem(str(port_info.get("port", ""))))
            self.ports_table.setItem(row, 1, QTableWidgetItem(port_info.get("service", "")))
            self.ports_table.setItem(row, 2, QTableWidgetItem(port_info.get("state", "")))
            self.ports_table.setItem(row, 3, QTableWidgetItem(port_info.get("version", "")))
        
        # Display services and vulnerabilities
        services = results.get("services", {})
        for port, service_info in services.items():
            row = self.services_table.rowCount()
            self.services_table.insertRow(row)
            self.services_table.setItem(row, 0, QTableWidgetItem(service_info.get("name", "")))
            vulns = ", ".join(service_info.get("vulnerabilities", []))
            self.services_table.setItem(row, 1, QTableWidgetItem(vulns))
        
        # Display recommendations
        recommendations = results.get("recommendations", [])
        rec_text = "Security Recommendations:\n\n"
        for rec in recommendations:
            rec_text += f"• {rec}\n"
        
        if not recommendations:
            rec_text += "No specific recommendations at this time."
        
        self.recommendations_text.setText(rec_text)
        
        self.status_text.append(f"Found {len(results.get('open_ports', []))} open ports")
    
    def get_results(self):
        """Get current results"""
        return self.results