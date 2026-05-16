"""
Axiom Internals - Advanced Forensic & Analysis Suite
Version: 2.1.1
Description: A professional endpoint detection and response (EDR) tool 
designed for deep system analysis, threat hunting, and incident response.
"""

import sys
import os
import ctypes
import json
import requests
import webbrowser
import yara
from datetime import datetime

from PySide6.QtWidgets import (QApplication, QHBoxLayout, QMainWindow, QMessageBox, QTableWidget, 
                               QTableWidgetItem, QVBoxLayout, QWidget, QPushButton, QHeaderView,
                               QMenu, QLineEdit, QAbstractItemView, QStatusBar, QCheckBox, QTabWidget,
                               QInputDialog, QDialog, QProgressDialog, QTableView)
from PySide6.QtCore import Qt, QTimer, QThread, Signal, QAbstractTableModel
from PySide6.QtGui import QColor, QFont

# --- BACKGROUND THREADS ---
class MemoryScannerWorker(QThread):
    finished = Signal(str)

    def __init__(self, engine, pid):
        super().__init__()
        self.engine = engine
        self.pid = pid

    def run(self):
        raw_json = self.engine.GetProcessMemoryStringsJSON(self.pid)
        if raw_json:
            self.finished.emit(raw_json.decode('utf-8'))
        else:
            self.finished.emit("")

# --- CUSTOM TABLE MODEL FOR LARGE DATASETS (FREEZE PROBLEM FIX) ---
class MemoryStringModel(QAbstractTableModel):
    def __init__(self, data):
        super().__init__()
        self._data = data
        self._headers = ["Memory Address (Hex)", "Extracted Text"]

    def rowCount(self, /, parent = None):
        return len(self._data)
    
    def columnCount(self, parent=None):
        return 2

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None

        row = index.row()
        col = index.column()
        item = self._data[row]

        # 1. Display Text
        if role == Qt.DisplayRole:
            if col == 0: return item.get("address", "N/A")
            elif col == 1: return item.get("text", "")
        
        # 2. Color Coding for Memory Addresses
        elif role == Qt.ForegroundRole:
            if col == 0: return QColor("#50fa7b") 
            elif col == 1: return QColor("#f8f8f2")
        
        return None
    
    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if role == Qt.DisplayRole and orientation == Qt.Horizontal:
            return self._headers[section]
        return None

class AxiomInternalsGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Axiom Internals - Advanced Forensic & Analysis Suite")
        self.resize(1150, 750)
        self.vt_api_key, self.suspicious_keywords = self.load_config()

        # 1. Load Engine (DLL) using ctypes
        # Using a relative path for Release compatibility
        dll_name = "AxiomInternals.dll"
        dll_path = os.path.abspath(os.path.join(os.path.dirname(__file__), dll_name))
        
        # Fallback to current directory if not found in script dir (useful for PyInstaller)
        if not os.path.exists(dll_path):
            dll_path = os.path.abspath(dll_name)

        try:
            self.axiom_engine = ctypes.CDLL(dll_path)
            
            # API Setup: Process Module
            self.axiom_engine.GetProcessListJSON.restype = ctypes.c_char_p
            self.axiom_engine.KillProcessByPID.argtypes = [ctypes.c_ulong]
            self.axiom_engine.KillProcessByPID.restype = ctypes.c_bool
            
            # API Setup: Registry Module
            self.axiom_engine.GetAutoRunsJSON.restype = ctypes.c_char_p
            self.axiom_engine.DeleteAutoRunKey.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
            self.axiom_engine.DeleteAutoRunKey.restype = ctypes.c_bool
            
            # API Setup: Network & Hash Modules
            self.axiom_engine.GetNetworkConnectionsJSON.restype = ctypes.c_char_p
            self.axiom_engine.GetFileSHA256.restype = ctypes.c_char_p
            self.axiom_engine.GetFileSHA256.argtypes = [ctypes.c_char_p]
            
            # API Setup: Services Module
            self.axiom_engine.GetWindowsServicesJSON.restype = ctypes.c_char_p
            self.axiom_engine.ControlServiceByName.argtypes = [ctypes.c_char_p, ctypes.c_bool]
            self.axiom_engine.ControlServiceByName.restype = ctypes.c_bool

            #API Setup: Memory Scanning Module
            self.axiom_engine.GetProcessMemoryStringsJSON.restype = ctypes.c_char_p
            self.axiom_engine.GetProcessMemoryStringsJSON.argtypes = [ctypes.c_uint32]

            #API Setup: Threat Hunter / Injection Detector Module
            self.axiom_engine.GetInjectionAnomaliesJSON.argtypes = []
            self.axiom_engine.GetInjectionAnomaliesJSON.restype = ctypes.c_char_p
            
        except Exception as e:
            QMessageBox.critical(self, "Engine Error", f"Failed to load backend engine (AxiomInternals.dll):\n{e}")
            sys.exit()

        # Rules folder check
        self.create_default_rules()

        # --- 2. CORE TABBED ARCHITECTURE ---
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)

        # Tab 1: Process Explorer
        self.process_tab = QWidget()
        self.setup_process_tab()
        self.tabs.addTab(self.process_tab, "⚙️ Process Explorer")

        # Tab 2: Auto-Runs (Registry)
        self.autorun_tab = QWidget()
        self.setup_autorun_tab()
        self.tabs.addTab(self.autorun_tab, "🚀 Auto-Runs (Registry)")

        # Tab 3: Network Manager
        self.network_tab = QWidget()
        self.setup_network_tab()
        self.tabs.addTab(self.network_tab, "🌐 Network Manager")

        # Tab 4: Windows Services
        self.services_tab = QWidget()
        self.setup_services_tab()
        self.tabs.addTab(self.services_tab, "🔧 Windows Services")

        # Tab 5: Threat Hunter
        self.threat_tab = QWidget()
        self.setup_threat_hunter_tab()
        self.tabs.addTab(self.threat_tab, "🎯 Threat Hunter")

        # --- 3. INITIALIZATION ---
        self.setStatusBar(QStatusBar(self))
        self.statusBar().showMessage("[*] Ready. Axiom Suite initialized.", 5000)
        
        self.apply_dark_theme()
        
        self.load_processes()
        self.load_autoruns()
        self.load_network()
        self.load_services()

    # ==========================================
    # PROCESS EXPLORER MODULE
    # ==========================================
    def setup_process_tab(self):
        """Initializes the UI components for the Process Explorer tab."""
        layout = QVBoxLayout(self.process_tab)
        top_panel = QWidget()
        top_layout = QHBoxLayout(top_panel)
        top_layout.setContentsMargins(0, 0, 0, 0) 

        self.search_bar = QLineEdit()
        self.search_bar.setPlaceholderText("🔍 Search Process or PID...")
        self.search_bar.setMinimumHeight(35)
        self.search_bar.textChanged.connect(self.filter_processes) 
        top_layout.addWidget(self.search_bar)

        self.btn_refresh = QPushButton("Refresh List")
        self.btn_refresh.setMinimumHeight(35)
        self.btn_refresh.clicked.connect(self.load_processes) 
        top_layout.addWidget(self.btn_refresh)

        self.check_auto_refresh = QCheckBox("Auto-Refresh (3s)")
        self.check_auto_refresh.stateChanged.connect(self.toggle_auto_refresh) 
        top_layout.addWidget(self.check_auto_refresh)
        layout.addWidget(top_panel)

        self.refresh_timer = QTimer(self)
        self.refresh_timer.timeout.connect(self.silent_refresh)

        self.table = QTableWidget()
        self.table.setColumnCount(6) 
        self.table.setHorizontalHeaderLabels(["PID", "PPID", "Process Name", "Threads", "Executable Path", "Command Line"])
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers) 
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows) 
        self.table.verticalHeader().setVisible(False) 
        self.table.setAlternatingRowColors(True) 
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        
        header = self.table.horizontalHeader()

        header.setSectionResizeMode(0, QHeaderView.ResizeToContents) # PID
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents) # PPID
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents) # Threads

        header.setSectionResizeMode(2, QHeaderView.Interactive) # Name
        header.setSectionResizeMode(4, QHeaderView.Interactive) # Path
        self.table.setColumnWidth(4, 300)

        header.setSectionResizeMode(5, QHeaderView.Stretch)
        layout.addWidget(self.table)

        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.show_process_menu)


    def load_processes(self):
        """Fetches active processes from the C++ backend and populates the table."""
        
        # Adding Yara rules
        rules_list = os.listdir("rules")
        list_dict = {}
        for element in rules_list:
            list_dict[element] = "rules/" + element

        if not list_dict:
            return

        rules = yara.compile(filepaths=list_dict)
        json_bytes = self.axiom_engine.GetProcessListJSON()
        if not json_bytes: return
        
        try:
            process_list = json.loads(json_bytes.decode('utf-8'))
        except json.JSONDecodeError:
            self.statusBar().showMessage("[-] Error parsing process data from engine.", 5000)
            return

        self.table.setRowCount(0)
        self.table.setRowCount(len(process_list))
        
        for row, proc in enumerate(process_list):
            pid_item = QTableWidgetItem(str(proc.get('pid', '')))
            ppid_item = QTableWidgetItem(str(proc.get('ppid', '')))
            name_item = QTableWidgetItem(proc.get('name', ''))
            name_item.setToolTip(proc.get('name', ''))
            threads_item = QTableWidgetItem(str(proc.get('threads', '')))
            path_item = QTableWidgetItem(proc.get('path', ''))
            path_item.setToolTip(proc.get("path", ""))
            cmd_item = QTableWidgetItem(proc.get('command_line', ''))
            cmd_item.setToolTip(proc.get('command_line', ''))


            proc_name_lower = proc.get('name', '').lower()
            cmd_lower = proc.get('command_line', '').lower()


            is_suspicious = False
            
            for word in self.suspicious_keywords:
                if word in cmd_lower:
                    is_suspicious = True
                    break

            if is_suspicious:
                if not proc.get('path', ''):
                    QMessageBox.warning(self, "Suspicious Program", f"Automatic YARA scan failed. process {proc.get('name', '')} does not have valuable path.")
                    continue
                matches = rules.match(proc.get('path', ''))
                if matches:
                    QMessageBox.critical(self, "Suspicious Program", f"YARA Rule matched string: {matches} process: {proc.get('name', '')}")
            
            

            # Color Coding Logic
            if proc.get('pid') in [0, 4]: 
                row_color = QColor("#6e7681") 
                name_font = QFont("Consolas", 9, QFont.Normal)
            elif proc_name_lower in ["svchost.exe", "services.exe", "csrss.exe", "smss.exe", "wininit.exe", "lsass.exe", "winlogon.exe"]:
                row_color = QColor("#58a6ff") 
                name_font = QFont("Consolas", 9, QFont.Bold)
            elif is_suspicious:
                cmd_item.setForeground(QColor("#ff5555"))
                row_color = QColor("#f19326")
                name_font = QFont("Consolas", 9, QFont.Bold) 
                cmd_item.setToolTip("⚠️ SUSPICIOUS LOTL ACTIVITY DETECTED!")
            
            else:
                row_color = QColor("#c9d1d9") 
                name_font = QFont("Consolas", 9, QFont.Bold)

            # Path Availability Check
            if proc.get('path') in ["<Access Denied>", "<Path Not Available>"]:
                path_item.setForeground(QColor("#ff7b72"))
                path_font = QFont("Consolas", 9)
                path_font.setItalic(True) 
                path_item.setFont(path_font)
            else:
                path_item.setForeground(row_color)

            pid_item.setForeground(row_color)
            ppid_item.setForeground(row_color)
            name_item.setForeground(row_color)
            name_item.setFont(name_font)
            threads_item.setForeground(row_color)

            self.table.setItem(row, 0, pid_item)
            self.table.setItem(row, 1, ppid_item)
            self.table.setItem(row, 2, name_item)
            self.table.setItem(row, 3, threads_item)
            self.table.setItem(row, 4, path_item)
            self.table.setItem(row, 5, cmd_item)
            
        self.statusBar().showMessage(f"[+] Enumerated {len(process_list)} active processes.", 5000)

    def filter_processes(self, text):
        """Filters the process table based on search input."""
        search_text = text.lower()
        for row in range(self.table.rowCount()):
            pid = self.table.item(row, 0).text().lower()
            name = self.table.item(row, 2).text().lower()
            self.table.setRowHidden(row, not (search_text in pid or search_text in name))

    def show_process_menu(self, position):
        """Displays the context menu for process actions."""
        # Adding Yara rules
        rules_list = os.listdir("rules")
        list_dict = {}
        for element in rules_list:
            list_dict[element] = "rules/" + element

        if not list_dict:
            return

        
        row = self.table.rowAt(position.y())
        if row < 0: return
        
        pid = int(self.table.item(row, 0).text())
        name = self.table.item(row, 2).text()
        path = self.table.item(row, 4).text()

        menu = QMenu()
        terminate_action = menu.addAction(f"❌ Terminate Process: {name} (PID: {pid})")

        if pid in [0, 4]:
            terminate_action.setEnabled(False)
            terminate_action.setText(f"🛡️ SYSTEM PROTECTED: {name}")
            
        hash_action = menu.addAction(f"🔢 Calculate SHA256 Hash")
        vt_action = menu.addAction(f"🛡️ Analyze with VirusTotal")
        report_action = menu.addAction(f"📊 Generate Detailed Report")
        memory_scan_action = menu.addAction(f"🔍 Scan Process Memory for Strings")
        copy_action = menu.addAction(f"📋 Copy Value")
        yara_action = menu.addAction(f"🔍 Scan with YARA")

        action = menu.exec(self.table.viewport().mapToGlobal(position))

        if action == terminate_action:
            self.terminate_process(pid, name)
        elif action == hash_action:
            self.handle_hash_calculation(path, name)
        elif action == vt_action:
            self.handle_vt_analysis(path, name)
        elif action == report_action:
            if not path or path.startswith("<"):
                QMessageBox.warning(self, "Report Error", "Executable path not available for this process.")
                return
            self.generate_forensic_report(pid, name, path)
        elif action == memory_scan_action:
            pid_item = self.table.item(row, 0)
            if pid_item:
                pid = int(pid_item.text())
                self.scan_process_memory(pid)
        elif action == copy_action:
            item = self.table.itemAt(position)
            if item:
                QApplication.clipboard().setText(item.text())
        elif action == yara_action:
            rules = yara.compile(filepaths=list_dict)
            if not path:
                QMessageBox.warning(self, "YARA Scan", "There is not valuable path.")
                return
            matches = rules.match(path)
            if matches:
                QMessageBox.critical(self, "YARA Scan", f"YARA Rule matched string: {matches} process: {name}")
            else:
                QMessageBox.information(self, "YARA Scan", f"No matches found for {name}")
            

    def handle_hash_calculation(self, path, name):
        """Calculates and displays the SHA256 hash of a given file."""
        if not path or path.startswith("<"):
            QMessageBox.warning(self, "Hash Error", "Executable path not available for this process.")
            return
        
        self.statusBar().showMessage(f"Calculating SHA256 for '{path}'...", 2000)
        hash_bytes = self.axiom_engine.GetFileSHA256(path.encode('utf-8'))
        file_hash = hash_bytes.decode('utf-8')

        QApplication.clipboard().setText(file_hash)

        msg_box = QMessageBox(self)
        msg_box.setWindowTitle("File Hash Analysis")
        msg_box.setText(f"<b>Process:</b> {name}<br><b>Path:</b> {path}")
        msg_box.setInformativeText(f"<b>SHA256 Hash:</b><br>{file_hash}<br><br><span style= 'color:#50fa7b;'><i>[!] Hash copied to clipboard.</i></span>")
        msg_box.setTextInteractionFlags(Qt.TextSelectableByMouse)
        msg_box.setStyleSheet("background-color: #161b22; color: #c9d1d9;")
        msg_box.exec()

    def handle_vt_analysis(self, path, name):
        """Retrieves file hash and sends it to VirusTotal for analysis."""
        if not path or path.startswith("<"):
            QMessageBox.warning(self, "VirusTotal Error", "Executable path not available for this process.")
            return
            
        self.statusBar().showMessage(f"Generating hash for'{name}'...", 1000)
        hash_bytes = self.axiom_engine.GetFileSHA256(path.encode('utf-8'))
        file_hash = hash_bytes.decode('utf-8')

        self.analyze_with_virustotal(file_hash, name)

    def terminate_process(self, pid, name):
        """Sends a kill signal to the backend engine to terminate a process."""
        if self.axiom_engine.KillProcessByPID(pid):
            self.statusBar().showMessage(f"Terminated '{name}' (PID: {pid}).", 5000)
            self.load_processes() 
        else:
            self.statusBar().showMessage(f"Failed to terminate '{name}'. Access denied.", 5000)

    # ==========================================
    # MEMORY SCANNING MODULE
    # ==========================================
    def scan_process_memory(self, pid):
        """Initiates a background thread to scan process memory for strings."""
        self.progress = QProgressDialog(f"Scanning deep memory for PID {pid}...\nThis may take a few seconds.", None, 0, 0, self)
        self.progress.setWindowTitle("Memory Intelligence")
        self.progress.setWindowModality(Qt.WindowModal)
        self.progress.setStyleSheet("background-color: #161b22; color: #58a6ff; font-weight: bold; padding: 10px;")
        self.progress.setCancelButton(None)
        self.progress.show()

        # Allow the progress dialog to render before starting the scan
        QApplication.processEvents()

        # Start the memory scanning in a separate thread to keep the UI responsive
        self.worker = MemoryScannerWorker(self.axiom_engine, pid)
        self.worker.finished.connect(lambda data: self.on_memory_scan_finished(data, pid))
        self.worker.start()

    def on_memory_scan_finished(self, json_string, pid):
        """ Handles the results from the memory scanning thread and displays them using MVC. """
        self.progress.close()
        if not json_string:
            QMessageBox.warning(self, "Access Denied", f"Cannot read memory of PID {pid}. Process might be protected or system-level.")
            return
        try:
            strings_data = json.loads(json_string)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to parse memory scan results:\n{e}")
            return
        if not strings_data:
            QMessageBox.information(self, "No Strings Found", f"No readable strings found in the memory of PID {pid}.")
            return

        dialog = QDialog(self)
        total_found = len(strings_data)
        
        dialog.setWindowTitle(f"Memory Strings - PID: {pid} (Total Strings Extracted: {total_found})")
        dialog.resize(700, 500)
        
        layout = QVBoxLayout(dialog)

        mem_view = QTableView()
        self.mem_model = MemoryStringModel(strings_data)
        mem_view.setModel(self.mem_model)

        mem_view.verticalHeader().setVisible(False)
        mem_view.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        mem_view.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        mem_view.setAlternatingRowColors(True)
        mem_view.setSelectionBehavior(QAbstractItemView.SelectRows)
        mem_view.setStyleSheet(self.table.styleSheet())

        layout.addWidget(mem_view)

        # --- EXPORT TO TXT BUTTON ---
        export_btn = QPushButton("💾 Export to TXT")
        export_btn.setStyleSheet("""
            QPushButton {
                background-color: #238636;
                color: white;
                font-weight: bold;
                padding: 8px;
                border-radius: 4px;
            }
            QPushButton:hover { background-color: #2ea043; }
        """)

        # The function that button does
        def export_data():
            from PySide6.QtWidgets import QFileDialog
            file_path, _ = QFileDialog.getSaveFileName(dialog, "Save Memory Strings", f"PID_{pid}_Memory.txt", "Text Files (*.txt)")
            if file_path:
                try:
                    with open(file_path, "w", encoding="utf-8") as f:
                        f.write(f"--- Axiom Internals Memory Dump for PID {pid} ---\n")
                        f.write(f"Total Strings Extracted: {total_found}\n\n")
                        for item in strings_data:
                            f.write(f"[{item.get('address', 'N/A')}] {item.get('text', '')}\n")
                    QMessageBox.information(dialog, "Success", "Memory strings exported successfully!")
                except Exception as e:
                    QMessageBox.critical(dialog, "Error", f"Failed to save file: {e}")

        export_btn.clicked.connect(export_data)
        layout.addWidget(export_btn)

        dialog.exec()

    # ==========================================
    # AUTO-RUNS (REGISTRY) MODULE
    # ==========================================
    def setup_autorun_tab(self):
        """Initializes the UI components for the Auto-Runs tab."""
        layout = QVBoxLayout(self.autorun_tab)
        top_panel = QWidget()
        top_layout = QHBoxLayout(top_panel)
        top_layout.setContentsMargins(0, 0, 0, 0)

        self.autorun_search = QLineEdit()
        self.autorun_search.setPlaceholderText("🔍 Search in Registry paths or software names...")
        self.autorun_search.setMinimumHeight(35)
        self.autorun_search.textChanged.connect(self.filter_autoruns)
        top_layout.addWidget(self.autorun_search)

        self.btn_scan_registry = QPushButton("Scan Registry Keys")
        self.btn_scan_registry.setMinimumHeight(35)
        self.btn_scan_registry.clicked.connect(self.load_autoruns)
        top_layout.addWidget(self.btn_scan_registry)
        layout.addWidget(top_panel)

        self.autorun_table = QTableWidget()
        self.autorun_table.setColumnCount(3)
        self.autorun_table.setHorizontalHeaderLabels(["Software Name", "Command / Executable Path", "Registry Location"])
        self.autorun_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.autorun_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.autorun_table.setAlternatingRowColors(True)
        self.autorun_table.verticalHeader().setVisible(False)
        self.autorun_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.autorun_table.customContextMenuRequested.connect(self.show_autorun_menu)
        
        header = self.autorun_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        layout.addWidget(self.autorun_table)

    def load_autoruns(self):
        """Fetches persistent startup entries from the Windows Registry."""
        json_bytes = self.axiom_engine.GetAutoRunsJSON()
        if not json_bytes: return
        
        try:
            autorun_list = json.loads(json_bytes.decode('utf-8'))
        except json.JSONDecodeError:
            self.statusBar().showMessage("[-] Error parsing registry data.", 5000)
            return

        self.autorun_table.setRowCount(0)
        self.autorun_table.setRowCount(len(autorun_list))

        for row, item in enumerate(autorun_list):
            name_item = QTableWidgetItem(item.get('name', ''))
            path_item = QTableWidgetItem(item.get('command', ''))
            loc_item = QTableWidgetItem(item.get('location', ''))

            if not item.get('exists', True):
                name_item.setForeground(QColor("#ffb86c")) 
                path_item.setText(f"[MISSING] {item.get('command', '')}")
                path_item.setForeground(QColor("#ff5555")) 

            self.autorun_table.setItem(row, 0, name_item)
            self.autorun_table.setItem(row, 1, path_item)
            self.autorun_table.setItem(row, 2, loc_item)
        
        self.statusBar().showMessage(f"[*] Scan complete. Found {len(autorun_list)} startup entries.", 5000)

    def filter_autoruns(self, text):
        search_text = text.lower()
        for row in range(self.autorun_table.rowCount()):
            name = self.autorun_table.item(row, 0).text().lower()
            path = self.autorun_table.item(row, 1).text().lower()
            self.autorun_table.setRowHidden(row, not (search_text in name or search_text in path))

    def show_autorun_menu(self, position):
        row = self.autorun_table.rowAt(position.y())
        if row < 0: return
        
        val_name = self.autorun_table.item(row, 0).text()
        location = self.autorun_table.item(row, 2).text()

        menu = QMenu()
        disable_action = menu.addAction(f"Deactivate (Rename) Entry: {val_name}")
        action = menu.exec(self.autorun_table.viewport().mapToGlobal(position))

        if action == disable_action:
            success = self.axiom_engine.DeleteAutoRunKey(val_name.encode('utf-8'), location.encode('utf-8'))
            if success:
                self.statusBar().showMessage(f"Successfully deactivated: {val_name}", 5000)
                self.load_autoruns()
            else:
                self.statusBar().showMessage(f"Failed to deactivate entry. Admin rights needed.", 5000)

    # ==========================================
    # NETWORK MANAGER MODULE
    # ==========================================
    def setup_network_tab(self):
        """Initializes the UI components for the Network Manager tab."""
        layout = QVBoxLayout(self.network_tab)
        
        btn_refresh = QPushButton("Refresh Network Map")
        btn_refresh.setMinimumHeight(35)
        btn_refresh.clicked.connect(self.load_network)
        layout.addWidget(btn_refresh)

        self.net_table = QTableWidget()
        self.net_table.setColumnCount(5)
        self.net_table.setHorizontalHeaderLabels(["Local EndPoint", "Remote EndPoint", "State", "PID", "Process Name"])
        self.net_table.setAlternatingRowColors(True)
        self.net_table.verticalHeader().setVisible(False)
        self.net_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.net_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        
        header = self.net_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Stretch)
        header.setSectionResizeMode(1, QHeaderView.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)

        self.net_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.net_table.customContextMenuRequested.connect(self.show_network_menu)
        
        layout.addWidget(self.net_table)

    def load_network(self):
        """Fetches active TCP/UDP connections mapped to processes."""
        json_bytes = self.axiom_engine.GetNetworkConnectionsJSON()
        if not json_bytes: return
        
        try:
            net_list = json.loads(json_bytes.decode('utf-8'))
        except json.JSONDecodeError:
            self.statusBar().showMessage("[-] Error parsing network data.", 5000)
            return
        
        self.net_table.setRowCount(0)
        self.net_table.setRowCount(len(net_list))
        
        for row, conn in enumerate(net_list):
            self.net_table.setItem(row, 0, QTableWidgetItem(conn.get('local', '')))
            self.net_table.setItem(row, 1, QTableWidgetItem(conn.get('remote', '')))
            
            state_val = conn.get('state', 'UNKNOWN')
            state_item = QTableWidgetItem(state_val)
            
            if state_val == "ESTABLISHED":
                state_item.setForeground(QColor("#50fa7b")) 
            elif state_val == "LISTENING":
                state_item.setForeground(QColor("#8be9fd")) 
            elif "WAIT" in state_val:
                state_item.setForeground(QColor("#ffb86c"))   
            
            self.net_table.setItem(row, 2, state_item)
            self.net_table.setItem(row, 3, QTableWidgetItem(str(conn.get('pid', ''))))

            name_item = QTableWidgetItem(conn.get('name', ''))
            name_item.setFont(QFont("Consolas", 9, QFont.Bold))
            self.net_table.setItem(row, 4, name_item)

    def show_network_menu(self, position):
        """Displays context menu for network tracking actions."""
        row = self.net_table.rowAt(position.y())
        if row < 0: return

        remote_full = self.net_table.item(row, 1).text()
        process_name = self.net_table.item(row, 4).text()
        remote_ip = remote_full.split(':')[0]

        if remote_ip in ["0.0.0.0", "127.0.0.1", "::1"] or remote_ip.startswith("192.168.") or remote_ip.startswith("10."):
            return
        
        menu = QMenu()
        trace_action = menu.addAction(f"🌍 Trace Remote IP: {remote_ip}")

        action = menu.exec(self.net_table.viewport().mapToGlobal(position))

        if action == trace_action:
            self.trace_ip_location(remote_ip, process_name)

    # ==========================================
    # WINDOWS SERVICES MODULE
    # ==========================================
    def setup_services_tab(self):
        """Initializes the UI components for the Windows Services tab."""
        layout = QVBoxLayout()
        
        top_layout = QHBoxLayout()
        self.srv_search_input = QLineEdit()
        self.srv_search_input.setPlaceholderText("🔍 Search services or drivers (e.g., 'Update', 'Kernel')...")
        self.srv_search_input.textChanged.connect(self.filter_services)
        
        self.srv_refresh_btn = QPushButton("🔄 Refresh Services")
        self.srv_refresh_btn.clicked.connect(self.load_services)
        
        top_layout.addWidget(self.srv_search_input)
        top_layout.addWidget(self.srv_refresh_btn)
        
        self.srv_table = QTableWidget(0, 5)
        self.srv_table.setHorizontalHeaderLabels(["Name", "Display Name", "PID", "State", "Type"])
        self.srv_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.srv_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.srv_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.srv_table.verticalHeader().setVisible(False)
        self.srv_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.srv_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.srv_table.setAlternatingRowColors(True)
        
        self.srv_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.srv_table.customContextMenuRequested.connect(self.show_service_menu)
        
        layout.addLayout(top_layout)
        layout.addWidget(self.srv_table)
        self.services_tab.setLayout(layout)

    def load_services(self):
        """Fetches Windows services and kernel drivers from the Service Control Manager."""
        self.statusBar().showMessage("[*] Querying Service Control Manager...", 1000)
        
        json_bytes = self.axiom_engine.GetWindowsServicesJSON()
        if not json_bytes: return
        
        try:
            services_list = json.loads(json_bytes.decode('utf-8'))
        except json.JSONDecodeError:
            self.statusBar().showMessage("[-] Error parsing services data.", 5000)
            return

        self.srv_table.setRowCount(0)
        self.srv_table.setRowCount(len(services_list))
        
        for row, svc in enumerate(services_list):
            name_item = QTableWidgetItem(svc.get('name', ''))
            display_item = QTableWidgetItem(svc.get('display_name', ''))
            pid_item = QTableWidgetItem(str(svc.get('pid', 0)))
            
            state_val = svc.get('state', '')
            svc_type = svc.get('type', '')
            
            state_item = QTableWidgetItem(state_val)
            type_item = QTableWidgetItem(svc_type)
            
            text_color = QColor("#c9d1d9") 
            font = QFont("Consolas", 9)
            
            if svc_type == "KERNEL DRIVER":
                text_color = QColor("#ffb86c") 
                font.setBold(True)
                
            if state_val == "STOPPED":
                text_color = QColor("#6e7681") 
                font.setBold(False)
            
            for item in [name_item, display_item, pid_item, state_item, type_item]:
                item.setForeground(text_color)
                item.setFont(font)
                
            if state_val == "RUNNING" and svc_type != "KERNEL DRIVER":
                state_item.setForeground(QColor("#50fa7b")) 
                state_item.setFont(QFont("Consolas", 9, QFont.Bold))

            self.srv_table.setItem(row, 0, name_item)
            self.srv_table.setItem(row, 1, display_item)
            self.srv_table.setItem(row, 2, pid_item)
            self.srv_table.setItem(row, 3, state_item)
            self.srv_table.setItem(row, 4, type_item)
            
        self.statusBar().showMessage(f"[+] Loaded {len(services_list)} services and drivers.", 5000)

    def show_service_menu(self, position):
        """Displays context menu for starting/stopping services safely."""
        row = self.srv_table.rowAt(position.y())
        if row < 0: return
        
        service_name = self.srv_table.item(row, 0).text()
        state = self.srv_table.item(row, 3).text()
        
        menu = QMenu()
        start_action = menu.addAction(f"▶️ Start Service ({service_name})")
        stop_action = menu.addAction(f"🛑 Stop Service ({service_name})")
        
        if state == "RUNNING": start_action.setEnabled(False)
        if state == "STOPPED": stop_action.setEnabled(False)
        
        action = menu.exec(self.srv_table.viewport().mapToGlobal(position))
        
        if action == stop_action:
            reply = QMessageBox.warning(self, "Dangerous Action", 
                f"Stopping the service '{service_name}' might cause system instability.\n\nAre you sure you want to proceed?",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            
            if reply == QMessageBox.Yes:
                self.statusBar().showMessage(f"[*] Attempting to stop {service_name}...", 3000)
                if self.axiom_engine.ControlServiceByName(service_name.encode('utf-8'), True):
                    QMessageBox.information(self, "Success", f"Service '{service_name}' stopped.")
                    self.load_services()
                else:
                    QMessageBox.critical(self, "Error", "Failed to stop service. Admin rights may be required.")
        
        elif action == start_action:
            self.statusBar().showMessage(f"[*] Attempting to start {service_name}...", 3000)
            if self.axiom_engine.ControlServiceByName(service_name.encode('utf-8'), False):
                QMessageBox.information(self, "Success", f"Service '{service_name}' started.")
                self.load_services()
            else:
                QMessageBox.critical(self, "Error", "Failed to start service. Admin rights may be required.")

    def filter_services(self, text):
        """Filters the service table based on search input."""
        for row in range(self.srv_table.rowCount()):
            match = False
            for col in range(self.srv_table.columnCount()):
                item = self.srv_table.item(row, col)
                if item and text.lower() in item.text().lower():
                    match = True
                    break
            self.srv_table.setRowHidden(row, not match)

    # ==========================================
    # THREAT HUNDER MODULE
    # ==========================================
    def setup_threat_hunter_tab(self):
        layout = QVBoxLayout(self.threat_tab)

        # Scan Button
        self.scan_threats_btn = QPushButton("🚀 LAUNCH DEEP SYSTEM SCAN (Memory Anomaly Detection)")
        self.scan_threats_btn.setStyleSheet("""
            QPushButton {
                background-color: #b32d2e;
                color: white;
                font-size: 14px;
                font-weight: bold;
                padding: 12px;
                border-radius: 4px;
                border: 1px solid #ff5555;
            }
            QPushButton:hover { background-color: #ff5555; }
        """)
        self.scan_threats_btn.clicked.connect(self.run_threat_scan)
        layout.addWidget(self.scan_threats_btn)

        # The Table that Anomalies listed. 
        self.threat_table = QTableWidget()
        self.threat_table.setColumnCount(5)
        self.threat_table.setHorizontalHeaderLabels(["PID", "Process Name", "Injected Address", "Protection", "Risk Level"])

        # Table Settings
        self.threat_table.verticalHeader().setVisible(False)
        self.threat_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.threat_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)

        self.threat_table.setAlternatingRowColors(True)
        self.threat_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.threat_table.setStyleSheet(self.table.styleSheet()) # Senin o jilet gibi karanlık temanı uygula
        
        layout.addWidget(self.threat_table)

    def run_threat_scan(self):
        self.scan_threats_btn.setText("⏳ SCANNING ALL PROCESSES... PLEASE WAIT")
        self.scan_threats_btn.setEnabled(False)
        QApplication.processEvents() # Arayüzün butonu güncellemesine izin ver

        raw_json = self.axiom_engine.GetInjectionAnomaliesJSON()   
        
        self.scan_threats_btn.setText("🚀 LAUNCH DEEP SYSTEM SCAN (Memory Anomaly Detection)")
        self.scan_threats_btn.setEnabled(True)

        if not raw_json:
            QMessageBox.information(self, "Scan Complete", "System scan completed. No memory injections detected. System is clean.")
            self.threat_table.setRowCount(0)
            return

        try:
            threats_data = json.loads(raw_json.decode('utf-8'))
        except Exception as e:
            QMessageBox.critical(self, "Parse Error", f"Failed to parse threat data: {e}")
            return

        if not threats_data:
            QMessageBox.information(self, "Scan Complete", "No malicious memory regions found! 🛡️")
            self.threat_table.setRowCount(0)
            return

        self.threat_table.setRowCount(len(threats_data))
        self.threat_table.setUpdatesEnabled(False) # Performance

        for row, item in enumerate(threats_data):
            pid_cell = QTableWidgetItem(str(item.get("pid", "")))
            name_cell = QTableWidgetItem(item.get("name", "Unknown"))
            addr_cell = QTableWidgetItem(item.get("address", "N/A"))
            prot_cell = QTableWidgetItem(item.get("protection", ""))
            risk_cell = QTableWidgetItem(item.get("risk_level", ""))

            # Colors for Risk Level
            if "CRITICAL" in item.get("risk_level", ""):
                risk_color = QColor("#ff5555") # Definetly Malware 
            else:
                risk_color = QColor("#f1fa8c") # Probably JIT or Shellcode

            # Colors
            for cell in (pid_cell, name_cell, addr_cell, prot_cell, risk_cell):
                cell.setForeground(risk_color)
                # Font
                font = QFont()
                font.setBold(True)
                cell.setFont(font)

            self.threat_table.setItem(row, 0, pid_cell)
            self.threat_table.setItem(row, 1, name_cell)
            self.threat_table.setItem(row, 2, addr_cell)
            self.threat_table.setItem(row, 3, prot_cell)
            self.threat_table.setItem(row, 4, risk_cell)

        self.threat_table.setUpdatesEnabled(True) # Çizimi başlat
        
        QMessageBox.warning(self, "Threats Detected!", f"⚠️ CRITICAL ALERT!\n\nDetected {len(threats_data)} suspicious memory injections. Check the Threat Hunter dashboard immediately.")

    # ==========================================
    # CYBER INTELLIGENCE & FORENSICS (APIs)
    # ==========================================
    def trace_ip_location(self, ip_address, process_name):
        """Queries an external API to perform geographical OSINT on an IP address."""
        self.statusBar().showMessage(f"[*] Tracing IP '{ip_address}' for process '{process_name}'...", 3000)
        url = f"http://ip-api.com/json/{ip_address}?fields=status,country,city,isp,org,as,query"

        try:
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data.get("status") == "success":
                    country = data.get("country", "N/A")
                    city = data.get("city", "N/A")
                    isp = data.get("isp", "N/A")
                    org = data.get("org", "N/A")

                    msg_box = QMessageBox(self)
                    msg_box.setWindowTitle("IP Geo-Location Intelligence")
                    msg_box.setIcon(QMessageBox.Information)

                    report = (f"<span style='color:#8be9fd; font-size:14px;'><b>Process:</b> {process_name}</span><br><br>"
                              f"<b>Target IP:</b> {ip_address}<br>"
                              f"<b>Country:</b> {country}<br>"
                              f"<b>City:</b> {city}<br>"
                              f"<b>ISP:</b> {isp}<br>"
                              f"<b>Organization:</b> {org}")
                    
                    msg_box.setText(report)
                    msg_box.setTextInteractionFlags(Qt.TextSelectableByMouse)
                    msg_box.setStyleSheet("background-color: #161b22; color: #c9d1d9;")
                    msg_box.exec()
                else:
                    QMessageBox.warning(self, "Trace Failed", f"Could not locate IP: {ip_address}")
        except Exception as e:
            QMessageBox.critical(self, "API Error", f"Failed to connect to IP geolocation service:\n{e}")

    def analyze_with_virustotal(self, file_hash, process_name):
        """Sends a SHA256 hash to the VirusTotal v3 API for threat detection."""
        if not self.vt_api_key or self.vt_api_key == "":
            key, ok = QInputDialog.getText(self, "VirusTotal API Key Required", "Enter your VirusTotal API Key:\n(It will be saved locally to config.json)")
            if ok and key.strip():
                self.vt_api_key = key.strip()
                with open("config.json", "r") as f:
                    config_data = json.load(f)
                    if "vt_api_key" in config_data:
                        config_data["vt_api_key"] = key.strip()
                with open("config.json", "w") as f:
                    json.dump(config_data, f, indent=4)
                self.statusBar().showMessage("[+] API key saved. You can now analyze files.", 5000)
            else:
                return
        
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {"x-apikey": self.vt_api_key}

        self.statusBar().showMessage(f"[*] Querying VirusTotal for '{process_name}'...", 5000)

        try:
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                stats = data['data']['attributes']['last_analysis_stats']

                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                total = malicious + suspicious + stats.get('undetected', 0) + stats.get('harmless', 0)

                msg_box = QMessageBox(self)
                msg_box.setWindowTitle(f"VirusTotal Analysis - {process_name}")

                if malicious > 0:
                    msg_box.setIcon(QMessageBox.Critical)
                    status_text = "<span style='color:#ff5555; font-size:16px;'><b>[!] MALICIOUS FILE DETECTED</b></span>"
                else:
                    msg_box.setIcon(QMessageBox.Information)
                    status_text = "<span style='color:#50fa7b; font-size:16px;'><b>[+] NO MALICIOUS SIGNATURES FOUND</b></span>"
                
                report = (f"{status_text}<br><br>"
                          f"<b>Detections:</b> {malicious} / {total} <br>"
                          f"<b>Suspicious:</b> {suspicious} <br>"
                          f"<b>SHA256 Hash:</b><br>{file_hash}<br><br>")
                msg_box.setText(report)
                msg_box.setStyleSheet("background-color: #161b22; color: #c9d1d9;")
                msg_box.exec()
            elif response.status_code == 404:
                QMessageBox.information(self, "Not Found", f"<b>{process_name}</b> is unknown to VirusTotal.<br><br>Hash: {file_hash}<br><br><i>This could be a custom or completely new file.</i>")
            else:
                QMessageBox.warning(self, "API Error", f"VirusTotal returned error: {response.status_code}\n{response.text}")

        except Exception as e:
            QMessageBox.critical(self, "Connection Error", f"Failed to connect to VirusTotal API:\n{e}")

    def generate_forensic_report(self, pid, name, path):
        """Generates a professional HTML incident response report for a given process."""
        self.statusBar().showMessage(f"Generating forensic report for '{name}'...", 2000)

        hash_bytes = self.axiom_engine.GetFileSHA256(path.encode('utf-8'))
        file_hash = hash_bytes.decode('utf-8')

        net_conns = []
        for row in range(self.net_table.rowCount()):
            if self.net_table.item(row, 3).text() == str(pid):
                local = self.net_table.item(row, 0).text()
                remote = self.net_table.item(row, 1).text()
                state = self.net_table.item(row, 2).text()

                color = "#50fa7b" if state == "ESTABLISHED" else "#ffb86c" if state in ["LISTENING"] else "#8be9fd"
                net_conns.append(f"<li>{local} <b>-></b> {remote} <span style='color:{color};'>[{state}]</span></li>")

        net_html = "<ul>" + "".join(net_conns) + "</ul>" if net_conns else "<p style='color:#8b949e;'><i>No active network connections found.</i></p>"

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        html_content = f"""
        <html>
        <head>
            <title>Axiom Forensic Report - {name}</title>
            <style>
                body {{ background-color: #0d1117; color: #c9d1d9; font-family: 'Consolas', monospace; padding: 40px; line-height: 1.6; }}
                h1 {{ color: #58a6ff; border-bottom: 1px solid #30363d; padding-bottom: 10px; font-family: Arial, sans-serif; }}
                h2 {{ color: #ff7b72; font-family: Arial, sans-serif; margin-bottom: 5px; }}
                .box {{ background-color: #161b22; border: 1px solid #30363d; padding: 20px; border-radius: 8px; margin-top: 20px; box-shadow: 0 4px 8px rgba(0,0,0,0.5); }}
                .highlight {{ color: #f0883e; font-weight: bold; font-size: 1.1em; }}
                .hash {{ background-color: #0d1117; padding: 5px; border-radius: 4px; border: 1px dashed #30363d; display: inline-block; word-break: break-all; }}
            </style>
        </head>
        <body>
            <h1>🛡️ Axiom Internals - Incident Response Report</h1>
            <p><b>Generated on:</b> {timestamp}</p>
            <p><b>System Analyst:</b> Axiom Automated Engine</p>

            <div class="box">
                <h2>Target Executable Details</h2>
                <p><b>Process Name:</b> <span class="highlight">{name}</span></p>
                <p><b>Process ID (PID):</b> {pid}</p>
                <p><b>Image Path:</b> {path}</p>
                <p><b>SHA256 Fingerprint:</b><br><span class="hash">{file_hash}</span></p>
            </div>

            <div class="box">
                <h2>Live Network Activity</h2>
                {net_html}
            </div>

            <div class="box" style="border-color: #ffb86c;">
                <h2 style="color: #ffb86c;">Analyst Notes</h2>
                <p><i>This automated report captures a snapshot of the process state. If suspicious foreign IP connections are present, cross-reference the SHA256 hash with VirusTotal immediately.</i></p>
            </div>
        </body>
        </html>
        """
        report_filename = f"Axiom_Report_{name}_{pid}.html"
        try:
            with open(report_filename, "w", encoding="utf-8") as f:
                f.write(html_content)
            webbrowser.open(os.path.abspath(report_filename))
            self.statusBar().showMessage(f"Report generated: {report_filename}", 5000)
        except Exception as e:
            QMessageBox.critical(self, "Report Error", f"Failed to generate HTML report:\n{e}")

    # ==========================================
    # UTILITY & THEME FUNCTIONS
    # ==========================================
    def load_config(self):
        """Loads API keys and settings from config.json."""
        if not os.path.exists("config.json"):
            self.create_config()
            
        if os.path.exists("config.json"):
            try:
                with open("config.json", "r") as f:
                    config = json.load(f)
                    return config.get("vt_api_key", ""), config.get("suspicious_keywords", [])
            except Exception:
                return "", []
        return "", []
    
    def create_config(self):
        try:
            with open("config.json", "w") as f:
                default_config = {
    "vt_api_key": "",
    "suspicious_keywords": ["-hidden", "-bypass", "-enc", "encodedcommand", "downloadstring", "invoke-webrequest", "bypass", "amsi"]
}
                json.dump(default_config, f, indent=4)
                QMessageBox.information(self, "Info", f"Config file created succesfully (You can change suspicious keywords)")
        except:
            return
        
    def create_default_rules(self):
        default_rule = """rule mimikatzdetect{
    strings:
        $s1 = {33 DB 8B C3 48 83 C4 20 5B C3}
        $s2 = {83 64 24 30 00 44 8B 4C 24 48 48 8B 0D}
        $s3 = {83 64 24 30 00 44 8B 4D D8 48 8B 0D}
        $s4 = {84 C0 74 44 6A 08 68}
        $s5 = {8B F0 3B F3 7C 2C 6A 02 6A 10 68}
        $s6 = {8B F0 85 F6 78 2A 6A 02 6A 10 68}
    condition:
    any of them
}
"""
        dir_path = "rules/"
        if not os.path.exists(dir_path):
            os.makedirs(dir_path)
            with open("rules/mimikatz.yar", "w") as f:
                f.write(default_rule)
            QMessageBox.information(self, "Info", "Rules dictionary and mimikatz.yar(default) has been created successfuly. You can add your YARA rules into this folder.")
        else:
            if not os.listdir(dir_path):
                QMessageBox.warning(self, "Warning", "rules folder is empty, please add rules to it.")
                
    def toggle_auto_refresh(self, state):
        if self.check_auto_refresh.isChecked(): 
            self.refresh_timer.start(3000) 
        else: 
            self.refresh_timer.stop()
        
    def silent_refresh(self):
        if self.search_bar.text() == "": 
            self.load_processes()

    def apply_dark_theme(self):
        """Applies a professional, dark SOC-style theme using Qt Style Sheets."""
        self.table.verticalHeader().setDefaultSectionSize(32)
        self.autorun_table.verticalHeader().setDefaultSectionSize(32)
        self.net_table.verticalHeader().setDefaultSectionSize(32)

        self.setStyleSheet("""
            QMainWindow { background-color: #0d1117; }
            QTabWidget::pane { border: 1px solid #30363d; background-color: #0d1117; border-radius: 4px; }
            QTabBar::tab { background-color: #161b22; color: #8b949e; padding: 10px 25px; border-top-left-radius: 6px; border-top-right-radius: 6px; border: 1px solid transparent; font-weight: bold; margin-right: 2px; }
            QTabBar::tab:selected { background-color: #0d1117; color: #58a6ff; border: 1px solid #30363d; border-bottom: 2px solid #58a6ff; }
            QTabBar::tab:hover:!selected { background-color: #1f2428; color: #c9d1d9; }
            
            QLineEdit { background-color: #0d1117; color: #c9d1d9; border: 1px solid #30363d; padding: 8px; border-radius: 6px; font-size: 13px; }
            QLineEdit:focus { border: 1px solid #58a6ff; background-color: #161b22; }
            
            QPushButton { background-color: #21262d; color: #c9d1d9; border: 1px solid #363b42; font-weight: bold; border-radius: 6px; padding: 6px 16px; }
            QPushButton:hover { background-color: #30363d; border: 1px solid #8b949e; }
            QPushButton:pressed { background-color: #282e33; }
            
            QTableWidget, QTableView { background-color: #0d1117; color: #c9d1d9; gridline-color: #21262d; border: 1px solid #30363d; border-radius: 4px; outline: none; alternate-background-color: #161b22; }
            QTableWidget::item, QTableView::item { padding: 4px 8px; border-bottom: 1px solid #161b22; }
            QTableWidget::item:selected, QTableView::item:selected { background-color: #1f3a5f; color: #ffffff; }
            
            QHeaderView::section { background-color: #161b22; color: #8b949e; font-weight: bold; border: none; border-bottom: 1px solid #30363d; border-right: 1px solid #21262d; padding: 8px; font-size: 12px; }
            
            QMenu { background-color: #161b22; color: #c9d1d9; border: 1px solid #30363d; border-radius: 6px; padding: 4px; }
            QMenu::item { padding: 6px 24px 6px 24px; border-radius: 4px; margin: 2px; }
            QMenu::item:selected { background-color: #1f3a5f; color: white; }
            
            QStatusBar { color: #8b949e; font-weight: bold; padding-left: 10px; }
            QCheckBox { color: #8b949e; font-weight: bold; }
            QCheckBox::indicator { width: 16px; height: 16px; border-radius: 4px; border: 1px solid #30363d; background-color: #161b22; }
            QCheckBox::indicator:checked { background-color: #58a6ff; border: 1px solid #58a6ff; }
        """)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = AxiomInternalsGUI()
    window.show()
    sys.exit(app.exec())