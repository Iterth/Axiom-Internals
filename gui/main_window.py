import sys
import os
import ctypes
import json
from PySide6.QtWidgets import (QApplication, QHBoxLayout, QMainWindow, QMessageBox, QTableWidget, 
                               QTableWidgetItem, QVBoxLayout, QWidget, QPushButton, QHeaderView,
                               QMenu, QLineEdit, QAbstractItemView, QStatusBar, QCheckBox, QTabWidget)
from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QColor, QFont

class AxiomInternalsGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Axiom Internals - Advanced Forensic & Analysis Suite")
        self.resize(1150, 750) 

        # 1. Load Engine (DLL) using ctypes
        dll_path = os.path.abspath(r"C:\GitHub\AxiomInternals\src\x64\Debug\AxiomInternals.dll")
        try:
            self.axiom_engine = ctypes.CDLL(dll_path)
            
            # API Setup: Process Module
            self.axiom_engine.GetProcessListJSON.restype = ctypes.c_char_p
            self.axiom_engine.KillProcessByPID.argtypes = [ctypes.c_ulong]
            self.axiom_engine.KillProcessByPID.restype = ctypes.c_bool
            
            # API Setup: Registry Module
            self.axiom_engine.GetAutoRunsJSON.restype = ctypes.c_char_p
            # Deaktif etme fonksiyonu (Delete yerine Rename mantığı)
            self.axiom_engine.DeleteAutoRunKey.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
            self.axiom_engine.DeleteAutoRunKey.restype = ctypes.c_bool
            
        except Exception as e:
            QMessageBox.critical(self, "Engine Error", f"Failed to load AxiomInternals.dll:\n{e}")
            exit()

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

        # --- 3. INITIALIZATION ---
        self.setStatusBar(QStatusBar(self))
        self.statusBar().showMessage("[*] Ready. Axiom Suite initialized.", 5000)
        
        self.apply_dark_theme()
        
        self.load_processes()
        self.load_autoruns()

    def setup_process_tab(self):
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
        self.table.setColumnCount(5) 
        self.table.setHorizontalHeaderLabels(["PID", "PPID", "Process Name", "Threads", "Executable Path"])
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers) 
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows) 
        self.table.verticalHeader().setVisible(False) 
        self.table.setAlternatingRowColors(True) 
        
        header = self.table.horizontalHeader()
        for i in range(4): header.setSectionResizeMode(i, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.Stretch) 
        layout.addWidget(self.table)

        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.show_process_menu)

    def setup_autorun_tab(self):
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

    # --- REGISTRY LOGIC ---
    def load_autoruns(self):
        json_bytes = self.axiom_engine.GetAutoRunsJSON()
        autorun_list = json.loads(json_bytes.decode('utf-8'))

        self.autorun_table.setRowCount(0)
        self.autorun_table.setRowCount(len(autorun_list))

        for row, item in enumerate(autorun_list):
            name_item = QTableWidgetItem(item['name'])
            path_item = QTableWidgetItem(item['command'])
            loc_item = QTableWidgetItem(item['location'])

            if not item['exists']:
                name_item.setForeground(QColor("#ffb86c")) # Orange
                path_item.setText(f"[MISSING] {item['command']}")
                path_item.setForeground(QColor("#ff5555")) # Red

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
        # "Disable/Deactivate"
        disable_action = menu.addAction(f"Deactivate (Rename) Entry: {val_name}")
        action = menu.exec(self.autorun_table.viewport().mapToGlobal(position))

        if action == disable_action:
            success = self.axiom_engine.DeleteAutoRunKey(val_name.encode('utf-8'), location.encode('utf-8'))
            if success:
                self.statusBar().showMessage(f"Successfully deactivated: {val_name}", 5000)
                self.load_autoruns()
            else:
                self.statusBar().showMessage(f"Failed to deactivate entry. Admin rights needed.", 5000)

    # --- PROCESS EXPLORER LOGIC ---
    def load_processes(self):
        json_bytes = self.axiom_engine.GetProcessListJSON()
        process_list = json.loads(json_bytes.decode('utf-8'))
        self.table.setRowCount(0)
        self.table.setRowCount(len(process_list))
        for row, proc in enumerate(process_list):
            self.table.setItem(row, 0, QTableWidgetItem(str(proc['pid'])))
            self.table.setItem(row, 1, QTableWidgetItem(str(proc['ppid'])))
            self.table.setItem(row, 2, QTableWidgetItem(proc['name']))
            self.table.setItem(row, 3, QTableWidgetItem(str(proc['threads'])))
            self.table.setItem(row, 4, QTableWidgetItem(proc['path']))
        self.statusBar().showMessage(f"[+] Enumerated {len(process_list)} active processes.", 5000)

    def filter_processes(self, text):
        search_text = text.lower()
        for row in range(self.table.rowCount()):
            pid = self.table.item(row, 0).text().lower()
            name = self.table.item(row, 2).text().lower()
            self.table.setRowHidden(row, not (search_text in pid or search_text in name))

    def show_process_menu(self, position):
        row = self.table.rowAt(position.y())
        if row < 0: return 
        pid = int(self.table.item(row, 0).text())
        name = self.table.item(row, 2).text()
        menu = QMenu()
        terminate_action = menu.addAction("Terminate Process") 
        action = menu.exec(self.table.viewport().mapToGlobal(position))
        if action == terminate_action: self.terminate_process(pid, name)

    def terminate_process(self, pid, name):
        if self.axiom_engine.KillProcessByPID(pid):
            self.statusBar().showMessage(f"Terminated '{name}' (PID: {pid}).", 5000)
            self.load_processes() 
        else:
            self.statusBar().showMessage(f"Failed to terminate '{name}'. Access denied.", 5000)

    def toggle_auto_refresh(self, state):
        if self.check_auto_refresh.isChecked(): self.refresh_timer.start(3000) 
        else: self.refresh_timer.stop()
        
    def silent_refresh(self):
        if self.search_bar.text() == "": self.load_processes()

    # --- THEME SETUP ---
    def apply_dark_theme(self):
        self.setStyleSheet("""
            QMainWindow { background-color: #0d1117; }
            QTabWidget::pane { border: 1px solid #30363d; background-color: #0d1117; }
            QTabBar::tab { background-color: #161b22; color: #8b949e; padding: 10px 20px; border-top-left-radius: 4px; border-top-right-radius: 4px; border: 1px solid transparent; }
            QTabBar::tab:selected { background-color: #0d1117; color: #c9d1d9; border: 1px solid #30363d; border-bottom: 1px solid #0d1117; }
            QLineEdit { background-color: #161b22; color: #c9d1d9; border: 1px solid #30363d; padding: 5px; border-radius: 4px; }
            QPushButton { background-color: #238636; color: #ffffff; font-weight: bold; border-radius: 4px; padding: 5px 15px; }
            QPushButton:hover { background-color: #2ea043; }
            QTableWidget { background-color: #0d1117; color: #c9d1d9; gridline-color: #30363d; border: 1px solid #30363d; selection-background-color: #264f78; }
            QTableWidget::item:alternate { background-color: #161b22; }
            QHeaderView::section { background-color: #161b22; color: #8b949e; font-weight: bold; border: 1px solid #30363d; padding: 4px; }
            QMenu { background-color: #161b22; color: #c9d1d9; border: 1px solid #30363d; }
            QMenu::item:selected { background-color: #264f78; color: white; }
            QStatusBar { color: #8b949e; font-weight: bold; }
            QCheckBox { color: #8b949e; font-weight: bold; }
        """)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = AxiomInternalsGUI()
    window.show()
    sys.exit(app.exec())