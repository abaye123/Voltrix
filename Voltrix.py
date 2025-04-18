import sys
import os
import subprocess
import json
import uuid
import re
import tempfile
import time
import atexit
import shutil
from datetime import datetime
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
    QLabel, QLineEdit, QPushButton, QFileDialog, QMessageBox, 
    QGroupBox, QStatusBar, QDialog, QComboBox, QTabWidget,
    QRadioButton, QButtonGroup, QCheckBox, QTextEdit, QListWidget, QListWidgetItem, QInputDialog
)
from PySide6.QtCore import Qt, Signal, Slot, QSize, QProcess, QThreadPool, QRunnable, QObject, QFileInfo
from PySide6.QtGui import QIcon, QFont


if os.name == 'nt':
    APP_DATA_DIR = os.path.join(os.environ.get('APPDATA', ''), 'Voltrix')
elif os.name == 'posix':
    APP_DATA_DIR = os.path.join(os.path.expanduser('~'), '.config', 'Voltrix')
else:
    APP_DATA_DIR = os.path.join(os.path.expanduser('~'), '.Voltrix')


if not os.path.exists(APP_DATA_DIR):
    os.makedirs(APP_DATA_DIR)


CONFIG_FILE = os.path.join(APP_DATA_DIR, "config.json")

now = datetime.now()
log_filename = f"log_{now.strftime('%m-%Y')}.txt"
LOG_FILE = os.path.join(APP_DATA_DIR, log_filename)


def write_log(message):
    config = load_config()
    enable_logging = config.get("enable_logging", True)
    
    if enable_logging:
        with open(LOG_FILE, "a", encoding="utf-8") as log:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            log.write(f"[{timestamp}] {message}\n")
        print(message)


def load_config():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            return {}
    return {}


def save_config(config):
    os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
    
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(config, f, ensure_ascii=False, indent=4)


class AboutDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("אודות")
        self.setFixedSize(350, 300)
        self.setup_ui()
    
    def setup_ui(self):
        layout = QVBoxLayout()
        self.setLayout(layout)
        
        title_label = QLabel("Voltrix - הצפנת נתונים")
        title_font = QFont()
        title_font.setPointSize(16)
        title_font.setBold(True)
        title_label.setFont(title_font)
        title_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(title_label)
        
        version_label = QLabel("v2.0.0")
        version_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(version_label)
        
        desc_label = QLabel("תוכנה להצפנה ופענוח של קבצים באמצעות מפתח המבוסס על מספר סידורי של התקן USB")
        desc_label.setWordWrap(True)
        desc_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(desc_label)
        
        layout.addSpacing(20)
        
        dev_group = QGroupBox()
        dev_layout = QVBoxLayout()
        dev_group.setLayout(dev_layout)
        
        about_label = QLabel(
            "וולטריקס (Voltrix) היא תוכנה להצפנה ופענוח של קבצים<br>"
            "המשתמשת בספריית Fernet לצורך הצפנה סימטרית<br><br>"
            "© abaye 2025"
        )
        about_label.setOpenExternalLinks(True)
        about_label.setWordWrap(True)
        about_label.setAlignment(Qt.AlignCenter)
        dev_layout.addWidget(about_label)
        
        layout.addWidget(dev_group)
        
        layout.addStretch()
        
        close_btn = QPushButton("סגור")
        close_btn.clicked.connect(self.accept)
        close_btn.setDefault(True)
        
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        btn_layout.addWidget(close_btn)
        btn_layout.addStretch()
        
        layout.addLayout(btn_layout)

class SettingsDialog(QDialog):
    def __init__(self, parent=None, config=None):
        super().__init__(parent)
        self.config = config or {}
        self.setWindowTitle("הגדרות")
        self.setMinimumSize(400, 250)
        self.setup_ui()
    
    def setup_ui(self):
        layout = QVBoxLayout()
        self.setLayout(layout)
        
        title_label = QLabel("הגדרות Voltrix")
        title_font = QFont()
        title_font.setPointSize(14)
        title_font.setBold(True)
        title_label.setFont(title_font)
        layout.addWidget(title_label)
        
        display_group = QGroupBox("אפשרויות תצוגה")
        display_layout = QVBoxLayout()
        display_group.setLayout(display_layout)
        
        self.dark_mode_check = QCheckBox("מצב כהה")
        self.dark_mode_check.setChecked(self.config.get("dark_mode", False))
        display_layout.addWidget(self.dark_mode_check)
        
        layout.addWidget(display_group)
        
        save_group = QGroupBox("ברירת מחדל")
        save_layout = QVBoxLayout()
        save_group.setLayout(save_layout)
        
        self.auto_refresh_check = QCheckBox("רענון אוטומטי של התקני USB")
        self.auto_refresh_check.setChecked(self.config.get("auto_refresh", True))
        save_layout.addWidget(self.auto_refresh_check)
        
        self.enable_logging_check = QCheckBox("שמירה והדפסת לוגים")
        self.enable_logging_check.setChecked(self.config.get("enable_logging", True))
        save_layout.addWidget(self.enable_logging_check)
        
        layout.addWidget(save_group)
        
        layout.addStretch()
        
        buttons_layout = QHBoxLayout()
        layout.addLayout(buttons_layout)
        
        buttons_layout.addStretch()
        
        cancel_btn = QPushButton("ביטול")
        cancel_btn.clicked.connect(self.reject)
        buttons_layout.addWidget(cancel_btn)
        
        save_btn = QPushButton("שמור")
        save_btn.clicked.connect(self.accept)
        save_btn.setDefault(True)
        buttons_layout.addWidget(save_btn)
    
    def get_settings(self):
        return {
            "dark_mode": self.dark_mode_check.isChecked(),
            "auto_refresh": self.auto_refresh_check.isChecked(),
            "enable_logging": self.enable_logging_check.isChecked()
        }

def get_hardware_identifiers():

    identifiers = {}
    

    try:
        process = subprocess.Popen("wmic cpu get ProcessorId", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        if process.returncode == 0:
            cpu_id = re.search(r'[A-Z0-9]{30,}', stdout.decode())
            if cpu_id:
                identifiers["cpu"] = cpu_id.group(0).strip()
    except Exception as e:
        write_log(f"Error getting CPU serial number: {str(e)}")
    

    try:
        process = subprocess.Popen("wmic baseboard get SerialNumber", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        if process.returncode == 0:
            mb_serial = re.sub(r'SerialNumber\s*', '', stdout.decode()).strip()
            if mb_serial and mb_serial.lower() not in ["none", "to be filled by o.e.m.", "default string"]:
                identifiers["motherboard"] = mb_serial
    except Exception as e:
        write_log(f"Error getting motherboard serial number: {str(e)}")
    

    try:
        process = subprocess.Popen("wmic diskdrive get SerialNumber", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        if process.returncode == 0:
            lines = stdout.decode().strip().split('\n')
            if len(lines) > 1:
                hdd_serial = lines[1].strip()
                if hdd_serial:
                    identifiers["hdd"] = hdd_serial
    except Exception as e:
        write_log(f"Error getting disk serial number: {str(e)}")
    

    try:
        process = subprocess.Popen("wmic nic where PhysicalAdapter=True get MACAddress", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        if process.returncode == 0:
            mac_addresses = re.findall(r'([0-9A-F]{2}[:-][0-9A-F]{2}[:-][0-9A-F]{2}[:-][0-9A-F]{2}[:-][0-9A-F]{2}[:-][0-9A-F]{2})', stdout.decode())
            if mac_addresses:
                identifiers["mac"] = mac_addresses[0].replace(':', '-')
    except Exception as e:
        write_log(f"Error getting MAC address: {str(e)}")
    

    try:
        process = subprocess.Popen("wmic bios get SerialNumber", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        if process.returncode == 0:
            bios_serial = re.sub(r'SerialNumber\s*', '', stdout.decode()).strip()
            if bios_serial and bios_serial.lower() not in ["none", "to be filled by o.e.m.", "default string"]:
                identifiers["bios"] = bios_serial
    except Exception as e:
        write_log(f"Error getting BIOS serial number: {str(e)}")
    

    try:
        identifiers["uuid"] = str(uuid.getnode())
    except Exception as e:
        write_log(f"Error getting machine UUID: {str(e)}")
    
    return identifiers

class WorkerSignals(QObject):

    finished = Signal(str)
    error = Signal(str)

class TempFileWorker(QRunnable):

    
    def __init__(self, temp_file_path, program=None):
        super().__init__()
        self.temp_file_path = temp_file_path
        self.program = program
        self.signals = WorkerSignals()
    
    @Slot()
    def run(self):
        try:

            if self.program:
                if os.name == 'nt':
                    subprocess.Popen([self.program, self.temp_file_path], shell=True)
                else:
                    subprocess.Popen([self.program, self.temp_file_path])
            else:
                if os.name == 'nt':
                    os.startfile(self.temp_file_path)
                elif os.name == 'posix':
                    subprocess.Popen(['xdg-open' if 'linux' in sys.platform else 'open', self.temp_file_path])
            

            file_in_use = True
            while file_in_use:
                time.sleep(2)
                try:

                    os.rename(self.temp_file_path, self.temp_file_path + ".tmp")
                    os.rename(self.temp_file_path + ".tmp", self.temp_file_path)
                    file_in_use = False
                except (PermissionError, OSError):
                    pass
            

            try:
                os.remove(self.temp_file_path)
                self.signals.finished.emit(f"הקובץ הזמני נמחק: {self.temp_file_path}")
            except Exception as e:
                self.signals.error.emit(f"שגיאה במחיקת הקובץ הזמני: {str(e)}")
        except Exception as e:
            self.signals.error.emit(f"שגיאה בפתיחת הקובץ: {str(e)}")

class NotesDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("ניהול פתקים, תזכירים ומשימות")
        self.setMinimumSize(600, 500)
        self.data_file = os.path.join(APP_DATA_DIR, "user_notes.enc")
        self.data = {"notes": [], "memos": [], "tasks": []}
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        self.tabs = QTabWidget()
        layout.addWidget(self.tabs)

        self.notes_list = QListWidget()
        self.notes_list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.notes_list.customContextMenuRequested.connect(lambda pos: self.show_context_menu(pos, self.notes_list, "notes"))
        notes_tab = QWidget()
        notes_layout = QVBoxLayout(notes_tab)
        notes_layout.addWidget(self.notes_list)
        
        notes_btn_layout = QHBoxLayout()
        add_note_btn = QPushButton("הוסף פתק")
        add_note_btn.clicked.connect(self.add_note)
        notes_btn_layout.addWidget(add_note_btn)
        
        edit_note_btn = QPushButton("ערוך")
        edit_note_btn.clicked.connect(lambda: self.edit_item(self.notes_list, "notes"))
        notes_btn_layout.addWidget(edit_note_btn)
        
        delete_note_btn = QPushButton("מחק")
        delete_note_btn.clicked.connect(lambda: self.delete_item(self.notes_list, "notes"))
        notes_btn_layout.addWidget(delete_note_btn)
        
        notes_layout.addLayout(notes_btn_layout)
        self.tabs.addTab(notes_tab, "פתקים")

        self.memos_list = QListWidget()
        self.memos_list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.memos_list.customContextMenuRequested.connect(lambda pos: self.show_context_menu(pos, self.memos_list, "memos"))
        memos_tab = QWidget()
        memos_layout = QVBoxLayout(memos_tab)
        memos_layout.addWidget(self.memos_list)
        
        memos_btn_layout = QHBoxLayout()
        add_memo_btn = QPushButton("הוסף תזכיר")
        add_memo_btn.clicked.connect(self.add_memo)
        memos_btn_layout.addWidget(add_memo_btn)
        
        edit_memo_btn = QPushButton("ערוך")
        edit_memo_btn.clicked.connect(lambda: self.edit_item(self.memos_list, "memos"))
        memos_btn_layout.addWidget(edit_memo_btn)
        
        delete_memo_btn = QPushButton("מחק")
        delete_memo_btn.clicked.connect(lambda: self.delete_item(self.memos_list, "memos"))
        memos_btn_layout.addWidget(delete_memo_btn)
        
        memos_layout.addLayout(memos_btn_layout)
        self.tabs.addTab(memos_tab, "תזכירים")

        self.tasks_list = QListWidget()
        self.tasks_list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.tasks_list.customContextMenuRequested.connect(lambda pos: self.show_context_menu(pos, self.tasks_list, "tasks"))
        tasks_tab = QWidget()
        tasks_layout = QVBoxLayout(tasks_tab)
        tasks_layout.addWidget(self.tasks_list)
        
        tasks_btn_layout = QHBoxLayout()
        add_task_btn = QPushButton("הוסף משימה")
        add_task_btn.clicked.connect(self.add_task)
        tasks_btn_layout.addWidget(add_task_btn)
        
        edit_task_btn = QPushButton("ערוך")
        edit_task_btn.clicked.connect(lambda: self.edit_item(self.tasks_list, "tasks"))
        tasks_btn_layout.addWidget(edit_task_btn)
        
        delete_task_btn = QPushButton("מחק")
        delete_task_btn.clicked.connect(lambda: self.delete_item(self.tasks_list, "tasks"))
        tasks_btn_layout.addWidget(delete_task_btn)
        
        tasks_layout.addLayout(tasks_btn_layout)
        self.tabs.addTab(tasks_tab, "רשימת משימות")

        buttons_layout = QHBoxLayout()
        
        change_password_btn = QPushButton("שנה סיסמה")
        change_password_btn.clicked.connect(self.change_password)
        buttons_layout.addWidget(change_password_btn)
        
        save_btn = QPushButton("שמור וסגור")
        save_btn.clicked.connect(self.save_and_close)
        buttons_layout.addWidget(save_btn)
        
        layout.addLayout(buttons_layout)

    def show_context_menu(self, pos, list_widget, list_type):
        from PySide6.QtWidgets import QMenu
        
        menu = QMenu(self)
        edit_action = menu.addAction("ערוך")
        delete_action = menu.addAction("מחק")
        
        action = menu.exec(list_widget.mapToGlobal(pos))
        
        if action == edit_action:
            self.edit_item(list_widget, list_type)
        elif action == delete_action:
            self.delete_item(list_widget, list_type)

    def prompt_password(self, prompt="הזן קוד סודי לפתיחה:"):
        password, ok = QInputDialog.getText(self, "קוד סודי", prompt, QLineEdit.Password)
        if ok and password:
            return password
        return None

    def encrypt_data(self, password):
        import json
        import hashlib
        import base64
        from cryptography.fernet import Fernet

        key = base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest()[:32])
        cipher = Fernet(key)
        data_bytes = json.dumps(self.data, ensure_ascii=False, indent=2).encode("utf-8")
        encrypted = cipher.encrypt(data_bytes)
        with open(self.data_file, "wb") as f:
            f.write(encrypted)

    def decrypt_data(self, password):
        import json
        import hashlib
        import base64
        from cryptography.fernet import Fernet

        if not os.path.exists(self.data_file):
            return {"notes": [], "memos": [], "tasks": []}
        key = base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest()[:32])
        cipher = Fernet(key)
        with open(self.data_file, "rb") as f:
            encrypted = f.read()
        decrypted = cipher.decrypt(encrypted)
        return json.loads(decrypted.decode("utf-8"))

    def load_encrypted_data(self):
        password = self.prompt_password()
        if not password:
            self.reject()
            return False
        try:
            self.data = self.decrypt_data(password)
            self.password = password
        except Exception as e:
            QMessageBox.critical(self, "שגיאה", f"שגיאה בפענוח הנתונים: {str(e)}")
            self.reject()
            return False
        
        if not isinstance(self.data, dict) or not all(key in self.data for key in ["notes", "memos", "tasks"]):
            QMessageBox.critical(self, "שגיאה", "מבנה הנתונים אינו תקין")
            self.reject()
            return False
            
        self.refresh_lists()
        return True

    def refresh_lists(self):
        self.notes_list.clear()
        for note in self.data.get("notes", []):
            self.notes_list.addItem(QListWidgetItem(note))
        self.memos_list.clear()
        for memo in self.data.get("memos", []):
            self.memos_list.addItem(QListWidgetItem(memo))
        self.tasks_list.clear()
        for task in self.data.get("tasks", []):
            self.tasks_list.addItem(QListWidgetItem(task))

    def show_text_input_dialog(self, title, label, default_text=""):
        dialog = QDialog(self)
        dialog.setWindowTitle(title)
        dialog.setMinimumWidth(400)
        
        layout = QVBoxLayout(dialog)
        
        label_widget = QLabel(label)
        layout.addWidget(label_widget)
        
        text_edit = QTextEdit()
        text_edit.setMinimumHeight(100)
        text_edit.setText(default_text)
        layout.addWidget(text_edit)
        
        button_layout = QHBoxLayout()
        cancel_btn = QPushButton("ביטול")
        cancel_btn.clicked.connect(dialog.reject)
        button_layout.addWidget(cancel_btn)
        
        ok_btn = QPushButton("אישור")
        ok_btn.clicked.connect(dialog.accept)
        ok_btn.setDefault(True)
        button_layout.addWidget(ok_btn)
        
        layout.addLayout(button_layout)
        
        if dialog.exec() == QDialog.Accepted:
            return text_edit.toPlainText(), True
        return "", False

    def add_note(self):
        text, ok = self.show_text_input_dialog("הוסף פתק", "תוכן הפתק:")
        if ok and text:
            self.data.setdefault("notes", []).append(text)
            self.refresh_lists()

    def add_memo(self):
        text, ok = self.show_text_input_dialog("הוסף תזכיר", "תוכן התזכיר:")
        if ok and text:
            self.data.setdefault("memos", []).append(text)
            self.refresh_lists()

    def add_task(self):
        text, ok = self.show_text_input_dialog("הוסף משימה", "תוכן המשימה:")
        if ok and text:
            self.data.setdefault("tasks", []).append(text)
            self.refresh_lists()
            
    def edit_item(self, list_widget, list_type):
        current_item = list_widget.currentItem()
        if not current_item:
            QMessageBox.warning(self, "אזהרה", "יש לבחור פריט לעריכה")
            return
            
        current_row = list_widget.currentRow()
        current_text = current_item.text()
        
        new_text, ok = self.show_text_input_dialog(f"ערוך {list_type}", "תוכן:", current_text)
        if ok and new_text:
            self.data[list_type][current_row] = new_text
            current_item.setText(new_text)
            
    def delete_item(self, list_widget, list_type):
        current_row = list_widget.currentRow()
        if current_row < 0:
            QMessageBox.warning(self, "אזהרה", "יש לבחור פריט למחיקה")
            return
            
        confirm = QMessageBox.question(
            self, 
            "אישור מחיקה", 
            "האם אתה בטוח שברצונך למחוק פריט זה?",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if confirm == QMessageBox.Yes:
            list_widget.takeItem(current_row)
            del self.data[list_type][current_row]

    def change_password(self):
        current_password = self.prompt_password("הזן את הסיסמה הנוכחית:")
        if not current_password:
            return
            
        try:
            test_data = self.decrypt_data(current_password)
            if not isinstance(test_data, dict):
                QMessageBox.critical(self, "שגיאה", "הסיסמה שגויה")
                return
        except Exception:
            QMessageBox.critical(self, "שגיאה", "הסיסמה שגויה")
            return
            
        new_password = self.prompt_password("הזן סיסמה חדשה:")
        if not new_password:
            return
            
        confirm_password = self.prompt_password("אשר את הסיסמה החדשה:")
        if not confirm_password:
            return
            
        if new_password != confirm_password:
            QMessageBox.critical(self, "שגיאה", "הסיסמאות אינן תואמות")
            return
            
        try:
            self.password = new_password
            self.encrypt_data(new_password)
            QMessageBox.information(self, "הצלחה", "הסיסמה שונתה בהצלחה!")
        except Exception as e:
            QMessageBox.critical(self, "שגיאה", f"שגיאה בשינוי הסיסמה: {str(e)}")
    
    def save_and_close(self):
        try:
            self.encrypt_data(self.password)
            QMessageBox.information(self, "הצלחה", "הנתונים נשמרו בהצלחה!")
            self.accept()
        except Exception as e:
            QMessageBox.critical(self, "שגיאה", f"שגיאה בשמירת הנתונים: {str(e)}")

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        
        self.config = load_config()
        
        self.setWindowTitle("Voltrix")
        self.setMinimumSize(650, 500)
        
        if self.config.get("dark_mode", False):
            self.set_dark_mode()
        
        self.hardware_ids = get_hardware_identifiers()
        self.setup_ui()
    
    def set_dark_mode(self):
        dark_style = """
        QMainWindow, QDialog {
            background-color: #2d2d2d;
            color: #ffffff;
        }
        QWidget {
            background-color: #2d2d2d;
            color: #ffffff;
        }
        QGroupBox {
            border: 1px solid #555555;
            border-radius: 5px;
            margin-top: 1ex;
            color: #ffffff;
        }
        QGroupBox::title {
            subcontrol-origin: margin;
            subcontrol-position: top center;
            padding: 0 3px;
        }
        QPushButton {
            background-color: #0d6efd;
            color: white;
            border: none;
            border-radius: 4px;
            padding: 5px 15px;
        }
        QPushButton:hover {
            background-color: #0b5ed7;
        }
        QPushButton:pressed {
            background-color: #0a58ca;
        }
        QLineEdit, QTextEdit, QPlainTextEdit, QComboBox {
            background-color: #3d3d3d;
            color: #ffffff;
            border: 1px solid #555555;
            border-radius: 4px;
            padding: 2px;
        }
        QComboBox QAbstractItemView {
            background-color: #3d3d3d;
            color: #ffffff;
            selection-background-color: #0d6efd;
        }
        QRadioButton, QCheckBox {
            color: #ffffff;
        }
        QLabel {
            color: #ffffff;
        }
        QStatusBar {
            background-color: #252525;
            color: #ffffff;
        }
        QTabWidget::pane {
            border: 1px solid #555555;
            background-color: #2d2d2d;
        }
        QTabBar::tab {
            background-color: #353535;
            color: #ffffff;
            border: 1px solid #555555;
            border-bottom-color: #555555;
            border-top-left-radius: 4px;
            border-top-right-radius: 4px;
            padding: 5px 10px;
        }
        QTabBar::tab:selected, QTabBar::tab:hover {
            background-color: #0d6efd;
        }"""

        self.setStyleSheet(dark_style)
    
    def setup_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(20, 20, 20, 20)
        
        header_layout = QHBoxLayout()
        main_layout.addLayout(header_layout)
        
        title_label = QLabel("Voltrix")
        title_font = QFont()
        title_font.setPointSize(16)
        title_font.setBold(True)
        title_label.setFont(title_font)
        header_layout.addWidget(title_label)
        
        btn_layout = QHBoxLayout()
        header_layout.addLayout(btn_layout)
        
        btn_layout.addStretch()
        
        about_btn = QPushButton("אודות")
        about_btn.clicked.connect(self.show_about)
        btn_layout.addWidget(about_btn)
        
        settings_btn = QPushButton("הגדרות")
        settings_btn.clicked.connect(self.show_settings)
        btn_layout.addWidget(settings_btn)

        notes_btn = QPushButton("פתקים/משימות")
        notes_btn.clicked.connect(self.show_notes_dialog)
        btn_layout.addWidget(notes_btn)
        
        main_layout.addSpacing(10)
        

        file_group = QGroupBox("בחירת קובץ")
        file_layout = QVBoxLayout()
        file_group.setLayout(file_layout)
        
        file_label = QLabel("בחר קובץ להצפנה או פענוח:")
        file_layout.addWidget(file_label)
        
        file_selection_layout = QHBoxLayout()
        self.file_text = QLineEdit()
        self.file_text.setReadOnly(True)
        self.file_text.setPlaceholderText("בחר קובץ...")
        file_selection_layout.addWidget(self.file_text)
        
        browse_button = QPushButton("בחר")
        browse_button.clicked.connect(self.on_browse)
        file_selection_layout.addWidget(browse_button)
        
        file_layout.addLayout(file_selection_layout)
        main_layout.addWidget(file_group)
        

        key_group = QGroupBox("מקור המפתח")
        key_layout = QVBoxLayout()
        key_group.setLayout(key_layout)
        
        self.tab_widget = QTabWidget()
        key_layout.addWidget(self.tab_widget)
        

        usb_tab = QWidget()
        usb_layout = QVBoxLayout(usb_tab)
        
        usb_label = QLabel("בחר התקן USB (המפתח יופק ממספר הסידורי שלו):")
        usb_layout.addWidget(usb_label)
        
        usb_selection_layout = QHBoxLayout()
        self.usb_combo = QComboBox()
        usb_selection_layout.addWidget(self.usb_combo)
        
        refresh_button = QPushButton("רענן")
        refresh_button.clicked.connect(self.update_usb_devices)
        usb_selection_layout.addWidget(refresh_button)
        
        usb_layout.addLayout(usb_selection_layout)
        usb_layout.addStretch()
        
        self.tab_widget.addTab(usb_tab, "התקן USB")
        

        hw_tab = QWidget()
        hw_layout = QVBoxLayout(hw_tab)
        
        hw_label = QLabel("בחר רכיב חומרה (המפתח יופק מהמספר הסידורי שלו):")
        hw_layout.addWidget(hw_label)
        
        self.hw_id_group = QButtonGroup()
        

        self.hw_radio_buttons = {}
        for i, (hw_type, hw_id) in enumerate(self.hardware_ids.items()):
            radio_btn = QRadioButton(f"{self.get_hw_name(hw_type)}: {hw_id}")
            radio_btn.setChecked(i == 0)
            hw_layout.addWidget(radio_btn)
            self.hw_id_group.addButton(radio_btn, i)
            self.hw_radio_buttons[i] = (hw_type, hw_id)
        
        hw_layout.addStretch()
        
        self.tab_widget.addTab(hw_tab, "רכיבי חומרה")
        
        main_layout.addWidget(key_group)
        

        buttons_layout = QHBoxLayout()
        buttons_layout.addStretch()
        
        self.encrypt_button = QPushButton("הצפן")
        self.encrypt_button.setMinimumSize(120, 40)
        button_font = QFont()
        button_font.setBold(True)
        self.encrypt_button.setFont(button_font)
        self.encrypt_button.clicked.connect(self.on_encrypt)
        buttons_layout.addWidget(self.encrypt_button)
        
        self.decrypt_button = QPushButton("פענח")
        self.decrypt_button.setMinimumSize(120, 40)
        self.decrypt_button.setFont(button_font)
        self.decrypt_button.clicked.connect(self.on_decrypt)
        buttons_layout.addWidget(self.decrypt_button)
        
        buttons_layout.addStretch()
        main_layout.addLayout(buttons_layout)
        

        main_layout.addSpacing(10)
        
        open_buttons_layout = QHBoxLayout()
        open_buttons_layout.addStretch()
        
        self.open_decrypt_button = QPushButton("פתח קובץ")
        self.open_decrypt_button.setMinimumSize(120, 40)
        self.open_decrypt_button.setFont(button_font)
        self.open_decrypt_button.clicked.connect(self.on_open_decrypted)
        open_buttons_layout.addWidget(self.open_decrypt_button)
        
        self.open_with_button = QPushButton("פתח באמצעות...")
        self.open_with_button.setMinimumSize(120, 40)
        self.open_with_button.setFont(button_font)
        self.open_with_button.clicked.connect(self.on_open_with)
        open_buttons_layout.addWidget(self.open_with_button)
        
        open_buttons_layout.addStretch()
        main_layout.addLayout(open_buttons_layout)
        
        main_layout.addStretch()
        

        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Voltrix מוכן")
        

        self.update_usb_devices()
        

        self.temp_files = []
        

        self.threadpool = QThreadPool()
    
    def get_hw_name(self, hw_type):

        hw_names = {
            "cpu": "מעבד",
            "motherboard": "לוח אם",
            "hdd": "דיסק קשיח",
            "mac": "כרטיס רשת",
            "bios": "BIOS",
            "uuid": "מזהה מכונה"
        }
        return hw_names.get(hw_type, hw_type)
    
    def update_usb_devices(self):
        write_log("=== Starting USB device detection ===")
        self.usb_combo.clear()
        devices = []
        
        command = "wmic logicaldisk where DriveType=2 get DeviceID, VolumeName"
        write_log(f"Command: {command}")
        
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        
        if process.returncode == 0:
            output = stdout.decode().strip().split("\n")[1:]
            write_log(f"WMIC output:\n{stdout.decode()}")
            
            for line in output:
                parts = line.strip().split()
                if len(parts) >= 1:
                    if len(parts) == 2:
                        drive_letter, volume_name = parts
                        devices.append(f"{volume_name} ({drive_letter})")
                    elif len(parts) == 1:
                        drive_letter = parts[0]
                        devices.append(f"Unknown ({drive_letter})")
        else:
            error_message = stderr.decode()
            write_log(f"Error detecting USB devices: {error_message}")
            QMessageBox.critical(self, "שגיאה", f"שגיאה בזיהוי התקני USB: {error_message}")
        
        if devices:
            self.usb_combo.addItems(devices)
        else:
            self.usb_combo.addItem("לא נמצאו התקנים")
            write_log("No USB devices found")
    
    def get_key_serial(self):

        current_tab = self.tab_widget.currentIndex()
        
        if current_tab == 0:
            serial = self.usb_combo.currentText()
            if not serial or serial == "לא נמצאו התקנים":
                QMessageBox.warning(self, "שגיאה", "בחר התקן USB")
                return None
            
            try:
                device_letter = serial.split(" (")[1].split(")")[0]
                command = f"wmic logicaldisk where DeviceID='{device_letter}' get VolumeSerialNumber"
                write_log(f"Command: {command}")
                
                process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                stdout, stderr = process.communicate()
                
                if process.returncode == 0:
                    try:
                        serial_number = stdout.decode().strip().split("\n")[1].strip()
                        write_log(f"USB serial number: {serial_number}")
                        return serial_number
                    except IndexError:
                        QMessageBox.critical(self, "שגיאה", "לא הצלחתי לקבל מספר סידורי")
                        return None
                else:
                    error_message = stderr.decode()
                    write_log(f"Error getting serial number: {error_message}")
                    QMessageBox.critical(self, "שגיאה", f"שגיאה: {error_message}")
                    return None
            except Exception as e:
                write_log(f"Error processing serial number: {str(e)}")
                QMessageBox.critical(self, "שגיאה", f"שגיאה בעיבוד המספר הסידורי: {str(e)}")
                return None
                
        elif current_tab == 1:
            selected_id = self.hw_id_group.checkedId()
            if selected_id >= 0 and selected_id in self.hw_radio_buttons:
                hw_type, hw_id = self.hw_radio_buttons[selected_id]
                write_log(f"Selected hardware identifier: {hw_type} - {hw_id}")
                return hw_id
            else:
                QMessageBox.warning(self, "שגיאה", "בחר רכיב חומרה")
                return None
        
        return None
    
    def on_browse(self):
        dlg = QFileDialog(self, "בחר קובץ")
        if dlg.exec():
            file_path = dlg.selectedFiles()[0]
            self.file_text.setText(file_path)
            write_log(f"File selected: {file_path}")
    
    def on_encrypt(self):
        file_path = self.file_text.text()
        if not file_path:
            QMessageBox.warning(self, "שגיאה", "בחר קובץ להצפנה")
            return
        
        serial_number = self.get_key_serial()
        if not serial_number:
            return
        
        self.status_bar.showMessage("מצפין קובץ...")
        

        env = os.environ.copy()
        env["PYTHONIOENCODING"] = "utf-8"
        
        #encrypt_command = f'python Encrypt.exe {serial_number} "{file_path}"'
        encrypt_command = f'Encrypt.exe {serial_number} "{file_path}"'
        write_log(f"Encryption command: {encrypt_command}")
        
        process = subprocess.Popen(encrypt_command, shell=True, stdout=subprocess.PIPE, 
                                  stderr=subprocess.PIPE, env=env)
        stdout, stderr = process.communicate()
        
        try:
            stdout_text = stdout.decode('utf-8')
        except UnicodeDecodeError:
            stdout_text = stdout.decode('utf-8', errors='replace')
            
        write_log(f"Encryption output:\n{stdout_text}")
        
        if process.returncode == 0:
            self.status_bar.showMessage("הקובץ הוצפן בהצלחה")
            QMessageBox.information(self, "הצלחה", "הקובץ הוצפן בהצלחה!")
        else:
            try:
                error_message = stderr.decode('utf-8')
            except UnicodeDecodeError:
                error_message = stderr.decode('utf-8', errors='replace')
                
            write_log(f"Encryption error: {error_message}")
            self.status_bar.showMessage("ההצפנה נכשלה")
            QMessageBox.critical(self, "שגיאה", f"ההצפנה נכשלה: {error_message}")
    
    def on_decrypt(self):
        file_path = self.file_text.text()
        if not file_path:
            QMessageBox.warning(self, "שגיאה", "בחר קובץ לפענוח")
            return
        
        serial_number = self.get_key_serial()
        if not serial_number:
            return
        
        self.status_bar.showMessage("מפענח קובץ...")
        

        env = os.environ.copy()
        env["PYTHONIOENCODING"] = "utf-8"
        
        #decrypt_command = f'python Decrypt.exe {serial_number} "{file_path}"'
        decrypt_command = f'Decrypt.exe {serial_number} "{file_path}"'
        write_log(f"Decryption command: {decrypt_command}")
        
        process = subprocess.Popen(decrypt_command, shell=True, stdout=subprocess.PIPE, 
                                  stderr=subprocess.PIPE, env=env)
        stdout, stderr = process.communicate()
        
        try:
            stdout_text = stdout.decode('utf-8')
        except UnicodeDecodeError:
            stdout_text = stdout.decode('utf-8', errors='replace')
            
        write_log(f"Decryption output:\n{stdout_text}")
        
        if process.returncode == 0:
            self.status_bar.showMessage("הקובץ פוענח בהצלחה")
            QMessageBox.information(self, "הצלחה", "הקובץ פוענח בהצלחה!")
        else:
            try:
                error_message = stderr.decode('utf-8')
            except UnicodeDecodeError:
                error_message = stderr.decode('utf-8', errors='replace')
                
            write_log(f"Decryption error: {error_message}")
            self.status_bar.showMessage("הפענוח נכשל")
            QMessageBox.critical(self, "שגיאה", f"הפענוח נכשל: {error_message}")
    
    def on_open_decrypted(self):

        file_path = self.file_text.text()
        if not file_path:
            QMessageBox.warning(self, "שגיאה", "בחר קובץ לפענוח")
            return
        
        serial_number = self.get_key_serial()
        if not serial_number:
            return
        
        self.status_bar.showMessage("מפענח ופותח קובץ...")
        

        env = os.environ.copy()
        env["PYTHONIOENCODING"] = "utf-8"
        
        #decrypt_command = f'python Decrypt.exe {serial_number} "{file_path}" --temp'
        decrypt_command = f'Decrypt.exe {serial_number} "{file_path}" --temp'
        write_log(f"Temporary decryption command: {decrypt_command}")
        
        process = subprocess.Popen(decrypt_command, shell=True, stdout=subprocess.PIPE, 
                                 stderr=subprocess.PIPE, env=env)
        stdout, stderr = process.communicate()
        
        try:
            stdout_text = stdout.decode('utf-8')
        except UnicodeDecodeError:
            stdout_text = stdout.decode('utf-8', errors='replace')
            
        write_log(f"Temporary decryption output:\n{stdout_text}")
        
        if process.returncode == 0:

            lines = stdout_text.strip().split('\n')
            temp_file_path = None
            for line in lines:
                if "Temporary decrypted file created at:" in line:
                    temp_file_path = line.split("Temporary decrypted file created at:")[1].strip()
                    break
            
            if temp_file_path and os.path.exists(temp_file_path):
                self.status_bar.showMessage(f"הקובץ פוענח זמנית ונפתח: {temp_file_path}")
                self.temp_files.append(temp_file_path)
                

                worker = TempFileWorker(temp_file_path)
                worker.signals.finished.connect(lambda msg: self.status_bar.showMessage(msg))
                worker.signals.error.connect(lambda msg: self.status_bar.showMessage(msg))
                self.threadpool.start(worker)
            else:
                self.status_bar.showMessage("שגיאה בפענוח הקובץ הזמני")
                QMessageBox.critical(self, "שגיאה", "לא ניתן למצוא את הקובץ המפוענח הזמני")
        else:
            try:
                error_message = stderr.decode('utf-8')
            except UnicodeDecodeError:
                error_message = stderr.decode('utf-8', errors='replace')
                
            write_log(f"Temporary decryption error: {error_message}")
            self.status_bar.showMessage("הפענוח הזמני נכשל")
            QMessageBox.critical(self, "שגיאה", f"הפענוח הזמני נכשל: {error_message}")

    def on_open_with(self):

        file_path = self.file_text.text()
        if not file_path:
            QMessageBox.warning(self, "שגיאה", "בחר קובץ לפענוח")
            return
        
        serial_number = self.get_key_serial()
        if not serial_number:
            return
        

        program_path, _ = QFileDialog.getOpenFileName(
            self,
            "בחר תוכנה לפתיחת הקובץ",
            "",
            "קבצי הפעלה (*.exe);;כל הקבצים (*.*)" if os.name == 'nt' else "כל הקבצים (*.*)"
        )
        
        if not program_path:
            return
        
        self.status_bar.showMessage("מפענח ופותח קובץ...")
        

        env = os.environ.copy()
        env["PYTHONIOENCODING"] = "utf-8"
        
        #decrypt_command = f'python Decrypt.exe {serial_number} "{file_path}" --temp'
        decrypt_command = f'Decrypt.exe {serial_number} "{file_path}" --temp'
        write_log(f"Temporary decryption command for opening with: {decrypt_command}")
        
        process = subprocess.Popen(decrypt_command, shell=True, stdout=subprocess.PIPE, 
                                 stderr=subprocess.PIPE, env=env)
        stdout, stderr = process.communicate()
        
        try:
            stdout_text = stdout.decode('utf-8')
        except UnicodeDecodeError:
            stdout_text = stdout.decode('utf-8', errors='replace')
            
        write_log(f"Temporary decryption output for opening with:\n{stdout_text}")
        
        if process.returncode == 0:

            lines = stdout_text.strip().split('\n')
            temp_file_path = None
            for line in lines:
                if "Temporary decrypted file created at:" in line:
                    temp_file_path = line.split("Temporary decrypted file created at:")[1].strip()
                    break
            
            if temp_file_path and os.path.exists(temp_file_path):
                self.status_bar.showMessage(f"הקובץ פוענח זמנית ונפתח באמצעות {os.path.basename(program_path)}")
                self.temp_files.append(temp_file_path)
                

                worker = TempFileWorker(temp_file_path, program_path)
                worker.signals.finished.connect(lambda msg: self.status_bar.showMessage(msg))
                worker.signals.error.connect(lambda msg: self.status_bar.showMessage(msg))
                self.threadpool.start(worker)
            else:
                self.status_bar.showMessage("שגיאה בפענוח הקובץ הזמני")
                QMessageBox.critical(self, "שגיאה", "לא ניתן למצוא את הקובץ המפוענח הזמני")
        else:
            try:
                error_message = stderr.decode('utf-8')
            except UnicodeDecodeError:
                error_message = stderr.decode('utf-8', errors='replace')
                
            write_log(f"Temporary decryption error for opening with: {error_message}")
            self.status_bar.showMessage("הפענוח הזמני נכשל")
            QMessageBox.critical(self, "שגיאה", f"הפענוח הזמני נכשל: {error_message}")
    
    def closeEvent(self, event):

        for temp_file in self.temp_files:
            try:
                if os.path.exists(temp_file):
                    os.remove(temp_file)
                    write_log(f"Temporary file deleted on application close: {temp_file}")
            except Exception as e:
                write_log(f"Error deleting temporary file on application close: {str(e)}")
        
        event.accept()
    
    def show_about(self):
        dialog = AboutDialog(self)
        dialog.exec()
    
    def show_settings(self):
        dialog = SettingsDialog(self, self.config)
        if dialog.exec():
            old_dark_mode = self.config.get("dark_mode", False)
            self.config = dialog.get_settings()
            save_config(self.config)
            
            if old_dark_mode != self.config.get("dark_mode", False):
                if self.config.get("dark_mode", False):
                    self.set_dark_mode()
                else:
                    self.setStyleSheet("")

    def show_notes_dialog(self):
        dialog = NotesDialog(self)
        
        if dialog.load_encrypted_data() == False:
            return
            
        dialog.exec()

def main():
    app = QApplication(sys.argv)
    app.setLayoutDirection(Qt.RightToLeft)
    app.setStyle("Fusion")
    
    window = MainWindow()
    window.show()
    
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
