"""
SSH Credential Tester GUI (Educational Purposes Only)
----------------------------------------------------
Graphical interface for the SSH credential tester with blue theme.
Includes all ethical safeguards from the command-line version.

WARNING: Only for authorized security testing with explicit permission.
"""

import sys
import paramiko
import socket
import time
from typing import List, Optional
import queue
import threading
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                             QLabel, QLineEdit, QPushButton, QTextEdit, QProgressBar,
                             QFileDialog, QMessageBox, QGroupBox, QSpinBox, QCheckBox)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QFont, QPalette, QColor

# Constants
MAX_ATTEMPTS_PER_ACCOUNT = 3
DELAY_BETWEEN_ATTEMPTS = 5
MAX_THREADS = 5  # Strict limit for ethical reasons

class TestResult:
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"
    ERROR = "ERROR"

class WorkerThread(QThread):
    update_signal = pyqtSignal(str, str, str)
    progress_signal = pyqtSignal(int)
    completed_signal = pyqtSignal(int, int, int)

    def __init__(self, target_ip, target_port, username_list, password_list, max_threads):
        super().__init__()
        self.target_ip = target_ip
        self.target_port = target_port
        self.username_list = username_list
        self.password_list = password_list
        self.max_threads = min(max_threads, MAX_THREADS)
        self.stop_event = threading.Event()
        self.results = queue.Queue()
        self.cred_queue = queue.Queue()
        self.lock = threading.Lock()

    def run(self):
        # Fill the credential queue
        for username in self.username_list:
            for password in self.password_list:
                self.cred_queue.put((username, password))

        total = self.cred_queue.qsize()
        completed = 0
        successful = 0
        failed = 0
        errors = 0

        # Worker function for threads
        def worker():
            nonlocal completed, successful, failed, errors
            while not self.cred_queue.empty() and not self.stop_event.is_set():
                try:
                    username, password = self.cred_queue.get_nowait()
                    result = self.test_credentials(username, password)
                    
                    with self.lock:
                        if result == TestResult.SUCCESS:
                            successful += 1
                            self.update_signal.emit(username, password, "SUCCESS")
                            self.stop_event.set()
                        elif result == TestResult.FAILURE:
                            failed += 1
                            self.update_signal.emit(username, password, "FAILURE")
                        else:
                            errors += 1
                            self.update_signal.emit(username, password, "ERROR")
                        
                        completed += 1
                        progress = int((completed / total) * 100)
                        self.progress_signal.emit(progress)
                        self.cred_queue.task_done()
                        
                        # Rate limiting
                        time.sleep(DELAY_BETWEEN_ATTEMPTS)
                        
                except queue.Empty:
                    break

        # Create and start threads
        threads = []
        for _ in range(self.max_threads):
            t = threading.Thread(target=worker)
            t.start()
            threads.append(t)

        # Wait for threads to complete
        for t in threads:
            t.join()

        self.completed_signal.emit(successful, failed, errors)

    def test_credentials(self, username: str, password: str) -> str:
        if self.stop_event.is_set():
            return TestResult.ERROR

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            client.connect(
                self.target_ip,
                port=self.target_port,
                username=username,
                password=password,
                timeout=10,
                banner_timeout=10
            )
            client.close()
            return TestResult.SUCCESS
        except paramiko.AuthenticationException:
            return TestResult.FAILURE
        except (paramiko.SSHException, socket.error):
            return TestResult.ERROR
        finally:
            try:
                client.close()
            except:
                pass

    def stop(self):
        self.stop_event.set()

class BlueTheme:
    @staticmethod
    def apply(app):
        app.setStyle("Fusion")
        
        dark_palette = QPalette()
        dark_palette.setColor(QPalette.Window, QColor(30, 60, 90))
        dark_palette.setColor(QPalette.WindowText, Qt.white)
        dark_palette.setColor(QPalette.Base, QColor(20, 40, 60))
        dark_palette.setColor(QPalette.AlternateBase, QColor(30, 60, 90))
        dark_palette.setColor(QPalette.ToolTipBase, Qt.white)
        dark_palette.setColor(QPalette.ToolTipText, Qt.white)
        dark_palette.setColor(QPalette.Text, Qt.white)
        dark_palette.setColor(QPalette.Button, QColor(50, 100, 150))
        dark_palette.setColor(QPalette.ButtonText, Qt.white)
        dark_palette.setColor(QPalette.BrightText, Qt.red)
        dark_palette.setColor(QPalette.Highlight, QColor(0, 120, 215))
        dark_palette.setColor(QPalette.HighlightedText, Qt.white)
        
        app.setPalette(dark_palette)
        app.setStyleSheet("""
            QGroupBox {
                border: 1px solid #4682B4;
                border-radius: 5px;
                margin-top: 10px;
                padding-top: 15px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 3px;
            }
            QPushButton {
                background-color: #4682B4;
                border: 1px solid #4682B4;
                border-radius: 4px;
                padding: 5px;
                min-width: 80px;
            }
            QPushButton:hover {
                background-color: #5F9EA0;
            }
            QPushButton:pressed {
                background-color: #4169E1;
            }
            QPushButton:disabled {
                background-color: #708090;
            }
            QProgressBar {
                border: 1px solid #4682B4;
                border-radius: 3px;
                text-align: center;
            }
            QProgressBar::chunk {
                background-color: #4682B4;
                width: 10px;
            }
        """)

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Accurate Cyber Defense SSH CRACKER)")
        self.setGeometry(100, 100, 800, 600)
        
        # Central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Main layout
        main_layout = QVBoxLayout()
        central_widget.setLayout(main_layout)
        
        # Title
        title = QLabel("SSH Credential Tester")
        title.setFont(QFont("Arial", 16, QFont.Bold))
        title.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(title)
        
        # Warning label
        warning = QLabel("WARNING: Only use this tool on systems you own or have explicit permission to test.")
        warning.setFont(QFont("Arial", 10))
        warning.setStyleSheet("color: #FF6347;")
        warning.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(warning)
        
        # Target group
        target_group = QGroupBox("Target Information")
        target_layout = QVBoxLayout()
        
        # IP address
        ip_layout = QHBoxLayout()
        ip_layout.addWidget(QLabel("Target IP:"))
        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("192.168.1.1")
        ip_layout.addWidget(self.ip_input)
        target_layout.addLayout(ip_layout)
        
        # Port
        port_layout = QHBoxLayout()
        port_layout.addWidget(QLabel("SSH Port:"))
        self.port_input = QSpinBox()
        self.port_input.setRange(1, 65535)
        self.port_input.setValue(22)
        port_layout.addWidget(self.port_input)
        target_layout.addLayout(port_layout)
        
        target_group.setLayout(target_layout)
        main_layout.addWidget(target_group)
        
        # Credentials group
        creds_group = QGroupBox("Credentials")
        creds_layout = QVBoxLayout()
        
        # Username file
        user_layout = QHBoxLayout()
        user_layout.addWidget(QLabel("Username List:"))
        self.user_file_input = QLineEdit()
        self.user_file_input.setPlaceholderText("Path to username wordlist")
        user_layout.addWidget(self.user_file_input)
        self.user_file_button = QPushButton("Browse...")
        self.user_file_button.clicked.connect(self.browse_user_file)
        user_layout.addWidget(self.user_file_button)
        creds_layout.addLayout(user_layout)
        
        # Password file
        pass_layout = QHBoxLayout()
        pass_layout.addWidget(QLabel("Password List:"))
        self.pass_file_input = QLineEdit()
        self.pass_file_input.setPlaceholderText("Path to password wordlist")
        pass_layout.addWidget(self.pass_file_input)
        self.pass_file_button = QPushButton("Browse...")
        self.pass_file_button.clicked.connect(self.browse_pass_file)
        pass_layout.addWidget(self.pass_file_button)
        creds_layout.addLayout(pass_layout)
        
        creds_group.setLayout(creds_layout)
        main_layout.addWidget(creds_group)
        
        # Options group
        options_group = QGroupBox("Options")
        options_layout = QHBoxLayout()
        
        # Threads
        options_layout.addWidget(QLabel("Threads:"))
        self.threads_input = QSpinBox()
        self.threads_input.setRange(1, MAX_THREADS)
        self.threads_input.setValue(1)
        options_layout.addWidget(self.threads_input)
        
        # Output file
        options_layout.addWidget(QLabel("Output File:"))
        self.output_file_input = QLineEdit()
        self.output_file_input.setPlaceholderText("Optional results file")
        options_layout.addWidget(self.output_file_input)
        self.output_file_button = QPushButton("Browse...")
        self.output_file_button.clicked.connect(self.browse_output_file)
        options_layout.addWidget(self.output_file_button)
        
        options_group.setLayout(options_layout)
        main_layout.addWidget(options_group)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setTextVisible(True)
        main_layout.addWidget(self.progress_bar)
        
        # Buttons
        button_layout = QHBoxLayout()
        self.start_button = QPushButton("Start Test")
        self.start_button.clicked.connect(self.start_test)
        button_layout.addWidget(self.start_button)
        
        self.stop_button = QPushButton("Stop Test")
        self.stop_button.clicked.connect(self.stop_test)
        self.stop_button.setEnabled(False)
        button_layout.addWidget(self.stop_button)
        
        main_layout.addLayout(button_layout)
        
        # Results
        self.results_display = QTextEdit()
        self.results_display.setReadOnly(True)
        main_layout.addWidget(self.results_display)
        
        # Worker thread
        self.worker_thread = None
        
        # Status bar
        self.status_bar = self.statusBar()
        self.status_bar.showMessage("Ready")
        
    def browse_user_file(self):
        filename, _ = QFileDialog.getOpenFileName(self, "Select Username Wordlist", "", "Text Files (*.txt);;All Files (*)")
        if filename:
            self.user_file_input.setText(filename)
    
    def browse_pass_file(self):
        filename, _ = QFileDialog.getOpenFileName(self, "Select Password Wordlist", "", "Text Files (*.txt);;All Files (*)")
        if filename:
            self.pass_file_input.setText(filename)
    
    def browse_output_file(self):
        filename, _ = QFileDialog.getSaveFileName(self, "Select Output File", "", "Text Files (*.txt);;All Files (*)")
        if filename:
            self.output_file_input.setText(filename)
    
    def validate_inputs(self):
        ip = self.ip_input.text().strip()
        if not self.is_valid_ip(ip):
            QMessageBox.warning(self, "Invalid Input", "Please enter a valid IP address")
            return False
        
        user_file = self.user_file_input.text().strip()
        pass_file = self.pass_file_input.text().strip()
        
        if not user_file or not pass_file:
            QMessageBox.warning(self, "Invalid Input", "Please select both username and password wordlists")
            return False
        
        return True
    
    def is_valid_ip(self, ip):
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(part) <= 255 for part in parts)
        except ValueError:
            return False
    
    def start_test(self):
        if not self.validate_inputs():
            return
        
        # Confirm ethical use
        reply = QMessageBox.question(
            self, "Ethical Warning",
            "This tool should only be used against systems you own or have explicit written permission to test.\n\n"
            "Unauthorized access is illegal. Do you have proper authorization?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        )
        
        if reply != QMessageBox.Yes:
            self.status_bar.showMessage("Testing aborted - authorization not confirmed")
            return
        
        # Get input values
        ip = self.ip_input.text().strip()
        port = self.port_input.value()
        user_file = self.user_file_input.text().strip()
        pass_file = self.pass_file_input.text().strip()
        threads = self.threads_input.value()
        output_file = self.output_file_input.text().strip()
        
        # Load wordlists
        try:
            with open(user_file, 'r', errors='ignore') as f:
                usernames = [line.strip() for line in f if line.strip()]
            
            with open(pass_file, 'r', errors='ignore') as f:
                passwords = [line.strip() for line in f if line.strip()]
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load wordlists: {str(e)}")
            return
        
        if not usernames or not passwords:
            QMessageBox.warning(self, "Error", "Wordlists cannot be empty")
            return
        
        # Clear previous results
        self.results_display.clear()
        self.progress_bar.setValue(0)
        
        # Update UI
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.status_bar.showMessage("Testing in progress...")
        
        # Start worker thread
        self.worker_thread = WorkerThread(ip, port, usernames, passwords, threads)
        self.worker_thread.update_signal.connect(self.update_results)
        self.worker_thread.progress_signal.connect(self.update_progress)
        self.worker_thread.completed_signal.connect(self.test_completed)
        self.worker_thread.start()
    
    def stop_test(self):
        if self.worker_thread and self.worker_thread.isRunning():
            self.worker_thread.stop()
            self.worker_thread.wait()
        
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.status_bar.showMessage("Testing stopped by user")
    
    def update_results(self, username, password, result):
        if result == TestResult.SUCCESS:
            color = "#00FF00"  # Green
            prefix = "[SUCCESS]"
        elif result == TestResult.FAILURE:
            color = "#FFFF00"  # Yellow
            prefix = "[FAILURE]"
        else:
            color = "#FF0000"  # Red
            prefix = "[ERROR]"
        
        self.results_display.append(
            f'<span style="color:{color}">{prefix} {username}:{password}</span>'
        )
    
    def update_progress(self, value):
        self.progress_bar.setValue(value)
    
    def test_completed(self, successful, failed, errors):
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        
        # Save results if output file specified
        output_file = self.output_file_input.text().strip()
        if successful > 0 and output_file:
            try:
                with open(output_file, 'w') as f:
                    # We would save the successful credentials here
                    f.write(f"Successful logins: {successful}\n")
            except Exception as e:
                QMessageBox.warning(self, "Error", f"Failed to save results: {str(e)}")
        
        self.status_bar.showMessage(
            f"Testing complete - Successful: {successful}, Failed: {failed}, Errors: {errors}"
        )
        
        if successful > 0:
            QMessageBox.information(
                self, "Test Complete",
                f"Found {successful} valid credential(s)!\n\n"
                "Remember: Only use this information for authorized security improvements."
            )

def main():
    app = QApplication(sys.argv)
    
    # Apply blue theme
    BlueTheme.apply(app)
    
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()