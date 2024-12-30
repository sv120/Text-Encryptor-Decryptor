# This code is written by Sharad Verma.
# the Version of this code is 1.0.
# This code encrypts and decrypts text using AES encryption with a secret key.

import sys
import base64
import os
from PyQt5.QtWidgets import QApplication, QWidget, QLabel, QTextEdit, QPushButton, QVBoxLayout, QHBoxLayout, QSpacerItem, QSizePolicy
from PyQt5.QtCore import Qt, QTimer
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives import hmac
import pyperclip
import ctypes

# Function to derive key
def derive_key(passphrase, salt):
    kdf = PBKDF2HMAC(
        algorithm=SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(passphrase.encode())

# Encrypt text using AES
def encrypt_text(text, passphrase):
    salt = os.urandom(16)
    iv = os.urandom(16)
    key = derive_key(passphrase, salt)
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    padder = PKCS7(128).padder()
    padded_data = padder.update(text.encode()) + padder.finalize()
    
    encrypted_bytes = encryptor.update(padded_data) + encryptor.finalize()
    encrypted_data = salt + iv + encrypted_bytes
    
    # Create HMAC to ensure integrity
    hmac_obj = hmac.HMAC(key, SHA256(), backend=default_backend())
    hmac_obj.update(encrypted_data)
    mac = hmac_obj.finalize()
    
    encrypted_data_with_mac = encrypted_data + mac
    return base64.b64encode(encrypted_data_with_mac).decode()

# Decrypt text using AES
def decrypt_text(encrypted_text, passphrase):
    try:
        encrypted_data_with_mac = base64.b64decode(encrypted_text)
        mac = encrypted_data_with_mac[-32:]
        encrypted_data = encrypted_data_with_mac[:-32]
        
        salt = encrypted_data[:16]
        iv = encrypted_data[16:32]
        encrypted_bytes = encrypted_data[32:]
        
        key = derive_key(passphrase, salt)
        
        # Verify HMAC to ensure integrity
        hmac_obj = hmac.HMAC(key, SHA256(), backend=default_backend())
        hmac_obj.update(encrypted_data)
        hmac_obj.verify(mac)
        
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        
        decrypted_bytes = decryptor.update(encrypted_bytes) + decryptor.finalize()
        
        # Validate and remove padding
        padding_len = decrypted_bytes[-1]
        if padding_len < 1 or padding_len > 16:
            raise ValueError("Invalid padding length")
        decrypted_text = decrypted_bytes[:-padding_len].decode()
        
        return decrypted_text
    except Exception:
        return None

# Clear sensitive data securely
def secure_clear(data):
    if isinstance(data, bytearray):
        for i in range(len(data)):
            data[i] = 0
        del data  # Delete the reference to the bytearray
    elif isinstance(data, str):
        ctypes.memset(id(data), 0, len(data))
        del data  # Delete the reference to the string

class TextEncryptorApp(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        # Labels with HTML formatting
        self.input_label = QLabel("<b>Input Text</b> (Rich Text Supported):")
        self.output_label = QLabel("<b>Output Text:</b>")
        self.passphrase_label = QLabel("<b>Enter Your Secret Key:</b>")

        # Set font size and apply styles to the labels
        font = self.input_label.font()
        font.setPointSize(10)
        self.input_label.setFont(font)
        self.output_label.setFont(font)
        self.passphrase_label.setFont(font)

        # Text areas
        self.input_text = QTextEdit()
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)

        # Passphrase input
        self.passphrase_input = QTextEdit()
        self.passphrase_input.setMaximumHeight(50)
        self.passphrase_input.setMinimumHeight(50)
        self.passphrase_input.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.passphrase_input.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.passphrase_input.setLineWrapMode(QTextEdit.NoWrap)

        # Buttons with object names
        self.encrypt_button = QPushButton("Encrypt")
        self.decrypt_button = QPushButton("Decrypt")
        self.clear_button = QPushButton("Clear")
        self.paste_button = QPushButton("Paste")
        self.copy_button = QPushButton("Copy")

        # Set object names for buttons to apply specific styles
        self.copy_button.setObjectName("copy_button")
        self.paste_button.setObjectName("paste_button")
        self.clear_button.setObjectName("clear_button")

        # Connect buttons to functions
        self.encrypt_button.clicked.connect(self.handle_encrypt)
        self.decrypt_button.clicked.connect(self.handle_decrypt)
        self.clear_button.clicked.connect(self.clear_fields)
        self.paste_button.clicked.connect(self.paste_input)
        self.copy_button.clicked.connect(self.copy_output)

        # Layouts
        main_layout = QVBoxLayout()

        # Input Layout
        input_layout = QHBoxLayout()
        input_layout.addWidget(self.input_label)
        input_layout.addStretch()
        input_layout.addWidget(self.paste_button)
        main_layout.addLayout(input_layout)
        main_layout.addWidget(self.input_text)

        # Passphrase Layout
        passphrase_layout = QHBoxLayout()
        passphrase_layout.addWidget(self.passphrase_label)
        passphrase_layout.addWidget(self.passphrase_input)
        main_layout.addLayout(passphrase_layout)

        # Button Layout
        button_layout = QHBoxLayout()
        button_layout.addWidget(self.encrypt_button)
        button_layout.addWidget(self.decrypt_button)
        button_layout.addWidget(self.clear_button)
        main_layout.addLayout(button_layout)

        # Output Layout
        output_layout = QHBoxLayout()
        output_layout.addWidget(self.output_label)
        output_layout.addStretch()
        output_layout.addWidget(self.copy_button)
        main_layout.addLayout(output_layout)
        main_layout.addWidget(self.output_text)

        # Message Label
        self.message_label = QLabel("")
        self.message_label.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(self.message_label)

        # Footer Layout
        footer_layout = QHBoxLayout()
        footer_left = QLabel("Made by: Sharad Verma")
        footer_right = QLabel("Version: 1.0")
        
        font = footer_left.font()
        font.setFamily("Courier")
        font.setPointSize(8)
        footer_left.setFont(font)
        footer_right.setFont(font)

        footer_left.setStyleSheet("color: gray;")
        footer_right.setStyleSheet("color: gray;")
        footer_layout.addWidget(footer_left)
        footer_layout.addStretch()
        footer_layout.addWidget(footer_right)

        main_layout.addLayout(footer_layout)

        # Set layout
        self.setLayout(main_layout)
        self.setWindowTitle("Text Encryptor and Decryptor")
        self.setMinimumSize(600, 400)
        self.resize(800, 600)

        # Apply rounded styles and colors to buttons
        self.setStyleSheet("""
            QTextEdit, QPushButton {
                border-radius: 10px;  /* Rounded corners */
            }
            QPushButton {
                color: white;  /* White text color */
                border: none;  /* Remove borders */
                padding: 10px 20px;  /* Padding inside buttons */
                font-size: 15px;  /* Adjust font size */
            }
            /* Default button background */
            QPushButton {
                background-color: #4CAF50;  /* Green background for buttons */
            }
            QPushButton:hover {
                background-color: #45a049;  /* Darker green on hover */
            }
            /* Blue buttons (Copy & Paste) */
            QPushButton#copy_button, QPushButton#paste_button {
                background-color: #2196F3;  /* Blue background */
            }
            QPushButton#copy_button:hover, QPushButton#paste_button:hover {
                background-color: #0b7dda;  /* Darker blue on hover */
            }
            /* Red button (Clear) */
            QPushButton#clear_button {
                background-color: #f44336;  /* Red background */
            }
            QPushButton#clear_button:hover {
                background-color: #e53935;  /* Darker red on hover */
            }
            QTextEdit {
                border: 1px solid #ccc;  /* Light border color */
                padding: 10px;  /* Padding inside the text edit box */
                font-size: 16px;  /* Font size set to 16 */
            }
        """)

    def show_message(self, message, success=True):
        if success:
            self.message_label.setStyleSheet("color: green;")
        else:
            self.message_label.setStyleSheet("color: red;")
        self.message_label.setText(message)
        QTimer.singleShot(5000, lambda: self.message_label.clear())

    def handle_encrypt(self):
        text = self.input_text.toHtml().strip()  # Extract HTML from QTextEdit
        passphrase = self.passphrase_input.toPlainText().strip()
        if text and passphrase:
            encrypted = encrypt_text(text, passphrase)
            self.output_text.setText(encrypted)
            self.show_message("Encrypted successfully!")
            secure_clear(text)  # Securely clear sensitive data
        else:
            self.show_message("Please enter text and a secret key.", success=False)

    def handle_decrypt(self):
        text = self.input_text.toPlainText().strip()
        passphrase = self.passphrase_input.toPlainText().strip()
        if text and passphrase:
            decrypted = decrypt_text(text, passphrase)
            if decrypted:
                self.output_text.setHtml(decrypted)  # Restore HTML in QTextEdit
                self.show_message("Decrypted successfully!")
            else:
                self.show_message("Invalid encrypted text or secret key.", success=False)
            secure_clear(text)  # Securely clear sensitive data
        else:
            self.show_message("Please enter text and a secret key.", success=False)

    def clear_fields(self):
        self.input_text.clear()
        self.output_text.clear()
        self.passphrase_input.clear()
        self.show_message("Fields cleared!")

    def paste_input(self):
        try:
            clipboard_text = pyperclip.paste()
            self.input_text.setText(clipboard_text)
            self.show_message("Text pasted successfully!")
        except Exception as e:
            self.show_message(f"Could not paste text: {e}", success=False)

    def copy_output(self):
        try:
            output_text = self.output_text.toPlainText()
            pyperclip.copy(output_text)
            self.show_message("Output text copied to clipboard!")
        except Exception as e:
            self.show_message(f"Could not copy text: {e}", success=False)

    # Override close event to secure clear sensitive data
    def closeEvent(self, event):
        self.clear_sensitive_data_on_exit()
        event.accept()  # Proceed with closing the app

    def clear_sensitive_data_on_exit(self):
        # Securely clear memory before exiting
        self.secure_clear(self.passphrase_input.toPlainText())  # Clear passphrase input
        self.secure_clear(self.input_text.toPlainText())  # Clear input text
        self.secure_clear(self.output_text.toPlainText())  # Clear output text
        self.secure_clear(self.passphrase_input)  # Clear widget reference
        self.secure_clear(self.input_text)  # Clear widget reference
        self.secure_clear(self.output_text)  # Clear widget reference

# Run the application
if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = TextEncryptorApp()
    window.show()
    sys.exit(app.exec_())
