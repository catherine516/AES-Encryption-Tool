# Usage:
# 1. Install dependencies: pip install cryptography
# 2. Run the app: python main.py
#    (Make sure you are in the project directory.)

import tkinter as tk
from tkinter import ttk, messagebox
from utils.crypto import encrypt_file, decrypt_file, select_file, select_save_file
import hashlib
from PIL import ImageGrab
import time

def derive_key_from_password(password):
    return hashlib.sha256(password.encode('utf-8')).digest()

def take_app_screenshot(root, filename="output_screenshot.png"):
    # Wait for the GUI to update
    root.update_idletasks()
    root.update()
    # Get window coordinates
    x = root.winfo_rootx()
    y = root.winfo_rooty()
    w = x + root.winfo_width()
    h = y + root.winfo_height()
    # Small delay to ensure rendering
    time.sleep(0.2)
    img = ImageGrab.grab(bbox=(x, y, w, h))
    img.save(filename)

class AESApp:
    def __init__(self, root):
        self.root = root
        self.root.title("AES-256 File Encryption Tool")
        self.root.geometry("500x420")
        self.root.configure(bg="#f4f6fb")

        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TFrame', background='#f4f6fb')
        style.configure('TLabel', background='#f4f6fb', font=('Segoe UI', 11))
        style.configure('TButton', font=('Segoe UI', 10, 'bold'), padding=6)
        style.configure('Title.TLabel', font=('Segoe UI', 16, 'bold'), foreground='#2d3e50', background='#f4f6fb')
        style.configure('Status.TLabel', font=('Segoe UI', 10), foreground='#2d3e50', background='#eaf0fa')

        # Main frame
        main_frame = ttk.Frame(root, padding=20)
        main_frame.pack(expand=True, fill='both')

        # Title label
        ttk.Label(main_frame, text="AES-256 File Encryption/Decryption", style='Title.TLabel').pack(pady=(0, 15))

        # Password frame
        pw_frame = ttk.Frame(main_frame)
        pw_frame.pack(fill='x', pady=5)
        ttk.Label(pw_frame, text="Password:").pack(side='left', padx=(0, 8))
        self.password_entry = ttk.Entry(pw_frame, show="*", width=30)
        self.password_entry.pack(side='left', fill='x', expand=True)

        # Button frame
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(pady=20)
        ttk.Button(btn_frame, text="Encrypt File", width=16, command=self.encrypt_action).pack(side='left', padx=10)
        ttk.Button(btn_frame, text="Decrypt File", width=16, command=self.decrypt_action).pack(side='left', padx=10)

        # Status/output display frame
        status_frame = ttk.Frame(main_frame)
        status_frame.pack(fill='x', pady=(10, 0))
        self.status_text = tk.StringVar()
        self.status_label = ttk.Label(status_frame, textvariable=self.status_text, style='Status.TLabel', anchor='w', background='#eaf0fa', relief='groove')
        self.status_label.pack(fill='x', padx=2, pady=2, ipady=8)

        # Log panel (console)
        log_frame = ttk.LabelFrame(main_frame, text="Console / Log", padding=(8, 4))
        log_frame.pack(fill='both', expand=True, pady=(12, 0))
        self.log_text = tk.Text(log_frame, height=7, bg="#23272e", fg="#eaf0fa", font=("Consolas", 10), relief='flat', wrap='word')
        self.log_text.pack(fill='both', expand=True)
        self.log_text.config(state='disabled')

    def log(self, message):
        self.log_text.config(state='normal')
        self.log_text.insert('end', message + '\n')
        self.log_text.see('end')
        self.log_text.config(state='disabled')

    def encrypt_action(self):
        password = self.password_entry.get()
        if not password:
            self.status_text.set("Please enter a password.")
            self.log("No password entered for encryption.")
            return
        key = derive_key_from_password(password)
        input_path = select_file("Select file to encrypt")
        if not input_path:
            self.status_text.set("Encryption cancelled.")
            self.log("Encryption cancelled: No input file selected.")
            return
        self.log(f"Selected file for encryption: {input_path}")
        output_path = select_save_file("Save encrypted file as")
        if not output_path:
            self.status_text.set("Encryption cancelled.")
            self.log("Encryption cancelled: No output file selected.")
            return
        self.log(f"Output file for encrypted data: {output_path}")
        try:
            encrypt_file(input_path, output_path, key)
            self.status_text.set(f"File encrypted successfully:\n{output_path}")
            self.log(f"Encryption successful: {output_path}")
            take_app_screenshot(self.root, "output_screenshot.png")
        except Exception as e:
            self.status_text.set(f"Encryption failed: {e}")
            self.log(f"Encryption failed: {e}")

    def decrypt_action(self):
        password = self.password_entry.get()
        if not password:
            self.status_text.set("Please enter a password.")
            self.log("No password entered for decryption.")
            return
        key = derive_key_from_password(password)
        input_path = select_file("Select file to decrypt")
        if not input_path:
            self.status_text.set("Decryption cancelled.")
            self.log("Decryption cancelled: No input file selected.")
            return
        self.log(f"Selected file for decryption: {input_path}")
        output_path = select_save_file("Save decrypted file as")
        if not output_path:
            self.status_text.set("Decryption cancelled.")
            self.log("Decryption cancelled: No output file selected.")
            return
        self.log(f"Output file for decrypted data: {output_path}")
        try:
            decrypt_file(input_path, output_path, key)
            self.status_text.set(f"File decrypted successfully:\n{output_path}")
            self.log(f"Decryption successful: {output_path}")
            take_app_screenshot(self.root, "output_screenshot.png")
        except Exception as e:
            self.status_text.set(f"Decryption failed: {e}")
            self.log(f"Decryption failed: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = AESApp(root)
    root.mainloop()