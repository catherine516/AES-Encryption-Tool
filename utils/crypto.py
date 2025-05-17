import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import tkinter as tk
from tkinter import filedialog
import base64

def encrypt_file(input_path, output_path, key):
    # Ensure key is 32 bytes (256 bits)
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes (256 bits) for AES-256.")

    # Generate a secure random 16-byte IV
    iv = os.urandom(16)

    # Read plaintext data
    with open(input_path, 'rb') as f:
        plaintext = f.read()

    # Pad plaintext to block size (AES block size is 128 bits = 16 bytes)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()

    # Create AES-256 cipher in CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # Write IV + ciphertext to output file
    with open(output_path, 'wb') as f:
        f.write(iv + ciphertext)

def decrypt_file(input_path, output_path, key):
    # Ensure key is 32 bytes (256 bits)
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes (256 bits) for AES-256.")

    # Read IV + ciphertext from input file
    with open(input_path, 'rb') as f:
        iv = f.read(16)
        ciphertext = f.read()

    # Create AES-256 cipher in CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Unpad plaintext
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    # Write plaintext to output file
    with open(output_path, 'wb') as f:
        f.write(plaintext)

def generate_key():
    """Generate a secure random 32-byte (256-bit) AES key."""
    return os.urandom(32)

def save_key(key, filepath):
    """Save the key to a file in base64 encoding."""
    with open(filepath, 'wb') as f:
        f.write(base64.b64encode(key))

def load_key(filepath):
    """Load the key from a file (base64 encoded)."""
    with open(filepath, 'rb') as f:
        key = base64.b64decode(f.read())
    if len(key) != 32:
        raise ValueError("Loaded key is not 32 bytes (256 bits).")
    return key

def select_file(title="Select a file"):
    """Open a file dialog to select a file and return its path."""
    root = tk.Tk()
    root.withdraw()
    file_path = filedialog.askopenfilename(title=title)
    root.destroy()
    return file_path

def select_save_file(title="Select output file"):
    """Open a file dialog to select a file path for saving and return its path."""
    root = tk.Tk()
    root.withdraw()
    file_path = filedialog.asksaveasfilename(title=title)
    root.destroy()
    return file_path
