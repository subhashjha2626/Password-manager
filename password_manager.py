import pickle
import re as regex
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os
import string
import random
import tkinter as tk
from tkinter import messagebox

BLOCK_SIZE = 16  # AES block size

# Caesar cipher encryption
def caesar_encrypt(data, key):
    encrypted_text = ""
    for char in data:
        if char.isalpha():
            shift = ord(char.lower()) - ord('a')
            encrypted_char = chr(((shift + key) % 26) + ord('a'))
            encrypted_text += encrypted_char.upper() if char.isupper() else encrypted_char
        else:
            encrypted_text += char
    return encrypted_text

# Caesar cipher decryption
def caesar_decrypt(encrypted_data, key):
    decrypted_text = ""
    for char in encrypted_data:
        if char.isalpha():
            shift = ord(char.lower()) - ord('a')
            decrypted_char = chr(((shift - key) % 26) + ord('a'))
            decrypted_text += decrypted_char.upper() if char.isupper() else decrypted_char
        else:
            decrypted_text += char
    return decrypted_text

# AES encryption
def aes_encrypt(data, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data.encode('utf-8'), BLOCK_SIZE))
    return cipher.iv + ct_bytes

# AES decryption
def aes_decrypt(encrypted_data, key):
    iv = encrypted_data[:BLOCK_SIZE]
    ct = encrypted_data[BLOCK_SIZE:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(ct), BLOCK_SIZE).decode('utf-8')
    return decrypted_data

# Store password with given Caesar and AES keys
def store_password(service_name, username, password, caesar_key, aes_key, file_path="encrypted_passwords.dat"):
    encrypted_username = aes_encrypt(caesar_encrypt(username, caesar_key), aes_key)
    encrypted_password = aes_encrypt(caesar_encrypt(password, caesar_key), aes_key)

    with open(file_path, "ab") as file:
        pickle.dump((service_name, caesar_key, aes_key, encrypted_username, encrypted_password), file)
    print("Password stored successfully!")

# Tkinter GUI
def main_gui():
    def encrypt_password():
        service_name = entry_service.get()
        username = entry_username.get()
        password = entry_password.get()
        caesar_key = int(entry_caesar.get())

        aes_key = os.urandom(16)

        if service_name and username and password and caesar_key:
            store_password(service_name, username, password, caesar_key, aes_key)
            messagebox.showinfo("Success", "Password stored successfully!")
        else:
            messagebox.showerror("Error", "Please fill all fields.")

    # Create window
    window = tk.Tk()
    window.title("Password Manager")

    # Labels
    tk.Label(window, text="Service Name:").grid(row=0)
    tk.Label(window, text="Username:").grid(row=1)
    tk.Label(window, text="Password:").grid(row=2)
    tk.Label(window, text="Caesar Key:").grid(row=3)

    # Entries
    entry_service = tk.Entry(window, width=30)
    entry_username = tk.Entry(window, width=30)
    entry_password = tk.Entry(window, width=30)
    entry_caesar = tk.Entry(window, width=30)

    entry_service.grid(row=0, column=1)
    entry_username.grid(row=1, column=1)
    entry_password.grid(row=2, column=1)
    entry_caesar.grid(row=3, column=1)

    # Buttons
    tk.Button(window, text="Store Password", command=encrypt_password).grid(row=4, column=0, pady=4)

    window.mainloop()

# Main
if __name__ == "__main__":
    main_gui()
