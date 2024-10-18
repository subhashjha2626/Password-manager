import pickle
import re as regex
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os
import string
import random
import tkinter as tk
from tkinter import messagebox

BLOCK_SIZE = 16  #AES block size

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

# Check password strength
def check_password_strength(password):
    length_regex = r'.{8,}'
    uppercase_regex = r'[A-Z]'
    lowercase_regex = r'[a-z]'
    digit_regex = r'\d'
    special_char_regex = r'[^A-Za-z0-9]'

    if not regex.search(length_regex, password):
        return "Password should be at least 8 characters long."
    if not regex.search(uppercase_regex, password):
        return "Password should contain at least one uppercase letter."
    if not regex.search(lowercase_regex, password):
        return "Password should contain at least one lowercase letter."
    if not regex.search(digit_regex, password):
        return "Password should contain at least one digit."
    if not regex.search(special_char_regex, password):
        return "Password should contain at least one special character."

    return "Password is strong!"

# Generate random password
def generate_password(length=12, include_special=True):
    chars = string.ascii_letters + string.digits
    if include_special:
        chars += string.punctuation
    return ''.join(random.choice(chars) for _ in range(length))

# Store password with given Caesar and AES keys
def store_password(service_name, username, password, caesar_key, aes_key, file_path="encrypted_passwords.dat"):
    encrypted_username = aes_encrypt(caesar_encrypt(username, caesar_key), aes_key)
    encrypted_password = aes_encrypt(caesar_encrypt(password, caesar_key), aes_key)

    # Store both keys along with the encrypted data
    with open(file_path, "ab") as file:
        pickle.dump((service_name, caesar_key, aes_key, encrypted_username, encrypted_password), file)
    print("Password stored successfully!")

# Decrypt passwords using a specific Caesar key
def decrypt_passwords(caesar_key, file_path="encrypted_passwords.dat"):
    try:
        with open(file_path, "rb") as file:
            found = False
            while True:
                try:
                    # Load stored password information
                    service_name, stored_caesar_key, stored_aes_key, encrypted_username, encrypted_password = pickle.load(file)

                    # Only decrypt if the Caesar key matches
                    if stored_caesar_key == caesar_key:
                        decrypted_username = caesar_decrypt(aes_decrypt(encrypted_username, stored_aes_key), caesar_key)
                        decrypted_password = caesar_decrypt(aes_decrypt(encrypted_password, stored_aes_key), caesar_key)

                        print(f"\nService: {service_name}")
                        print(f"Username: {decrypted_username}")
                        print(f"Password: {decrypted_password}")
                        found = True

                except EOFError:
                    break

            if not found:
                print("No passwords found with the provided key.")
    except FileNotFoundError:
        print("No passwords file found.")

# Get a Caesar cipher key from the user
def get_caesar_key():
    while True:
        try:
            return int(input("Enter your Caesar cipher key (an integer): "))
        except ValueError:
            print("Invalid key. Please enter an integer.")

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

    def decrypt_password():
        caesar_key = int(entry_caesar.get())
        if caesar_key:
            decrypt_passwords(caesar_key)
        else:
            messagebox.showerror("Error", "Please provide Caesar key.")

    def check_strength():
        password = entry_password.get()
        result = check_password_strength(password)
        messagebox.showinfo("Password Strength", result)

    def generate_new_password():
        new_password = generate_password(length=16)
        entry_password.delete(0, tk.END)
        entry_password.insert(0, new_password)

    # Create window
    window = tk.Tk()
    window.title("Password Manager")

    # Labels
    tk.Label(window, text="Service Name:").grid(row=0)
    tk.Label(window, text="Username:").grid(row=1)
    tk.Label(window, text="Password:").grid(row=2)
    tk.Label(window, text="Caesar Key:").grid(row=3)

    # Entries with increased width
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
    tk.Button(window, text="Decrypt Password", command=decrypt_password).grid(row=4, column=1, pady=4)
    tk.Button(window, text="Check Password Strength", command=check_strength).grid(row=5, column=0, pady=4)
    tk.Button(window, text="Generate Password", command=generate_new_password).grid(row=5, column=1, pady=4)

    window.mainloop()

# Main
if __name__ == "__main__":
    main_gui()
























































































# import pickle
# import re as regex
# from Crypto.Cipher import AES
# from Crypto.Util.Padding import pad, unpad
# import os
# import string
# import random
# import tkinter as tk
# from tkinter import messagebox

# BLOCK_SIZE = 16  # AES block size

# # Caesar cipher encryption
# def caesar_encrypt(data, key):
#     encrypted_text = ""
#     for char in data:
#         if char.isalpha():
#             shift = ord(char.lower()) - ord('a')
#             encrypted_char = chr(((shift + key) % 26) + ord('a'))
#             encrypted_text += encrypted_char.upper() if char.isupper() else encrypted_char
#         else:
#             encrypted_text += char
#     return encrypted_text

# # Caesar cipher decryption
# def caesar_decrypt(encrypted_data, key):
#     decrypted_text = ""
#     for char in encrypted_data:
#         if char.isalpha():
#             shift = ord(char.lower()) - ord('a')
#             decrypted_char = chr(((shift - key) % 26) + ord('a'))
#             decrypted_text += decrypted_char.upper() if char.isupper() else decrypted_char
#         else:
#             decrypted_text += char
#     return decrypted_text

# # AES encryption
# def aes_encrypt(data, key):
#     cipher = AES.new(key, AES.MODE_CBC)
#     ct_bytes = cipher.encrypt(pad(data.encode('utf-8'), BLOCK_SIZE))
#     return cipher.iv + ct_bytes

# # AES decryption
# def aes_decrypt(encrypted_data, key):
#     iv = encrypted_data[:BLOCK_SIZE]
#     ct = encrypted_data[BLOCK_SIZE:]
#     cipher = AES.new(key, AES.MODE_CBC, iv)
#     decrypted_data = unpad(cipher.decrypt(ct), BLOCK_SIZE).decode('utf-8')
#     return decrypted_data

# # Check password strength
# def check_password_strength(password):
#     length_regex = r'.{8,}'
#     uppercase_regex = r'[A-Z]'
#     lowercase_regex = r'[a-z]'
#     digit_regex = r'\d'
#     special_char_regex = r'[^A-Za-z0-9]'

#     if not regex.search(length_regex, password):
#         return "Password should be at least 8 characters long."
#     if not regex.search(uppercase_regex, password):
#         return "Password should contain at least one uppercase letter."
#     if not regex.search(lowercase_regex, password):
#         return "Password should contain at least one lowercase letter."
#     if not regex.search(digit_regex, password):
#         return "Password should contain at least one digit."
#     if not regex.search(special_char_regex, password):
#         return "Password should contain at least one special character."

#     return "Password is strong!"

# # Generate random password
# def generate_password(length=12, include_special=True):
#     chars = string.ascii_letters + string.digits
#     if include_special:
#         chars += string.punctuation
#     return ''.join(random.choice(chars) for _ in range(length))

# # Store password with given Caesar and AES keys
# def store_password(service_name, username, password, caesar_key, aes_key, file_path="encrypted_passwords.dat"):
#     encrypted_username = aes_encrypt(caesar_encrypt(username, caesar_key), aes_key)
#     encrypted_password = aes_encrypt(caesar_encrypt(password, caesar_key), aes_key)

#     with open(file_path, "ab") as file:
#         pickle.dump((service_name, caesar_key, aes_key, encrypted_username, encrypted_password), file)
#     print("Password stored successfully!")

# # Decrypt passwords using a specific Caesar key
# def decrypt_passwords(caesar_key, file_path="encrypted_passwords.dat"):
#     try:
#         with open(file_path, "rb") as file:
#             found = False
#             while True:
#                 try:
#                     service_name, stored_caesar_key, stored_aes_key, encrypted_username, encrypted_password = pickle.load(file)

#                     if stored_caesar_key == caesar_key:
#                         decrypted_username = caesar_decrypt(aes_decrypt(encrypted_username, stored_aes_key), caesar_key)
#                         decrypted_password = caesar_decrypt(aes_decrypt(encrypted_password, stored_aes_key), caesar_key)

#                         print(f"\nService: {service_name}")
#                         print(f"Username: {decrypted_username}")
#                         print(f"Password: {decrypted_password}")
#                         found = True

#                 except EOFError:
#                     break

#             if not found:
#                 print("No passwords found with the provided key.")
#     except FileNotFoundError:
#         print("No passwords file found.")

# # Change password for a specific service
# def change_password(service_name, username, new_password, caesar_key, aes_key, file_path="encrypted_passwords.dat"):
#     try:
#         passwords = []
#         found = False
#         with open(file_path, "rb") as file:
#             while True:
#                 try:
#                     entry = pickle.load(file)
#                     passwords.append(entry)
#                 except EOFError:
#                     break

#         # Update the password for the specific service
#         with open(file_path, "wb") as file:
#             for service, stored_caesar_key, stored_aes_key, encrypted_username, encrypted_password in passwords:
#                 if service == service_name and caesar_key == stored_caesar_key:
#                     encrypted_username = aes_encrypt(caesar_encrypt(username, caesar_key), aes_key)
#                     encrypted_password = aes_encrypt(caesar_encrypt(new_password, caesar_key), aes_key)
#                     found = True

#                 pickle.dump((service, stored_caesar_key, stored_aes_key, encrypted_username, encrypted_password), file)

#         if found:
#             print("Password changed successfully!")
#         else:
#             print("Service name or Caesar key does not match.")
#     except FileNotFoundError:
#         print("No passwords file found.")

# # Get a Caesar cipher key from the user
# def get_caesar_key():
#     while True:
#         try:
#             return int(input("Enter your Caesar cipher key (an integer): "))
#         except ValueError:
#             print("Invalid key. Please enter an integer.")

# # Tkinter GUI
# def main_gui():
#     def encrypt_password():
#         service_name = entry_service.get()
#         username = entry_username.get()
#         password = entry_password.get()
#         caesar_key = int(entry_caesar.get())
#         aes_key = os.urandom(16)

#         if service_name and username and password and caesar_key:
#             store_password(service_name, username, password, caesar_key, aes_key)
#             messagebox.showinfo("Success", "Password stored successfully!")
#         else:
#             messagebox.showerror("Error", "Please fill all fields.")

#     def decrypt_password():
#         caesar_key = int(entry_caesar.get())
#         if caesar_key:
#             decrypt_passwords(caesar_key)
#         else:
#             messagebox.showerror("Error", "Please provide Caesar key.")

#     def change_password_ui():
#         service_name = entry_service.get()
#         username = entry_username.get()
#         new_password = entry_password.get()
#         caesar_key = int(entry_caesar.get())

#         if service_name and username and new_password and caesar_key:
#             aes_key = os.urandom(16)  # Generate a new AES key
#             change_password(service_name, username, new_password, caesar_key, aes_key)
#             messagebox.showinfo("Success", "Password changed successfully!")
#         else:
#             messagebox.showerror("Error", "Please fill all fields.")

#     def check_strength():
#         password = entry_password.get()
#         result = check_password_strength(password)
#         messagebox.showinfo("Password Strength", result)

#     def generate_new_password():
#         new_password = generate_password(length=16)
#         entry_password.delete(0, tk.END)
#         entry_password.insert(0, new_password)

#     # Create window
#     window = tk.Tk()
#     window.title("Password Manager")

#     # Labels
#     tk.Label(window, text="Service Name:").grid(row=0)
#     tk.Label(window, text="Username:").grid(row=1)
#     tk.Label(window, text="Password:").grid(row=2)
#     tk.Label(window, text="Caesar Key:").grid(row=3)

#     # Entries with increased width
#     entry_service = tk.Entry(window, width=30)
#     entry_username = tk.Entry(window, width=30)
#     entry_password = tk.Entry(window, width=30)
#     entry_caesar = tk.Entry(window, width=30)

#     entry_service.grid(row=0, column=1)
#     entry_username.grid(row=1, column=1)
#     entry_password.grid(row=2, column=1)
#     entry_caesar.grid(row=3, column=1)

#     # Buttons
#     tk.Button(window, text="Store Password", command=encrypt_password).grid(row=4, column=0, pady=4)
#     tk.Button(window, text="Decrypt Password", command=decrypt_password).grid(row=4, column=1, pady=4)
#     tk.Button(window, text="Change Password", command=change_password_ui).grid(row=4, column=2, pady=4)
#     tk.Button(window, text="Check Password Strength", command=check_strength).grid(row=5, column=0, pady=4)
#     tk.Button(window, text="Generate Password", command=generate_new_password).grid(row=5, column=1, pady=4)

#     window.mainloop()

# # Main
# if __name__ == "__main__":
#     main_gui()
