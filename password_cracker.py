import pickle
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import string
import itertools

BLOCK_SIZE = 16

def aes_decrypt(encrypted_data, key):
    iv = encrypted_data[:BLOCK_SIZE]
    ct = encrypted_data[BLOCK_SIZE:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    try:
        decrypted_data = unpad(cipher.decrypt(ct), BLOCK_SIZE).decode('utf-8')
        return decrypted_data
    except (ValueError, KeyError):
        return None

# Brute-force AES key by trying all combinations
def brute_force_aes(encrypted_username, encrypted_password, key_space):
    for key in key_space:
        try:
            key_bytes = key.encode('utf-8').ljust(16, b'\0')  # Convert key to bytes and pad to 16 bytes
            decrypted_username = aes_decrypt(encrypted_username, key_bytes)
            decrypted_password = aes_decrypt(encrypted_password, key_bytes)
            
            if decrypted_username and decrypted_password:
                print(f"\nSuccess! AES Key: {key}")
                print(f"Decrypted Username: {decrypted_username}")
                print(f"Decrypted Password: {decrypted_password}")
                return key
        except Exception as e:
            continue  # Continue trying with the next key

    print("AES key not found in the provided key space.")
    return None

# Generate key space: try 4-8 character alphanumeric combinations
def generate_key_space():
    chars = string.ascii_letters + string.digits  # Alphanumeric characters
    return (''.join(candidate) for length in range(4, 10) for candidate in itertools.product(chars, repeat=length))

# Load encrypted data from file
def load_encrypted_data(file_path):
    with open(file_path, "rb") as file:
        while True:
            try:
                service_name, caesar_key, aes_key, encrypted_username, encrypted_password = pickle.load(file)
                return encrypted_username, encrypted_password
            except EOFError:
                break
    return None, None

if __name__ == "__main__":
    encrypted_username, encrypted_password = load_encrypted_data("encrypted_passwords.dat")

    if encrypted_username and encrypted_password:
        print("Trying to brute-force AES key...")

        # Generate the key space and attempt brute-force
        key_space = generate_key_space()
        found_key = brute_force_aes(encrypted_username, encrypted_password, key_space)

        if found_key:
            print(f"AES Key Cracked: {found_key}")
        else:
            print("Failed to crack the AES key.")
    else:
        print("No encrypted data found.")
