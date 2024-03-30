import tkinter as tk
from tkinter import filedialog
from tkinter import messagebox
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
import os

#Doing as a test

def browse_file(entry):
    file_path = filedialog.askopenfilename()
    entry.delete(0, tk.END)
    entry.insert(0, file_path)

def encrypt_file():
    # Auto-generate a random key (32 bytes for AES-256)
    key = get_random_bytes(32)

    # Get the file path from the entry widget
    plain_file_path = plain_file_entry.get()
    if not plain_file_path:
        messagebox.showerror("Error", "Please select a file to encrypt.")
        return

    # Read the content of the file
    try:
        with open(plain_file_path, 'rb') as f:
            plaintext = f.read()
    except Exception as e:
        messagebox.showerror("Error", f"Could not read file: {e}")
        return

    # Create a new AES cipher object with a random IV
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Encrypt the plaintext
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

    # Write the IV and the ciphertext to a file
    encrypted_file_path = filedialog.asksaveasfilename(defaultextension=".bin",
                                                       filetypes=[("Binary files", "*.bin")],
                                                       title="Save the encrypted file")
    if encrypted_file_path:
        try:
            with open(encrypted_file_path, 'wb') as f:
                f.write(iv + ciphertext)  
            messagebox.showinfo("Success", "File encrypted successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Could not write encrypted file: {e}")
            return
    else:
        messagebox.showwarning("Warning", "Encryption cancelled. Encrypted file was not saved.")
        return

    # Suggest the user to save the key
    key_file_path = filedialog.asksaveasfilename(defaultextension=".key",
                                                  filetypes=[("Key Files", "*.key")],
                                                  title="Save the encryption key")
    if key_file_path:
        try:
            with open(key_file_path, 'wb') as key_file:
                key_file.write(key)
            messagebox.showinfo("Success", "Encryption key saved. Keep it secure!")
        except Exception as e:
            messagebox.showerror("Error", f"Could not write key file: {e}")
            return
    else:
        messagebox.showwarning("Warning", "Key not saved. You will need the key to decrypt your file.")
        return

def decrypt_file():
    # Get the file paths from the entry widgets
    encrypted_file_path = encrypted_file_entry.get()
    key_file_path = key_entry.get()

    if not encrypted_file_path or not key_file_path:
        messagebox.showerror("Error", "Please select both the encrypted file and the key.")
        return

    # Load the key from the key file
    try:
        with open(key_file_path, 'rb') as key_file:
            key = key_file.read()
    except Exception as e:
        messagebox.showerror("Error", f"Could not read key file: {e}")
        return

    # Check key length for AES-256
    if len(key) != 32:
        messagebox.showerror("Error", "The key is not valid for AES-256.")
        return

    # Load the encrypted data from the file
    try:
        with open(encrypted_file_path, 'rb') as f:
            iv_and_ciphertext = f.read()
    except Exception as e:
        messagebox.showerror("Error", f"Could not read encrypted file: {e}")
        return

    # Extract the IV and the ciphertext
    iv = iv_and_ciphertext[:AES.block_size]
    ciphertext = iv_and_ciphertext[AES.block_size:]

    # Create a new AES cipher object
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Decrypt and unpad the plaintext
    try:
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    except ValueError as e:
        messagebox.showerror("Error", "Incorrect decryption. The key may be wrong or the file corrupted.")
        return

    # Save the decrypted plaintext to a new file
    decrypted_file_path = filedialog.asksaveasfilename(defaultextension=".*",
                                                   filetypes=[("All files", "*.*")],
                                                   title="Save the decrypted file")
    if decrypted_file_path:
        try:
            with open(decrypted_file_path, 'wb') as f:
                f.write(plaintext)
            messagebox.showinfo("Success", "File decrypted successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Could not write decrypted file: {e}")
            return
    else:
        messagebox.showwarning("Warning", "Decryption cancelled. Decrypted file was not saved.")


app = tk.Tk()
app.title('File Encryptor/Decryptor')

frame = tk.Frame(app)
frame.pack(padx=10, pady=10)

# Field for selecting plain file
tk.Label(frame, text="Plain file:").grid(row=0, column=0, sticky='w')
plain_file_entry = tk.Entry(frame, width=50)
plain_file_entry.grid(row=0, column=1)
tk.Button(frame, text="Browse", command=lambda: browse_file(plain_file_entry)).grid(row=0, column=2)

# Encrypt button
encrypt_button = tk.Button(frame, text="Encrypt", command=encrypt_file)
encrypt_button.grid(row=1, columnspan=3, pady=5)

# Field for selecting encrypted file
tk.Label(frame, text="Encrypted file:").grid(row=2, column=0, sticky='w')
encrypted_file_entry = tk.Entry(frame, width=50)
encrypted_file_entry.grid(row=2, column=1)
tk.Button(frame, text="Browse", command=lambda: browse_file(encrypted_file_entry)).grid(row=2, column=2)

# Field for selecting key for decryption
tk.Label(frame, text="Key:").grid(row=3, column=0, sticky='w')
key_entry = tk.Entry(frame, width=50)
key_entry.grid(row=3, column=1)
tk.Button(frame, text="Browse", command=lambda: browse_file(key_entry)).grid(row=3, column=2)

# Decrypt button
decrypt_button = tk.Button(frame, text="Decrypt", command=decrypt_file)
decrypt_button.grid(row=4, columnspan=3, pady=5)

app.mainloop()
