import tkinter as tk
from tkinter import filedialog, messagebox, ttk, simpledialog
from ttkthemes import ThemedTk
from PIL import Image
import cv2
import hashlib
import shutil
import os
import base64
from cryptography.fernet import Fernet
import random

class SteganographyApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Steganography Tool")
        self.root.geometry("600x450")
        self.root.resizable(False, False)

        # UI Theme
        self.style = ttk.Style()
        self.style.theme_use("radiance")

        # Title
        self.label = ttk.Label(root, text="Secure Steganography Tool", font=("Arial", 16, "bold"))
        self.label.pack(pady=20)

        # Quote
        self.quote_label = ttk.Label(root, text=self.get_random_quote(), font=("Arial", 10, "italic"))
        self.quote_label.pack(pady=10)

        # Buttons
        self.encrypt_btn = ttk.Button(root, text="Encrypt Message", command=self.encrypt_message)
        self.encrypt_btn.pack(pady=10, ipadx=10)

        self.decrypt_btn = ttk.Button(root, text="Decrypt Message", command=self.decrypt_message)
        self.decrypt_btn.pack(pady=10, ipadx=10)

        self.exit_btn = ttk.Button(root, text="Exit", command=root.quit)
        self.exit_btn.pack(pady=10, ipadx=10)

    def get_random_quote(self):
        quotes = [
            "“The world is a dangerous place, not because of those who do evil, but because of those who look on and do nothing.” – Mr. Robot",
            "“Control is an illusion.” – Mr. Robot",
            "“People always make the best exploits.” – Mr. Robot",
            "“When you see a good move, look for a better one.” – Mr. Robot",
            "“We are all living in each other’s paranoia.” – Mr. Robot"
        ]
        return random.choice(quotes)

    def derive_key(self, user_key):
        """Creates a consistent key from user input."""
        hashed_key = hashlib.sha256(user_key.encode()).digest()[:32]  # Consistent 32-byte key
        return base64.urlsafe_b64encode(hashed_key)  # Convert to Fernet key

    def text_to_bin(self, text):
        return ''.join(format(ord(i), '08b') for i in text)

    def bin_to_text(self, binary):
        binary_values = [binary[i:i+8] for i in range(0, len(binary), 8)]
        ascii_characters = [chr(int(bv, 2)) for bv in binary_values]
        return ''.join(ascii_characters)

    def encode_image(self, image_path, data, save_path):
        img = cv2.imread(image_path)
        if img is None:
            messagebox.showerror("Error", "Invalid image format!")
            return
        data_bin = self.text_to_bin(data) + '1111111111111110'  # End marker
        img_flat = img.flatten()

        if len(data_bin) > len(img_flat):
            messagebox.showerror("Error", "Message is too large for this image!")
            return

        for i in range(len(data_bin)):
            img_flat[i] = (img_flat[i] & 0xFE) | int(data_bin[i])  # Embed in LSB

        img_encoded = img_flat.reshape(img.shape)
        cv2.imwrite(save_path, img_encoded)

    def decode_image(self, image_path):
        img = cv2.imread(image_path)
        if img is None:
            messagebox.showerror("Error", "Invalid image format!")
            return ""
        img_flat = img.flatten()

        binary_data = ''
        for i in range(len(img_flat)):
            binary_data += str(img_flat[i] & 1)

        binary_data = binary_data.split('1111111111111110')[0]  # Stop at end marker
        return self.bin_to_text(binary_data)

    def encrypt_message(self):
        file_path = filedialog.askopenfilename(title="Select Image",
                                               filetypes=[("Image Files", "*.png *.jpg *.jpeg *.heic")])
        if not file_path:
            return

        message = simpledialog.askstring("Input", "Enter the message to hide:", parent=self.root)
        if not message:
            return

        user_key = simpledialog.askstring("Input", "Enter a secret key:", parent=self.root)
        if not user_key:
            messagebox.showerror("Error", "Key cannot be empty!")
            return

        save_path = filedialog.asksaveasfilename(defaultextension=".png",
                                                 filetypes=[("PNG Files", "*.png")],
                                                 title="Save Encrypted Image")
        if not save_path:
            return

        try:
            shutil.copy(file_path, save_path)  # Preserve original

            cipher_key = self.derive_key(user_key)
            cipher = Fernet(cipher_key)
            encrypted_msg = cipher.encrypt(message.encode())

            # Convert to Base64 for safe storage in image
            encrypted_msg_b64 = base64.b64encode(encrypted_msg).decode()

            self.encode_image(save_path, encrypted_msg_b64, save_path)
            messagebox.showinfo("Success", "Message encrypted and saved in the image!")
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")

    def decrypt_message(self):
        file_path = filedialog.askopenfilename(title="Select Image",
                                               filetypes=[("Image Files", "*.png *.jpg *.jpeg *.heic")])
        if not file_path:
            return

        user_key = simpledialog.askstring("Input", "Enter the secret key:", parent=self.root)
        if not user_key:
            messagebox.showerror("Error", "Key cannot be empty!")
            return

        try:
            cipher_key = self.derive_key(user_key)
            cipher = Fernet(cipher_key)

            hidden_data = self.decode_image(file_path)

            # Decode from Base64
            encrypted_msg = base64.b64decode(hidden_data.encode())

            decrypted_msg = cipher.decrypt(encrypted_msg).decode()
            messagebox.showinfo("Decrypted Message", f"Hidden Message:\n\n{decrypted_msg}")
        except Exception as e:
            messagebox.showerror("Error", "Decryption failed! Wrong key or corrupted image.")

# Run the GUI
root = ThemedTk(theme="radiance")
app = SteganographyApp(root)
root.mainloop()
