# CryptologyCommunication

A Python-based GUI application that allows users to securely hide and retrieve encrypted messages within images using steganography and AES-based encryption.

## Features

- **Encrypt and Hide Messages**: Users can input a message and a secret key to encrypt the message and hide it inside an image file.
- **Decrypt and Retrieve Messages**: Encrypted messages hidden within images can be extracted and decrypted using the correct secret key.
- **User-friendly GUI**: Built using `Tkinter` with themes from `ttkthemes` for an intuitive interface.
- **Random Security Quotes**: The app shows random security quotes from the show *Mr. Robot* to add some inspiration!

## Installation

1. **Clone the repository:**

    ```bash
    git clone https://github.com/santhoshagain/CryptologyCommunication.git
    cd steganography-app
    ```

2. **Install dependencies:**

    Install the required Python libraries using `pip`:

    ```bash
    pip install librarie name
    ```

    The dependencies include:
    - `tkinter` for GUI
    - `ttkthemes` for themed UI
    - `Pillow` for image handling
    - `opencv-python` (`cv2`) for image processing
    - `cryptography` for encryption and decryption

## Usage

1. **Run the application:**

    ```bash
    python app.py
    ```

2. **Encrypting a message:**
    - Select an image file to hide the message.
    - Enter the message and a secret key.
    - Save the newly generated image containing the encrypted message.

3. **Decrypting a message:**
    - Select the image that contains the hidden message.
    - Enter the secret key used during encryption.
    - View the decrypted message if the key is correct.

## How It Works

- **Encryption**: Messages are encrypted using a key derived from the user-provided passphrase using SHA-256 hashing. The message is then encrypted using the AES algorithm (via `cryptography.Fernet`).
- **Steganography**: The encrypted message is embedded within the least significant bits (LSB) of the image's pixel values. A special end marker (`1111111111111110`) is used to mark the end of the hidden message.
- **Decryption**: The encrypted message is extracted from the image's pixel data, decrypted using the correct secret key, and converted back to readable text.

## Requirements

- Python 3.x
- The libraries listed 

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Inspired by *Mr. Robot* quotes.
