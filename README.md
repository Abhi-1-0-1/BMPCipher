# BMPCipher

## CS50x Final Project

**BMPCipher** is a Flask web application encryption system that utilizes **BMP files** as cryptographic keys to encrypt text, creating industry-standard, tamper-proof encryption that is virtually unbreakable.

---

## Table of Contents

1. [Overview](#overview)
2. [Usage](#usage)
3. [How It Works And Technical Architecture](#how-it-works-and-technical-architecture)
4. [Project Structure](#project-structure)
5. [Security Features](#security-features)
6. [Technologies Used](#technologies-used)
7. [Future of the Project](#future-of-the-project)
8. [License](#license)
9. [Disclaimer](#disclaimer)
10. [Acknowledgements](#acknowledgements)
11. [Author](#author)

---

## Overview

**BMPCipher** is an advanced encryption tool that converts standard **BMP (Bitmap)** files into robust cryptographic keys. By combining the unique pixel data of the file with a user-provided password, it protects your messages with industry-standard **AES-256-GCM** encryption.

---

## Usage

See the app in use [here](https://youtu.be/NJIcC7HXnbg).
The Flask web application contains two main interfaces for encryption and decryption operations.

### Encrypting a Message

1. Navigate to the **Encrypt** page via the navigation bar or by clicking the **"Get Started"** button on the home page
2. Upload your **BMP file** and enter your chosen **password**
3. Type the **message** you want to encrypt in the text area
4. Click the **"Generate Ciphertext"** button
5. Your encrypted text is **automatically copied** to your clipboard (if not, use the **"Manual Copy"** button)

### Decrypting a Message

1. Navigate to the **Decrypt** page via the navigation bar
2. Upload the **exact same BMP image** used for encryption
3. Enter the **same password** used during encryption
4. Paste the **encrypted ciphertext** into the text area
5. Click the **"Reveal Message"** button
6. Your original message will be displayed (or an error message if credentials are incorrect)

### Important Notes

**Critical Requirements for Successful Decryption:**

- The BMP image must be **byte-for-byte identical** to the original
- The password must be **exactly the same**
- The ciphertext must be **complete and unmodified**

_Any variation in the above will result in decryption failure._

---

## How It Works And Technical Architecture

This web application uses the **Flask framework** in Python, which essentially acts as a link between the server (a Python file named `app.py`) and the client side (HTML files called templates). The front-end, built using **HTML**, **CSS**, and minimal **JavaScript**, acts as the UI for the Python encryption logic, which is the major focus of the application.

### Encryption Process

The core idea of encryption is that traditional encryption uses a password to generate a key. Here, we add an **image fingerprint** derived from a **BMP file**. This means that each image defines a **unique cryptographic identity**. Even with the same password, two different BMPs generate different keys. The same image + password combination can always reproduce the same key.

The following is the step-by-step process of what happens behind the scenes:

#### 1. Image Fingerprinting

- The entire **BMP file**, including the header and pixels, is read as **raw bytes**
- A **SHA-256 hash** is computed, creating a unique **256-bit fingerprint**
  - **SHA-256** (Secure Hash Algorithm - 256-bit) is a **cryptographic hash function** that produces a 32-byte (256-bit) fixed-size fingerprint from any input, regardless of the input size
- This fingerprint serves as part of the **key derivation material**
- **Why BMP images?**
  - BMP files store **raw and uncompressed data**, which makes them perfect for cryptographic encryption
  - Every byte remains **consistent** even when transferred across different platforms
  - Pixel data provides a **high amount of randomness** for unique key generation
  - Unlike popular file extensions like `.png` or `.jpeg`, `.bmp` files don't change due to **compression artifacts**

#### 2. Key Derivation

This is the most critical part of the program, where the **cryptographic key** is derived using **PBKDF2**.

**What is PBKDF2?**

- **Password-Based Key Derivation Function 2** (PBKDF2) is an algorithm that converts passwords into secure cryptographic keys by applying multiple rounds of hashing
- It takes the following inputs:
  - **Algorithm**: The hashing algorithm used (in this case, **SHA-256**)
  - **Length**: The length in bytes of the output encryption key (here, **32 bytes = 256 bits**)
  - **Salt**: A **random 16-byte value** generated uniquely for each encryption operation
    - **Salt** is random data added to the password before hashing to ensure that the same password produces different keys each time
    - It is combined with the **BMP fingerprint** to create salt + fingerprint material
    - This prevents **rainbow table attacks** (precomputed tables of password hashes)
  - **Iterations**: The number of times the hashing process is repeated (here, **100,000 iterations**)
    - More iterations make **brute-force attacks** (trying every possible password) computationally expensive and time-consuming
  - **Password**: The user-provided password encoded as **UTF-8 bytes**
- The output is a **256-bit encryption key** that is unique to your password, the BMP image, and the random salt

#### 3. Message Encryption

Once the key is derived, your message is encrypted using **AES-256-GCM**.

**What is AES-256-GCM?**

- **AES** (Advanced Encryption Standard) is a **symmetric encryption algorithm** used worldwide by governments and organizations
  - **Symmetric** means the same key is used for both encryption and decryption
- **256** refers to the **key size** (256 bits), providing extremely strong security
- **GCM** (Galois/Counter Mode) is an **authenticated encryption mode** that provides both:
  - **Confidentiality**: The message is encrypted and unreadable without the key
  - **Integrity**: Any tampering with the ciphertext is automatically detected

**Encryption Steps:**

- A random **12-byte nonce** (number used once) is generated
  - The **nonce** is an **initialization vector** that ensures the same message encrypted twice produces different ciphertext
- Your message is encoded to **UTF-8 bytes**
- **AES-256-GCM** encrypts the message using the derived key and nonce
- The output includes:
  - **Ciphertext**: Your encrypted message
  - **Authentication tag**: A signature that verifies the data hasn't been tampered with

#### 4. Result Packaging

The final step combines all necessary components for decryption:

- The following components are concatenated (joined together):
  - **Salt** (16 bytes)
  - **Nonce** (12 bytes)
  - **Ciphertext** (variable length, depends on your message)
- This complete **blob** is encoded using **Base64**
  - **Base64** is an encoding scheme that converts binary data into text format for easy transmission and storage
- You receive a single string containing all the information needed for decryption

---

### Decryption Process

Decryption reverses the encryption process to recover your original message.

#### 1. Input Validation and Extraction

- The **Base64-encoded ciphertext** is decoded back into binary data
- The **blob** is split into its three components:
  - **Salt** (first 16 bytes)
  - **Nonce** (next 12 bytes)
  - **Ciphertext** (remaining bytes)

#### 2. Key Reconstruction

- The uploaded **BMP image** is fingerprinted using **SHA-256** (identical to step 1 of encryption)
- The extracted **salt** is combined with the **BMP fingerprint**
- **PBKDF2** is run with:
  - Your provided **password**
  - The combined **salt + fingerprint**
  - The same **100,000 iterations**
  - The same **SHA-256 algorithm**
- If the image and password are correct, this produces the **exact same 256-bit key** used during encryption

#### 3. Message Recovery and Verification

- **AES-256-GCM** decryption is performed using:
  - The reconstructed **key**
  - The extracted **nonce**
  - The extracted **ciphertext**
- The **authentication tag** is automatically verified
  - If the tag matches, the data is **authentic and unmodified**
  - If the tag doesn't match, decryption fails immediately
- If everything is correct:
  - The **plaintext bytes** are decoded from **UTF-8** back into your original message
  - Your message is displayed
- If anything is incorrect (wrong password, wrong image, or tampered data):
  - **AES-GCM** raises an **InvalidTag exception**
  - An explicit **"DECRYPTION FAILED"** error message is displayed

---

**Key Takeaways:**

The security of BMPCipher relies on three factors:

1. **Something you know**: Your password
2. **Something you have**: The exact BMP image file
3. **Cryptographic strength**: Industry-standard algorithms (SHA-256, PBKDF2, AES-256-GCM)

Without all three components matching perfectly, decryption is computationally infeasible.

---

## Project Structure

```
project/
│
├── app.py                 # Main Flask application with encryption logic
├── uploads/               # Temporary folder for uploaded images (auto-cleaned)
│
├── templates/
│   ├── layout.html        # Base template with navigation
│   ├── index.html         # Landing page
│   ├── encrypt.html       # Encryption interface
│   ├── decrypt.html       # Decryption interface
│   └── learn.html         # Educational page
│
└── static/
    └── style.css          # Design and animations
```

---

## Security Features

- **Unique nonces**: A 12-byte random initialization vector is generated for each encryption operation
- Every encryption operation uses **fresh cryptographic material**
- The **authenticated encryption** prevents decryption of tampered or forged messages
- Uploaded images are **automatically deleted** after processing to ensure user privacy

### What BMPCipher Protects Against

- **Password brute-force attacks** (via PBKDF2 stretching)
- **Ciphertext tampering** (authenticated encryption detects modifications)
- **Known-plaintext attacks** (AES-256 security standard)
- **Unauthorized decryption** (requires both correct image and password)
- **Rainbow table attacks** (unique salts prevent precomputed attacks)

### What BMPCipher Does NOT Protect Against

- Compromise of both the BMP image and password together
- Side-channel attacks on the system running the application
- Social engineering to obtain credentials
- Malware or keyloggers on the host system
- Physical access to unlocked devices

### Best Practices

To maximize security when using BMPCipher, follow these recommendations:

- Create **strong passwords** with at least 12 characters, mixing uppercase, lowercase, numbers, and symbols
- Keep your **BMP key images** in a protected location separate from encrypted messages and passwords
- Use **separate image-password pairs** for different conversations or purposes
- **Secure transmission**: Share ciphertext only through encrypted channels (HTTPS, Signal, encrypted email)
- Ensure the **BMP file's integrity** regularly—verify it hasn't been corrupted or modified during storage or transfer

---

## Technologies Used

- **Backend**: Flask
  - A Python web framework

- **Cryptography**:
  - Python `cryptography` library

- **Frontend**:
  - HTML5
  - CSS3
  - Vanilla JavaScript

- **Encoding**:
  - Base64 for ciphertext representation

---

## Future of the Project

- **Steganography mode**: A mode which can hide messages within the image itself such that the image contains the decryption algorithm as well as the text

- **Real-time encrypted messaging**: Create entire conversations with each other in simple text, but messages are transmitted in encrypted form through the network—only with the correct uploaded image and password can you properly decipher the text using a login-based web application. Anyone can join the conversation with the correct credentials

---

## License

This project has been created exclusively for **educational purposes** as part of **CS50x 2025's Final Project**. Feel free to use and modify the application for learning and non-commercial purposes.

---

## Disclaimer

This application was developed exclusively for **educational and personal purposes**. While it implements industry-standard encryption algorithms, it has **not undergone a formal security audit**. Consequently, it should **not be used for highly sensitive data**. For critical applications, consider using established, professionally audited encryption tools.

---

## Acknowledgements

- **Harvard and CS50 Staff**: For providing an incredible and accessible free course through CS50x, offering an excellent introduction to programming
- **Python Cryptography Library**: For providing robust cryptographic primitives
- **Flask Community**: For excellent documentation and examples
- **GitHub Copilot**: For improving development efficiency and helping bring this ambitious project to completion

---

## Author

**Abhinav Parasher**

**Github Username**: Abhi-1-0-1

**EdX Username**: --Abhinav--

**City And Country**: Muscat, Oman

_CS50x Final Project - 2025_

This project was created as a Final Project for Harvard University's **CS50x**—their flagship Introduction to Computer Science course—demonstrating the practical applications of all the skills learned throughout the program.

---
