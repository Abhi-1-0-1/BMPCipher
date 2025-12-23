# CS50x Project: Secure Message Encryption and Decryption with BMP Images

# The comments in this code have been autocompleted by an AI tool to enhance clarity.

# Import libraries
from flask import Flask, render_template, request
import os
import hashlib
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# ========== Encryption and Decryption Functions ==========

# Read BMP file and return its bytes


def read_bmp_bytes(bmp_path):
    with open(bmp_path, "rb") as f:
        bmp_bytes = f.read()
    return bmp_bytes

# Get SHA-256 fingerprint of BMP bytes


def get_bmp_fingerprint(bmp_bytes):
    # Create an empty SHA-256 hash object
    sha256 = hashlib.sha256()

    # Update the hash object with the BMP bytes
    sha256.update(bmp_bytes)

    fingerprint = sha256.digest()
    return fingerprint

# Derive encryption key from password and BMP fingerprint


def derive_key(bmp_path, password, salt):
    bmp_bytes = read_bmp_bytes(bmp_path)
    fingerprint = get_bmp_fingerprint(bmp_bytes)
    # Derive key using PBKDF2HMAC. It combines password, salt, and BMP fingerprint
    '''
    Explanation of how this works:
    - PBKDF2HMAC is a key derivation function that applies a pseudorandom function (in this case, HMAC with SHA-256)
      to the input password along with a salt and iterates the process multiple times (100,000 here) to produce a secure key.
    - The salt is combined with the BMP fingerprint to ensure that the derived key is unique to both the password and the specific BMP image.
    - This makes it significantly harder for attackers to use precomputed tables (like rainbow tables) to guess the password, as the key will differ for different images even if the same password is used.
    '''
    kdf = PBKDF2HMAC(  # AI was used here to understand the parameters of PBKDF2HMAC and then autocompleted the function
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt + fingerprint,
        iterations=100000,
    )
    key = kdf.derive(password.encode('utf-8'))
    return key

# Encrypt message


def encrypt_message(bmp_path, password, message):
    salt = os.urandom(16)
    key = derive_key(bmp_path, password, salt)
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    '''
    Explanation of AESGCM encryption:
    - AESGCM is an implementation of the AES (Advanced Encryption Standard) algorithm
    - The nonce (number used once) is a unique value for each encryption operation to ensure that the same plaintext encrypted multiple times will yield different ciphertexts.
    - The encrypt method takes the nonce, plaintext message (encoded to bytes), and optional associated data (None here) to produce the ciphertext.
    '''
    ciphertext = aesgcm.encrypt(nonce, message.encode('utf-8'), None)
    full_blob = salt + nonce + ciphertext

    # Encode the full blob (salt + nonce + ciphertext) to base64 for easy transmission/storage
    encoded = base64.b64encode(full_blob).decode('utf-8')
    return encoded


def decrypt_message(bmp_path, password, encoded_ciphertext):
    try:
        # Decode the base64 encoded ciphertext
        full_blob = base64.b64decode(encoded_ciphertext)

        # Extract salt, nonce, and ciphertext
        salt = full_blob[:16]
        nonce = full_blob[16:28]
        ciphertext = full_blob[28:]

        # Derive the key using the same method as in encryption
        key = derive_key(bmp_path, password, salt)
        aesgcm = AESGCM(key)

        # Decrypt the ciphertext
        plaintext_bytes = aesgcm.decrypt(nonce, ciphertext, None)
        message = plaintext_bytes.decode('utf-8')
        return message
    except InvalidTag:
        return "DECRYPTION FAILED: Wrong password, wrong BMP, or tampered data!"
    except Exception as e:
        return f"Error: {e}"

# ========== Error Handling ==========


def error_handling(img, password, message):
    if not img or not password or not message:
        return "Missing image, password, or message", 400
    if img.filename == '':
        return "No selected file", 400
    if not img.filename.lower().endswith('.bmp'):
        return "Only BMP files are supported", 400
    return None

# ========== Flask Routes ==========

# Home Route


@app.route('/')
def index():
    return render_template('index.html')

# Learn Route


@app.route('/learn')
def learn():
    return render_template('learn.html')

# Encrypt Route


@app.route('/encrypt', methods=['GET', 'POST'])
def encrypt():
    if request.method == 'POST':
        # Check if the post request has the file part
        if 'image' not in request.files:
            return render_template('encrypt.html', error="No image part")

        # Get form data
        img = request.files['image']
        password = request.form.get('password')
        message = request.form.get('message')

        # Error handling
        error = error_handling(img, password, message)
        if error:
            error_msg = error[0] if isinstance(error, tuple) else error
            return render_template('encrypt.html', error=error_msg)

        # Save uploaded image
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], img.filename)
        img.save(filepath)

        # Process encryption
        try:
            with open(filepath, "rb") as image_file:
                thumbnail_data = base64.b64encode(image_file.read()).decode('utf-8')
            thumbnail = f"data:image/bmp;base64,{thumbnail_data}"

            encrypted_message = encrypt_message(filepath, password, message)
            return render_template('encrypt.html', result=encrypted_message, thumbnail=thumbnail, password=password)
        except Exception as e:
            return render_template('encrypt.html', error=str(e))
        finally:
            if os.path.exists(filepath):
                os.remove(filepath)
    else:
        return render_template('encrypt.html')

# Decrypt Route


@app.route('/decrypt', methods=['GET', 'POST'])
def decrypt():
    if request.method == 'POST':
        # Check if the post request has the file part
        if 'image' not in request.files:
            return render_template('decrypt.html', error="No image part")

        # Get form data
        img = request.files['image']
        password = request.form.get('password')
        encrypted_message = request.form.get('encrypted_message')

        # Error handling
        error = error_handling(img, password, encrypted_message)
        if error:
            error_msg = error[0] if isinstance(error, tuple) else error
            return render_template('decrypt.html', error=error_msg)

        # Save uploaded image
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], img.filename)
        img.save(filepath)

        # Process decryption
        try:
            with open(filepath, "rb") as image_file:
                thumbnail_data = base64.b64encode(image_file.read()).decode('utf-8')
            thumbnail = f"data:image/bmp;base64,{thumbnail_data}"

            decrypted_message = decrypt_message(filepath, password, encrypted_message)

            # Check for decryption failure
            if "DECRYPTION FAILED" in str(decrypted_message) or str(decrypted_message).startswith("Error:"):
                return render_template('decrypt.html', error=decrypted_message, password=password, encrypted_message=encrypted_message)
            return render_template('decrypt.html', result=decrypted_message, thumbnail=thumbnail, password=password)
        except Exception as e:
            return render_template('decrypt.html', error=str(e), password=password, encrypted_message=encrypted_message)
        finally:
            if os.path.exists(filepath):
                os.remove(filepath)
    else:
        return render_template('decrypt.html')


if __name__ == '__main__':
    app.run(debug=True)
