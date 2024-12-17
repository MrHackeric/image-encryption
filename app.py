from flask import Flask, request, send_from_directory, render_template, redirect, url_for
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import os

app = Flask(__name__)

# Define constants and directories
KEY_SIZE = 32  # AES-256
UPLOAD_FOLDER = 'static/uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


def encrypt_image(file_path):
    """Encrypt the image and generate a new key."""
    with open(file_path, 'rb') as f:
        file_data = f.read()

    key = get_random_bytes(KEY_SIZE)  # Generate a new key
    # key = b'\x00'
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(file_data, AES.block_size))

    encrypted_file_path = file_path + '.enc'
    with open(encrypted_file_path, 'wb') as f:
        f.write(cipher.iv)  # Save the IV for decryption
        f.write(ciphertext)

    return encrypted_file_path, key


def decrypt_image(file_path, key):
    """Decrypt the image using the provided key."""
    with open(file_path, 'rb') as f:
        iv = f.read(16)  # IV is 16 bytes for AES
        ciphertext = f.read()  # Remaining is the ciphertext

    if len(iv) != 16:
        raise ValueError("Invalid IV length. It should be 16 bytes.")
    
    cipher = AES.new(key, AES.MODE_CBC, iv)
    try:
        decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size)
    except (ValueError, KeyError) as e:
        raise ValueError(f"Decryption failed: {e}")

    decrypted_file_path = file_path.replace('.enc', '_decrypted.jpg')
    with open(decrypted_file_path, 'wb') as f:
        f.write(decrypted_data)

    return decrypted_file_path


@app.route('/')
def credentials():
    return render_template('login.html')


@app.route('/app')
def index():
    return render_template('index.html')


@app.route('/upload', methods=['POST'])
def upload_file():
    if 'image' not in request.files:
        return 'No file part', 400
    
    file = request.files['image']
    if file.filename == '':
        return 'No selected file', 400

    file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
    file.save(file_path)

    # Encrypt the image and generate the key
    encrypted_file_path, key = encrypt_image(file_path)

    # Provide the key to the user
    return (f'File encrypted successfully. Download it <a href="/uploads/{os.path.basename(encrypted_file_path)}">here</a>.<br>'
            f'Encryption Key (Save this to decrypt): <strong>{key.hex()}</strong>')


@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


@app.route('/decrypt', methods=['POST'])
def decrypt_file():
    key_hex = request.form.get('key')  # Get the decryption key from the form
    if not key_hex:
        return 'No decryption key provided.', 400

    try:
        key = bytes.fromhex(key_hex)  # Convert the hex key back to bytes
    except ValueError:
        return 'Invalid key format. Ensure it is in hexadecimal.', 400

    if len(key) != KEY_SIZE:
        return 'Invalid key length. Ensure it is a 32-byte key.', 400

    if 'image' not in request.files:
        return 'No file part', 400

    file = request.files['image']
    if file.filename == '':
        return 'No selected file', 400

    encrypted_file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
    file.save(encrypted_file_path)

    # Decrypt the image with the provided key
    decrypted_file_path = decrypt_image(encrypted_file_path, key)

    return f'File decrypted successfully. Download it <a href="/uploads/{os.path.basename(decrypted_file_path)}">here</a>.'


@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Check if the username and password are valid (you can implement your own logic here)
        if username == 'admin' and password == 'admin123':
            return redirect(url_for('index'))
        else:
            return render_template('login.html', message='Please check your credentials!!')

    return render_template('login.html')


if __name__ == '__main__':
    app.run(debug=True)
