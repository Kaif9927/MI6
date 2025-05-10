from flask import Flask, request, jsonify, send_from_directory, render_template, redirect, url_for, session
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
import os
# utils.py or at top of app.py
def load_or_create_aes_key(filename="aes.key"):
    if os.path.exists(filename):
        with open(filename, "rb") as f:
            return f.read()
    key = get_random_bytes(16)
    with open(filename, "wb") as f:
        f.write(key)
    return key

AES_KEY = load_or_create_aes_key()

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.secret_key = "secret_key"  # Replace with a secure key

# --- AES Encryption Utilities ---
AES_KEY = get_random_bytes(16)  # In production, load this from a secure config

def encrypt_password(plaintext):
    cipher = AES.new(AES_KEY, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode()

def decrypt_password(encoded_data):
    decoded = base64.b64decode(encoded_data)
    nonce = decoded[:16]
    tag = decoded[16:32]
    ciphertext = decoded[32:]
    cipher = AES.new(AES_KEY, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()

# --- User Management ---
def load_users(file):
    users = {}
    if not os.path.exists(file):
        return users
    with open(file, "r") as f:
        for line in f:
            username, encrypted_password = line.strip().split(",")
            users[username] = encrypted_password
    return users

def save_user(file, username, password):
    encrypted = encrypt_password(password)
    with open(file, "a") as f:
        f.write(f"{username},{encrypted}\n")

# --- Routes ---
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        users_A = load_users("users_A.txt")
        users_B = load_users("users_B.txt")

        if username in users_A:
            try:
                if decrypt_password(users_A[username]) == password:
                    session["user"] = username
                    return redirect(url_for("index"))
            except:
                return "Decryption failed. Possibly corrupt data."

        if username in users_B:
            try:
                if decrypt_password(users_B[username]) == password:
                    session["pending_user"] = username
                    return redirect(url_for("second_login"))
            except:
                return "Decryption failed. Possibly corrupt data."

        return "Invalid username or password. Please try again."

    return render_template("login.html")

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Save as User A
        save_user("users_A.txt", username, password)
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route("/second-login", methods=["GET", "POST"])
def second_login():
    if "pending_user" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        users_B = load_users("users_B.txt")
        if username in users_B:
            try:
                if decrypt_password(users_B[username]) == password and username != session["pending_user"]:
                    return redirect(url_for("hidden_data"))
            except:
                return "Decryption failed. Possibly corrupt data."

        return "Invalid second user or same as the first user."

    return render_template("second_login.html")

@app.route("/index")
def index():
    if "user" in session:
        files = os.listdir(app.config['UPLOAD_FOLDER'])
        return render_template("index.html", files=files)
    return redirect(url_for("login"))

@app.route("/hidden-data")
def hidden_data():
    if "pending_user" in session:
        return render_template("hidden_data.html")
    return redirect(url_for("login"))

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return "No file part", 400

    file = request.files['file']
    if file.filename == '':
        return "No selected file", 400

    file.save(os.path.join(app.config['UPLOAD_FOLDER'], file.filename))
    return "File uploaded successfully!", 200

@app.route('/files', methods=['GET'])
def list_files():
    files = os.listdir(app.config['UPLOAD_FOLDER'])
    return jsonify(files)

@app.route('/uploads/<filename>', methods=['GET'])
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/delete/<filename>', methods=['POST'])
def delete_file(filename):
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if os.path.exists(file_path):
        os.remove(file_path)
        return redirect(url_for('index'))
    return "File not found", 404

if __name__ == '__main__':
    app.run(debug=True)
