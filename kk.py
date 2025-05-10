from flask import Flask, request, jsonify, send_from_directory, render_template, redirect, url_for, session
import os

app = Flask(__name__)

# Directory to store uploaded files
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.secret_key = "secret_key"  # Replace with a secure key

# Load users from text files
def load_users(file):
    users = {}
    with open(file, "r") as f:
        for line in f:
            username, password = line.strip().split(",")
            users[username] = password
    return users

# Save a new user to the file
def save_user(file, username, password):
    with open(file, "a") as f:
        f.write(f"{username},{password}\n")

# Route to serve the HTML file
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        users_A = load_users("users_A.txt")
        users_B = load_users("users_B.txt")

        if username in users_A and users_A[username] == password:
            session["user"] = username
            return redirect(url_for("index"))
        elif username in users_B and users_B[username] == password:
            session["pending_user"] = username
            return redirect(url_for("second_login"))
        else:
            return "Invalid username or password. Please try again."

    return render_template("login.html")

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Always save as User A
        user_type = "A"
        
        # Save user data to users_A.txt (or use appropriate file/database)
        with open(f"users_{user_type}.txt", "a") as file:
            file.write(f"{username},{password}\n")
        
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
        if username in users_B and users_B[username] == password and username != session["pending_user"]:
            return redirect(url_for("hidden_data"))
        else:
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

# Route to list uploaded files
@app.route('/files', methods=['GET'])
def list_files():
    files = os.listdir(app.config['UPLOAD_FOLDER'])
    return jsonify(files)

# Route to serve uploaded files
@app.route('/uploads/<filename>', methods=['GET'])
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# Route to delete a file
@app.route('/delete/<filename>', methods=['POST'])
def delete_file(filename):
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if os.path.exists(file_path):
        os.remove(file_path)
        return redirect(url_for('index'))
    return "File not found", 404

if __name__ == '__main__':
    app.run(debug=True)
