from flask import Flask, render_template, request
import hashlib

from cryptography.fernet import Fernet

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

app = Flask(__name__)

app.secret_key = "crypto_project_secret_key"


# =========================
# HOME
# =========================
@app.route('/')
def home():
    return render_template('index.html')


# =========================
# HASHING (SHA-256)
# =========================
@app.route('/hashing', methods=['GET', 'POST'])
def hashing_page():

    result = ""

    if request.method == 'POST':
        text = request.form['text']
        result = hashlib.sha256(text.encode()).hexdigest()

    return render_template('hashing.html', result=result)


# =========================
# SYMMETRIC ENCRYPTION (FERNET)
# =========================
@app.route('/symmetric', methods=['GET', 'POST'])
def symmetric():

    encrypted = ""
    decrypted = ""

    # generate key per request (safe + simple for assignment)
    key = Fernet.generate_key()
    cipher = Fernet(key)

    if request.method == 'POST':

        message = request.form['message']

        encrypted = cipher.encrypt(message.encode()).decode()
        decrypted = cipher.decrypt(encrypted.encode()).decode()

    return render_template(
        'symmetric.html',
        encrypted=encrypted,
        decrypted=decrypted
    )


# =========================
# ASYMMETRIC ENCRYPTION (RSA)
# =========================
@app.route('/asymmetric', methods=['GET', 'POST'])
def asymmetric():

    encrypted = ""
    decrypted = ""

    if request.method == 'POST':

        message = request.form['message']

        # generate fresh key pair per request (NO SESSION STORAGE)
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )

        public_key = private_key.public_key()

        encrypted_bytes = public_key.encrypt(
            message.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        decrypted_bytes = private_key.decrypt(
            encrypted_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        encrypted = encrypted_bytes.hex()
        decrypted = decrypted_bytes.decode()

    return render_template(
        'asymmetric.html',
        encrypted=encrypted,
        decrypted=decrypted
    )


# =========================
# THREATS PAGE
# =========================
@app.route('/threats')
def threats():
    return render_template('threats.html')


# =========================
# RUN APP
# =========================
if __name__ == '__main__':
    app.run(debug=True)