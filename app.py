from flask import Flask, render_template, request
import hashlib
import time
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

app = Flask(__name__)
app.secret_key = "crypto_project_secret_key"

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/hashing', methods=['GET', 'POST'])
def hashing_page():
    result = ""
    if request.method == 'POST':
        text = request.form['text']
        result = hashlib.sha256(text.encode()).hexdigest()
    return render_template('hashing.html', result=result)

# ========================================================
# UPGRADED SYMMETRIC ENCRYPTION MODULE (AES-128 / FERNET)
# ========================================================
@app.route('/symmetric', methods=['GET', 'POST'])
def symmetric():
    encrypted = ""
    decrypted = ""
    aes_time = 0
    filename_used = ""
    
    # Fig 2 Evidence: Cryptographically secure key generation process
    key = Fernet.generate_key()
    cipher = Fernet(key)
    
    if request.method == 'POST':
        # Check for file upload input
        uploaded_file = request.files.get('file_input')
        
        if uploaded_file and uploaded_file.filename != '':
            # Fig 3 Evidence: Processing an uploaded text file
            message_bytes = uploaded_file.read()
            filename_used = uploaded_file.filename
        else:
            # Fall back to standard form text field input
            message_text = request.form.get('message', '')
            message_bytes = message_text.encode()
            filename_used = "Direct Input Text"

        if message_bytes:
            # Fig 5 Evidence: Performance Testing (Start Metric Timer)
            start_time = time.time()
            
            # Core AES Workflow: Symmetric transformation execution
            encrypted_bytes = cipher.encrypt(message_bytes)
            decrypted_bytes = cipher.decrypt(encrypted_bytes)
            
            # Fig 5 Evidence: Performance Testing (End Metric Timer in milliseconds)
            aes_time = round((time.time() - start_time) * 1000, 4)
            
            # Fig 4 Evidence: Decryption Results preparation
            encrypted = encrypted_bytes.decode()
            decrypted = decrypted_bytes.decode()

    return render_template('symmetric.html', 
                           encrypted=encrypted, 
                           decrypted=decrypted, 
                           aes_time=aes_time,
                           filename_used=filename_used)

@app.route('/asymmetric', methods=['GET', 'POST'])
def asymmetric():
    encrypted = ""
    decrypted = ""
    if request.method == 'POST':
        message = request.form['message']
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()
        encrypted_bytes = public_key.encrypt(
            message.encode(),
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        decrypted_bytes = private_key.decrypt(
            encrypted_bytes,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        encrypted = encrypted_bytes.hex()
        decrypted = decrypted_bytes.decode()
    return render_template('asymmetric.html', encrypted=encrypted, decrypted=decrypted)

# =========================
# CLASSICAL CIPHERS
# =========================

def caesar_encrypt(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - base + shift) % 26 + base)
        else:
            result += char
    return result

def caesar_decrypt(text, shift):
    return caesar_encrypt(text, -shift)

def vigenere_encrypt(text, key):
    result = ""
    key = key.lower()
    key_index = 0
    for char in text:
        if char.isalpha():
            shift = ord(key[key_index % len(key)]) - ord('a')
            base = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - base + shift) % 26 + base)
            key_index += 1
        else:
            result += char
    return result

def vigenere_decrypt(text, key):
    result = ""
    key = key.lower()
    key_index = 0
    for char in text:
        if char.isalpha():
            shift = ord(key[key_index % len(key)]) - ord('a')
            base = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - base - shift) % 26 + base)
            key_index += 1
        else:
            result += char
    return result

@app.route('/classical', methods=['GET', 'POST'])
def classical():
    caesar_encrypted = ""
    caesar_decrypted = ""
    vigenere_encrypted = ""
    vigenere_decrypted = ""
    error = ""
    caesar_steps = []
    vigenere_steps = []
    if request.method == 'POST':
        message = request.form.get('message', '').strip()
        caesar_shift = request.form.get('caesar_shift', '').strip()
        vigenere_key = request.form.get('vigenere_key', '').strip()
        if not message:
            error = "Message cannot be empty."
        elif not message.replace(' ', '').isalpha():
            error = "Message must contain letters only (spaces allowed)."
        elif not caesar_shift.isdigit() or not (1 <= int(caesar_shift) <= 25):
            error = "Caesar shift must be a number between 1 and 25."
        elif not vigenere_key.isalpha():
            error = "Vigenere key must contain letters only."
        else:
            shift = int(caesar_shift)
            caesar_encrypted = caesar_encrypt(message, shift)
            caesar_decrypted = caesar_decrypt(caesar_encrypted, shift)
            for char in message[:6]:
                if char.isalpha():
                    base = ord('A') if char.isupper() else ord('a')
                    enc_char = chr((ord(char) - base + shift) % 26 + base)
                    caesar_steps.append(f"'{char}' + shift {shift} = '{enc_char}'")
            vigenere_encrypted = vigenere_encrypt(message, vigenere_key)
            vigenere_decrypted = vigenere_decrypt(vigenere_encrypted, vigenere_key)
            key_lower = vigenere_key.lower()
            key_index = 0
            for char in message[:6]:
                if char.isalpha():
                    k = key_lower[key_index % len(key_lower)]
                    shift_v = ord(k) - ord('a')
                    base = ord('A') if char.isupper() else ord('a')
                    enc_char = chr((ord(char) - base + shift_v) % 26 + base)
                    vigenere_steps.append(f"'{char}' + key '{k}' (shift {shift_v}) = '{enc_char}'")
                    key_index += 1
    return render_template('classical.html',
        caesar_encrypted=caesar_encrypted,
        caesar_decrypted=caesar_decrypted,
        vigenere_encrypted=vigenere_encrypted,
        vigenere_decrypted=vigenere_decrypted,
        error=error,
        caesar_steps=caesar_steps,
        vigenere_steps=vigenere_steps,
        message=request.form.get('message', ''),
        caesar_shift=request.form.get('caesar_shift', ''),
        vigenere_key=request.form.get('vigenere_key', '')
    )

# =========================
# STREAM CIPHERS & RANDOMNESS
# =========================

def lfsr(seed, taps, length):
    state = list(seed)
    output = []
    for _ in range(length):
        output.append(state[-1])
        feedback = 0
        for t in taps:
            feedback ^= state[t]
        state = [feedback] + state[:-1]
    return output

def rc4_encrypt(key, plaintext):
    S = list(range(256))
    j = 0
    key_bytes = [ord(c) for c in key]
    for i in range(256):
        j = (j + S[i] + key_bytes[i % len(key_bytes)]) % 256
        S[i], S[j] = S[j], S[i]
    i = j = 0
    keystream = []
    ciphertext = []
    for char in plaintext:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        k = S[(S[i] + S[j]) % 256]
        keystream.append(k)
        ciphertext.append(ord(char) ^ k)
    return keystream, ciphertext

def rc4_decrypt(key, ciphertext_bytes):
    S = list(range(256))
    j = 0
    key_bytes = [ord(c) for c in key]
    for i in range(256):
        j = (j + S[i] + key_bytes[i % len(key_bytes)]) % 256
        S[i], S[j] = S[j], S[i]
    i = j = 0
    plaintext = []
    for byte in ciphertext_bytes:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        k = S[(S[i] + S[j]) % 256]
        plaintext.append(chr(byte ^ k))
    return ''.join(plaintext)

def randomness_tests(bits):
    total = len(bits)
    ones = sum(bits)
    zeros = total - ones
    balance_ratio = round((ones / total) * 100, 2)
    freq_pass = abs(ones - zeros) <= total * 0.1
    runs = 1
    for i in range(1, len(bits)):
        if bits[i] != bits[i-1]:
            runs += 1
    expected_runs = round((2 * ones * zeros / total) + 1, 2)
    runs_pass = abs(runs - expected_runs) <= total * 0.1
    longest = current = 1
    for i in range(1, len(bits)):
        if bits[i] == bits[i-1]:
            current += 1
            longest = max(longest, current)
        else:
            current = 1
    return {
        'total': total,
        'ones': ones,
        'zeros': zeros,
        'balance_ratio': balance_ratio,
        'freq_pass': freq_pass,
        'runs': runs,
        'expected_runs': expected_runs,
        'runs_pass': runs_pass,
        'longest_run': longest
    }

@app.route('/stream', methods=['GET', 'POST'])
def stream():
    lfsr_bits = []
    lfsr_seed_val = ''
    lfsr_taps_val = ''
    stats = None
    rc4_encrypted = []
    rc4_decrypted = ''
    rc4_keystream = []
    rc4_message = ''
    rc4_key_val = ''
    error = ''
    lfsr_time = 0
    rc4_time = 0
    action = ''

    if request.method == 'POST':
        action = request.form.get('action', '')

        if action == 'lfsr':
            lfsr_seed_val = request.form.get('lfsr_seed', '').strip()
            lfsr_taps_val = request.form.get('lfsr_taps', '').strip()

            if not lfsr_seed_val or not all(c in '01' for c in lfsr_seed_val):
                error = "Seed must contain only 0s and 1s."
            elif len(lfsr_seed_val) < 4:
                error = "Seed must be at least 4 bits long."
            else:
                try:
                    taps = [int(t.strip()) for t in lfsr_taps_val.split(',')]
                    if any(t < 0 or t >= len(lfsr_seed_val) for t in taps):
                        error = f"Taps must be between 0 and {len(lfsr_seed_val)-1}."
                    else:
                        seed = [int(b) for b in lfsr_seed_val]
                        start = time.time()
                        lfsr_bits = lfsr(seed, taps, 64)
                        lfsr_time = round((time.time() - start) * 1000, 4)
                        stats = randomness_tests(lfsr_bits)
                except:
                    error = "Invalid tap positions. Use comma-separated numbers e.g. 0,2"

        elif action == 'rc4':
            rc4_message = request.form.get('rc4_message', '').strip()
            rc4_key_val = request.form.get('rc4_key', '').strip()

            if not rc4_message:
                error = "Message cannot be empty."
            elif not rc4_key_val:
                error = "RC4 key cannot be empty."
            elif len(rc4_key_val) < 3:
                error = "RC4 key must be at least 3 characters."
            else:
                start = time.time()
                rc4_keystream, rc4_encrypted = rc4_encrypt(rc4_key_val, rc4_message)
                rc4_decrypted = rc4_decrypt(rc4_key_val, rc4_encrypted)
                rc4_time = round((time.time() - start) * 1000, 4)

    return render_template('stream.html',
        lfsr_bits=lfsr_bits,
        lfsr_bits_str=''.join(str(b) for b in lfsr_bits),
        lfsr_seed=lfsr_seed_val,
        lfsr_taps=lfsr_taps_val,
        stats=stats,
        rc4_encrypted=rc4_encrypted,
        rc4_encrypted_hex=' '.join(f'{b:02x}' for b in rc4_encrypted),
        rc4_decrypted=rc4_decrypted,
        rc4_keystream_hex=' '.join(f'{b:02x}' for b in rc4_keystream[:16]),
        rc4_message=rc4_message,
        rc4_key=rc4_key_val,
        error=error,
        lfsr_time=lfsr_time,
        rc4_time=rc4_time,
        action=action
    )

@app.route('/threats')
def threats():
    return render_template('threats.html')

if __name__ == '__main__':
    app.run(debug=True)