from flask import Flask, request, render_template
from Crypto.Cipher import AES
import base64
import os

app = Flask(__name__)

# Clave de 16 bytes para AES-128 (debe ser secreta y segura en producción)
SECRET_KEY = b'16bytesAESKey123'
IV = os.urandom(16)  # Genera un IV aleatorio cada vez

def encrypt_message(message):
    cipher = AES.new(SECRET_KEY, AES.MODE_CFB, IV)
    encrypted_message = cipher.encrypt(message.encode())
    return base64.b64encode(IV + encrypted_message).decode()

def decrypt_message(encrypted_message):
    encrypted_message = base64.b64decode(encrypted_message)
    iv = encrypted_message[:16]
    cipher = AES.new(SECRET_KEY, AES.MODE_CFB, iv)
    decrypted_message = cipher.decrypt(encrypted_message[16:]).decode()
    return decrypted_message

@app.route('/', methods=['GET', 'POST'])
def index():
    encrypted_text = decrypted_text = ''
    if request.method == 'POST':
        action = request.form['action']
        text = request.form['text']
        
        if action == 'encrypt':
            encrypted_text = encrypt_message(text)
        elif action == 'decrypt':
            decrypted_text = decrypt_message(text)
    
    return render_template('index.html', encrypted_text=encrypted_text, decrypted_text=decrypted_text)

if __name__ == '__main__':
    app.run(debug=True)
