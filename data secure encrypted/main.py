
import streamlit as st
import sqlite3
import hashlib
import os
from cryptography.fernet import Fernet

# -------------------- SETUP --------------------

KEY_FILE = "encryption_key.key"
DB_FILE = "vault_data.db"

# Load or generate encryption key
def load_key():
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as key_file:
            key_file.write(key)
    else:
        with open(KEY_FILE, "rb") as key_file:
            key = key_file.read()
    return key

# Hash the passkey
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Encrypt and decrypt functions
cipher = Fernet(load_key())

def encrypt_text(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_text(encrypted_text):
    return cipher.decrypt(encrypted_text.encode()).decode()

# Initialize database
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS secrets (
            label TEXT PRIMARY KEY,
            encrypted_data TEXT,
            hashed_passkey TEXT
        )
    """)
    conn.commit()
    conn.close()

init_db()

# -------------------- STREAMLIT UI --------------------

st.set_page_config(page_title="Secure Vault", page_icon="🔐")
# //st.title("🔐 Secure Vault App")

menu = ["Store Secret", "Retrieve Secret"]
choice = st.sidebar.radio("Choose Action", menu)

# -------------------- STORE SECRET --------------------

if choice == "Store Secret":
    st.subheader("📝 Store a New Secret")

    label = st.text_input("Label (Unique Identifier)")
    secret = st.text_area("Enter the secret text")
    passkey = st.text_input("Enter a passkey to protect your secret", type="password")

    if st.button("Encrypt & Save"):
        if not label or not secret or not passkey:
            st.warning("⚠️ Please fill all fields.")
        else:
            conn = sqlite3.connect(DB_FILE)
            c = conn.cursor()
            try:
                encrypted_data = encrypt_text(secret)
                hashed_key = hash_passkey(passkey)

                c.execute("INSERT INTO secrets (label, encrypted_data, hashed_passkey) VALUES (?, ?, ?)",
                          (label, encrypted_data, hashed_key))
                conn.commit()
                st.success("✅ Secret saved successfully!")
            except sqlite3.IntegrityError:
                st.error("❌ This label already exists. Use a different one.")
            conn.close()

# -------------------- RETRIEVE SECRET --------------------

elif choice == "Retrieve Secret":
    st.subheader("🔍 Retrieve Your Secret")

    label = st.text_input("Enter your label")
    passkey = st.text_input("Enter your passkey", type="password")

    if st.button("Decrypt & Show"):
        if not label or not passkey:
            st.warning("⚠️ Please enter both fields.")
        else:
            conn = sqlite3.connect(DB_FILE)
            c = conn.cursor()
            c.execute("SELECT encrypted_data, hashed_passkey FROM secrets WHERE label=?", (label,))
            result = c.fetchone()
            conn.close()

            if result:
                encrypted_data, stored_hash = result
                if hash_passkey(passkey) == stored_hash:
                    try:
                        decrypted = decrypt_text(encrypted_data)
                        st.success("✅ Secret retrieved:")
                        st.code(decrypted)
                    except Exception:
                        st.error("⚠️ Failed to decrypt the data. Maybe the key file changed?")
                else:
                    st.error("❌ Incorrect passkey.")
            else:
                st.warning("⚠️ No secret found for that label.")
