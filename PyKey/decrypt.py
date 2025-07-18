from cryptography.fernet import Fernet

# Load the encryption key
with open("key.key", "rb") as f:
    key = f.read()

fernet = Fernet(key)

# Load the encrypted log
with open("log.txt", "rb") as f:
    encrypted_data = f.read()

# Decrypt the content
decrypted = fernet.decrypt(encrypted_data).decode()

# Write the decrypted content to a new file
with open("decrypted_log.txt", "w", encoding="utf-8") as f:  #Unicode Transformation Format - 8 bit
    f.write(decrypted)

print("[✓] Decrypted log saved as 'decrypted_log.txt'")
