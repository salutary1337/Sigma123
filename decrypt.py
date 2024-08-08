from Crypto.Cipher import AES
import binascii

def decrypt_aes(ciphertext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(ciphertext)
    # Remove padding if present (PKCS#7)
    pad_len = decrypted[-1]
    if isinstance(pad_len, int) and 0 < pad_len <= AES.block_size:
        decrypted = decrypted[:-pad_len]
    return decrypted

def main():
    with open('decrypt.txt', 'r') as file:
        lines = file.readlines()
        key_hex = lines[0].strip().split('=')[1]
        iv_hex = lines[1].strip().split('=')[1]
        ciphertext_hex = lines[2].strip().split('=')[1]

    # Convert hex values to bytes
    key = binascii.unhexlify(key_hex)
    iv = binascii.unhexlify(iv_hex)
    ciphertext = binascii.unhexlify(ciphertext_hex)

    # Decrypt the ciphertext
    decrypted_bytes = decrypt_aes(ciphertext, key, iv)
    # Convert decrypted bytes to hexadecimal
    cookie_value = decrypted_bytes.hex()

    with open('decryptedcookie.txt', 'w') as file:
        file.write(cookie_value)

    print(f'Cookie value: {cookie_value}')

if __name__ == '__main__':
    main()
