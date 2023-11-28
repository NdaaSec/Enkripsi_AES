from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64

if __name__ == "__main__":
    while True:
        print("\nEnkripsi yang ingin dibuat: ")
        print("1. Enkripsi Rijndael")
        print("2. Enkripsi DES")
        print("3. Enkripsi RC4")
        print("4. Enkripsi Triple DES")
        print("0. Keluar")

        pilihan = input("Pilih Enkripsi: ")
        if pilihan == "0":
            break
        elif pilihan == "1":
            def generate_key():
                return get_random_bytes(16)

            def encrypt(plain_text, key):
                cipher = AES.new(key, AES.MODE_CBC)
                cipher_text = cipher.encrypt(pad(plain_text.encode('utf-8'), AES.block_size))
                return cipher.iv + cipher_text

            def decrypt(cipher_text, key):
                iv = cipher_text[:AES.block_size]
                cipher = AES.new(key, AES.MODE_CBC, iv)
                plain_text = unpad(cipher.decrypt(cipher_text[AES.block_size:]), AES.block_size)
                return plain_text.decode('utf-8')

            if __name__ == "__main__":
                while True:
                    print("\nMembuat code enkripsi dengan menggunakan Rijndael Cipher Block Chaining")
                    print("\nDengan kunci random")
                    print("1. Membuat Code Enkripsi")
                    print("2. Memecahkan Code Enkripsi")
                    print("0. Keluar")

                    choice = input("Pilih tindakan (0/1/2): ")
                    if choice == "0":
                        break
                    elif choice == "1":
                        plain_text = input("\nMasukkan teks yang ingin dienkripsi: ")
                        key = generate_key()
                        cipher_text = encrypt(plain_text, key)
                        print(f"\nPlaintext: {plain_text}")
                        print(f"Kunci: {base64.b64encode(key).decode('utf-8')}")
                        print(f"Ciphertext: {base64.b64encode(cipher_text).decode('utf-8')}")
                    elif choice == "2":
                        cipher_text = input("Masukkan teks terenkripsi: ")
                        key_str = input("Masukkan kunci enkripsi: ")
                        key = base64.b64decode(key_str)
                        decrypted_text = decrypt(base64.b64decode(cipher_text), key)
                        print(f"\nDecrypted Text: {decrypted_text}")
                    else:
                        print("Pilihan tidak valid. Silakan pilih 0, 1, atau 2.")

        elif pilihan == "2":

            def encrypt_des(key, plaintext):
                key = key.ljust(8, '0')[:8].encode('utf-8')
                plaintext = plaintext.encode('utf-8')
                cipher = Cipher(algorithms.DES(key), modes.ECB(), backend=default_backend())
                encryptor = cipher.encryptor()
                length = 8 - (len(plaintext) % 8)
                plaintext += bytes([length]) * length
                ciphertext = encryptor.update(plaintext) + encryptor.finalize()
                return base64.b64encode(ciphertext).decode('utf-8')

            def decrypt_des(key, ciphertext):
                key = key.ljust(8, '0')[:8].encode('utf-8') 
                ciphertext = base64.b64decode(ciphertext)
                cipher = Cipher(algorithms.DES(key), modes.ECB(), backend=default_backend())
                decryptor = cipher.decryptor()
                plaintext = decryptor.update(ciphertext) + decryptor.finalize()
                padding_length = plaintext[-1]
                plaintext = plaintext[:-padding_length]
                return plaintext.decode('utf-8')

            def main():
                print("\nPilih operasi:")
                print("1. Enkripsi")
                print("2. Dekripsi")

                choice = input("Masukkan pilihan (1 atau 2): ")
                if choice == '1':
                    key = input("Masukkan kunci DES (8 karakter): ")
                    plaintext = input("Masukkan teks untuk dienkripsi: ")
                    ciphertext = encrypt_des(key, plaintext)
                    print("Teks terenkripsi:", ciphertext)
                elif choice == '2':
                    key = input("Masukkan kunci DES (8 karakter): ")
                    ciphertext = input("Masukkan teks terenkripsi: ")
                    plaintext = decrypt_des(key, ciphertext)
                    print("Teks terdekripsi:", plaintext)
                else:
                    print("Pilihan tidak valid.")
            if __name__ == "__main__":
                main()


        elif pilihan == "3":

            def ksa(key):
                key_length = len(key)
                S = list(range(256))
                j = 0
                for i in range(256):
                    j = (j + S[i] + key[i % key_length]) % 256
                    S[i], S[j] = S[j], S[i]
                return S

            def prga(S, plaintext):
                i = j = 0
                keystream = []
                for char in plaintext:
                    i = (i + 1) % 256
                    j = (j + S[i]) % 256
                    S[i], S[j] = S[j], S[i]
                    keystream_byte = S[(S[i] + S[j]) % 256]
                    keystream.append(keystream_byte)
                return keystream

            def rc4_encrypt(key, plaintext):
                key = [ord(char) for char in key]
                S = ksa(key)
                keystream = prga(S, plaintext)
                ciphertext = [ord(char) ^ keystream_byte for char, keystream_byte in zip(plaintext, keystream)]
                return ''.join([format(char, '02x') for char in ciphertext])
            def rc4_decrypt(key, ciphertext_hex):
                key = [ord(char) for char in key]
                ciphertext = bytes.fromhex(ciphertext_hex).decode('latin-1')
                S = ksa(key)
                keystream = prga(S, ciphertext)
                plaintext = [ord(char) ^ keystream_byte for char, keystream_byte in zip(ciphertext, keystream)]
                return ''.join([chr(char) for char in plaintext])

            def main():
                print("\nPilih operasi:")
                print("1. Enkripsi RC4")
                print("2. Dekripsi RC4")

                choice = input("Masukkan pilihan (1 atau 2): ")
                if choice == '1':
                    key = input("Masukkan kunci RC4: ")
                    plaintext = input("Masukkan teks untuk dienkripsi: ")
                    ciphertext = rc4_encrypt(key, plaintext)
                    print("Teks terenkripsi (hex):", ciphertext)
                elif choice == '2':
                    key = input("Masukkan kunci RC4: ")
                    ciphertext_hex = input("Masukkan teks terenkripsi (hex): ")
                    plaintext = rc4_decrypt(key, ciphertext_hex)
                    print("Teks terdekripsi:", plaintext)
                else:
                    print("Pilihan tidak valid.")
            if __name__ == "__main__":
                main()

        elif pilihan == "4":

            def triple_des_encrypt(key, plaintext):
                key = key.ljust(24, '0')[:24].encode('utf-8')
                plaintext = plaintext.encode('utf-8')
                cipher = Cipher(algorithms.TripleDES(key), modes.ECB(), backend=default_backend())
                encryptor = cipher.encryptor()
                length = 8 - (len(plaintext) % 8)
                plaintext += bytes([length]) * length
                ciphertext = encryptor.update(plaintext) + encryptor.finalize()
                return base64.b64encode(ciphertext).decode('utf-8')

            def triple_des_decrypt(key, ciphertext):
                key = key.ljust(24, '0')[:24].encode('utf-8')
                ciphertext = base64.b64decode(ciphertext)
                cipher = Cipher(algorithms.TripleDES(key), modes.ECB(), backend=default_backend())
                decryptor = cipher.decryptor()
                plaintext = decryptor.update(ciphertext) + decryptor.finalize()
                padding_length = plaintext[-1]
                plaintext = plaintext[:-padding_length]
                return plaintext.decode('utf-8')

            def main():
                print("\nPilih operasi:")
                print("1. Enkripsi Triple DES")
                print("2. Dekripsi Triple DES")

                choice = input("Masukkan pilihan (1 atau 2): ")
                if choice == '1':
                    key = input("Masukkan kunci Triple DES (24 karakter): ")
                    plaintext = input("Masukkan teks untuk dienkripsi: ")
                    ciphertext = triple_des_encrypt(key, plaintext)
                    print("\nTeks terenkripsi:", ciphertext)
                elif choice == '2':
                    key = input("Masukkan kunci Triple DES (24 karakter): ")
                    ciphertext = input("Masukkan teks terenkripsi: ")
                    plaintext = triple_des_decrypt(key, ciphertext)
                    print("Teks terdekripsi:", plaintext)
                else:
                    print("Pilihan tidak valid.")
            if __name__ == "__main__":
                main()
