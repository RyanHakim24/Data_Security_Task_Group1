import os
import time

# --------------------------
# Fungsi dasar RSA
# --------------------------

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def modinv(a, m):
    """Menghitung invers modular a mod m menggunakan Extended Euclidean Algorithm."""
    m0 = m
    x, y = 1, 0
    if m == 1:
        return 0
    while a > 1:
        q = a // m
        t = m
        m = a % m
        a = t
        t = y
        y = x - q * y
        x = t
    if x < 0:
        x += m0
    return x

def generate_keys():
    """
    Menghasilkan pasangan kunci RSA sederhana.
    Untuk tujuan pembelajaran, digunakan bilangan prima kecil.
    p = 61, q = 53 ---> n = 3233, phi(n) = 3120, pilih e = 17.
    d merupakan invers modular e mod phi.
    """
    p = 61
    q = 53
    n = p * q              # n = 3233
    phi = (p - 1) * (q - 1)  # phi = 3120
    e = 17                 # eksponen publik (dipilih karena gcd(17,3120)==1)
    d = modinv(e, phi)     # eksponen privat
    return (e, n), (d, n)

def rsa_encrypt(plaintext, pubkey):
    """
    Mengenkripsi pesan dengan RSA.
    Untuk setiap karakter pada plaintext, enkripsi dengan:
        cipher = (ord(character) ** e) mod n
    """
    e, n = pubkey
    cipher_numbers = [pow(ord(ch), e, n) for ch in plaintext]
    return cipher_numbers

def rsa_decrypt(cipher_numbers, privkey):
    """
    Mendekripsi daftar bilangan ciphertext dengan RSA.
    Untuk setiap bilangan, lakukan dekripsi:
        plaintext = chr((cipher ** d) mod n)
    """
    d, n = privkey
    plaintext = ''.join(chr(pow(num, d, n)) for num in cipher_numbers)
    return plaintext

# --------------------------
# Fungsi Penyimpanan dan Pemuatan Kunci
# --------------------------

def save_keys(pubkey, privkey, base_name):
    """
    Menyimpan kunci publik dan privat ke file dengan ekstensi .pub dan .pri.
    Format file: "<eksponen> <modulus>"
    """
    pub_filename = base_name + ".pub"
    pri_filename = base_name + ".pri"
    try:
        with open(pub_filename, "w", encoding="utf-8") as f:
            f.write(f"{pubkey[0]} {pubkey[1]}")
        with open(pri_filename, "w", encoding="utf-8") as f:
            f.write(f"{privkey[0]} {privkey[1]}")
        print(f"\nKunci publik disimpan ke: {pub_filename}")
        print(f"Kunci privat disimpan ke: {pri_filename}")
    except Exception as err:
        print("Terjadi kesalahan saat menyimpan kunci:", err)

def load_public_key_from_file(filename):
    """Pemuatan kunci publik dari file dengan format: 'e n'."""
    try:
        with open(filename, "r", encoding="utf-8") as f:
            data = f.read().strip().split()
            e, n = int(data[0]), int(data[1])
        return (e, n)
    except Exception as err:
        print("Gagal membaca kunci publik:", err)
        return None

def load_private_key_from_file(filename):
    """Pemuatan kunci privat dari file dengan format: 'd n'."""
    try:
        with open(filename, "r", encoding="utf-8") as f:
            data = f.read().strip().split()
            d, n = int(data[0]), int(data[1])
        return (d, n)
    except Exception as err:
        print("Gagal membaca kunci privat:", err)
        return None

# --------------------------
# Fungsi Enkripsi File
# --------------------------
def encrypt_file():
    # Meminta input nama file plaintext (beserta path-nya)
    input_file = input("Masukkan path file plaintext (.txt): ").strip()
    if not os.path.exists(input_file):
        print("File tidak ditemukan.")
        return

    try:
        with open(input_file, "r", encoding="utf-8") as f:
            plaintext = f.read()
    except Exception as err:
        print("Gagal membaca file:", err)
        return

    # Pilihan cara pengambilan kunci publik
    pilihan = input("Ambil kunci publik dari file? (y/n): ").strip().lower()
    if pilihan.startswith('y'):
        key_file = input("Masukkan path file kunci publik (*.pub): ").strip()
        if not os.path.exists(key_file):
            print("File kunci publik tidak ditemukan.")
            return
        pubkey = load_public_key_from_file(key_file)
        if pubkey is None:
            return
    else:
        try:
            e = int(input("Masukkan nilai e (eksponen publik): "))
            n = int(input("Masukkan nilai n (modulus): "))
            pubkey = (e, n)
        except Exception as err:
            print("Input kunci tidak valid:", err)
            return

    # Proses enkripsi dan ukur waktu proses
    start_time = time.perf_counter()
    cipher_numbers = rsa_encrypt(plaintext, pubkey)
    end_time = time.perf_counter()
    encryption_time = end_time - start_time

    # Konversi bilangan cipher ke notasi heksadesimal
    cipher_hex_list = [hex(num)[2:] for num in cipher_numbers]  # menghilangkan "0x"
    cipher_hex = ' '.join(cipher_hex_list)

    # Tampilkan plaintext dan ciphertext ke layar
    print("\n--- Plaintext ---")
    print(plaintext)
    print("\n--- Ciphertext (Hex) ---")
    print(cipher_hex)

    # Menyimpan ciphertext ke file
    output_file = input("Masukkan path file untuk menyimpan ciphertext: ").strip()
    try:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(cipher_hex)
        file_size = os.path.getsize(output_file)
        print(f"\nCiphertext telah disimpan ke: {output_file}")
        print(f"Lama waktu enkripsi: {encryption_time:.6f} detik")
        print(f"Ukuran file ciphertext: {file_size} bytes")
    except Exception as err:
        print("Gagal menyimpan file ciphertext:", err)

# --------------------------
# Fungsi Dekripsi File
# --------------------------
def decrypt_file():
    # Meminta input file ciphertext
    cipher_file = input("Masukkan path file ciphertext (.txt): ").strip()
    if not os.path.exists(cipher_file):
        print("File ciphertext tidak ditemukan.")
        return

    try:
        with open(cipher_file, "r", encoding="utf-8") as f:
            cipher_text = f.read().strip()
    except Exception as err:
        print("Gagal membaca file ciphertext:", err)
        return

    # Konversi notasi heksadesimal ke bilangan integer
    try:
        cipher_numbers = [int(token, 16) for token in cipher_text.split()]
    except Exception as err:
        print("Format file ciphertext tidak valid:", err)
        return

    # Pilihan cara pengambilan kunci privat
    pilihan = input("Ambil kunci privat dari file? (y/n): ").strip().lower()
    if pilihan.startswith('y'):
        key_file = input("Masukkan path file kunci privat (*.pri): ").strip()
        if not os.path.exists(key_file):
            print("File kunci privat tidak ditemukan.")
            return
        privkey = load_private_key_from_file(key_file)
        if privkey is None:
            return
    else:
        try:
            d = int(input("Masukkan nilai d (eksponen privat): "))
            n = int(input("Masukkan nilai n (modulus): "))
            privkey = (d, n)
        except Exception as err:
            print("Input kunci tidak valid:", err)
            return

    # Proses dekripsi dan ukur waktu proses
    start_time = time.perf_counter()
    plaintext = rsa_decrypt(cipher_numbers, privkey)
    end_time = time.perf_counter()
    decryption_time = end_time - start_time

    # Tampilkan plaintext hasil dekripsi ke layar
    print("\n--- Plaintext ---")
    print(plaintext)

    # Simpan hasil dekripsi ke file
    output_file = input("Masukkan path file untuk menyimpan hasil dekripsi: ").strip()
    try:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(plaintext)
        file_size = os.path.getsize(output_file)
        print(f"\nPlaintext telah disimpan ke: {output_file}")
        print(f"Lama waktu dekripsi: {decryption_time:.6f} detik")
        print(f"Ukuran file plaintext: {file_size} bytes")
    except Exception as err:
        print("Gagal menyimpan file plaintext:", err)

# --------------------------
# Fungsi Generate dan Penyimpanan Kunci RSA
# --------------------------
def generate_and_save_keys():
    pubkey, privkey = generate_keys()
    print("\nKunci RSA telah dihasilkan:")
    print("Kunci publik (e, n):", pubkey)
    print("Kunci privat (d, n):", privkey)
    base_name = input("Masukkan nama dasar file kunci (tanpa ekstensi): ").strip()
    if base_name == "":
        print("Nama dasar kosong. Kunci tidak disimpan.")
        return
    save_keys(pubkey, privkey, base_name)

# --------------------------
# Menu Utama Program
# --------------------------
def main():
    while True:
        print("\n=== Program RSA Sederhana ===")
        print("1. Pembuatan Kunci RSA")
        print("2. Enkripsi File")
        print("3. Dekripsi File")
        print("4. Keluar")
        pilihan = input("Pilih menu (1/2/3/4): ").strip()

        if pilihan == "1":
            generate_and_save_keys()
        elif pilihan == "2":
            encrypt_file()
        elif pilihan == "3":
            decrypt_file()
        elif pilihan == "4":
            print("Keluar program.")
            break
        else:
            print("Pilihan tidak valid, silakan pilih kembali.")

if __name__ == "__main__":
    main()
