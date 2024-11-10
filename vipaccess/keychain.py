import os
import subprocess
from base64 import b64decode

try:
    import qrcode
except ImportError:
    qrcode = None
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from vipaccess import provision as vp

# AES Key (Hex encoded)
AES_KEY = b'\xd0\xd0\xd0\xe0\xd0\xd0\xdf\xdf\xdf,4297\xd7\xae'


# Retrieve Serial Number
def get_serial_number():
    result = subprocess.run(
        ["ioreg", "-c", "IOPlatformExpertDevice", "-d", "2"],
        stdout=subprocess.PIPE,
        text=True
    )
    for line in result.stdout.splitlines():
        if "IOPlatformSerialNumber" in line:
            return line.split('"')[-2]
    return None


# Retrieve encrypted values
def get_encrypted_acct(label, keychain):
    result = subprocess.run(
        ["security", "find-generic-password", "-gl", label, keychain],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    if 'acct"<blob>' in result.stdout:
        for line in result.stdout.splitlines():
            if 'acct"<blob>' in line:
                return line.split('"')[3]
    return None


# Retrieve encrypted values
def get_encrypted_value(label, keychain):
    result = subprocess.run(
        ["security", "find-generic-password", "-gl", label, keychain],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    if "password:" in result.stderr:
        return result.stderr.split('"')[1]
    return None


# Decrypt ID_CRYPT with padding
def decrypt_aes_128_cbc(data, key):
    backend = default_backend()
    iv = bytes(16)  # Initialization vector of zeros
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(b64decode(data)) + decryptor.finalize()
    return decrypted[:-ord(decrypted[-1:])]


def get_credential_from_keychain():
    serial_number = get_serial_number()
    # Keychain path and password
    keychain = f"/Users/{os.getenv('USER')}/Library/Keychains/VIPAccess.keychain"
    keychain_password = f"{serial_number}SymantecVIPAccess{os.getenv('USER')}"
    # Unlock Keychain
    subprocess.run(["security", "unlock-keychain", "-p", keychain_password, keychain])
    id_crypt = get_encrypted_acct("CredentialStore", keychain)
    key_crypt = get_encrypted_value("CredentialStore", keychain)
    # Lock Keychain
    subprocess.run(["security", "lock-keychain", keychain])
    id_plain = decrypt_aes_128_cbc(id_crypt, AES_KEY).decode('utf-8').removesuffix('Symantec')
    key_plain = decrypt_aes_128_cbc(key_crypt, AES_KEY).hex()
    d = {'id': id_plain, 'period': 30, 'digits': 6, 'algorithm': 'SHA1'}
    key_bytes = bytearray.fromhex(key_plain)
    otp_uri = vp.generate_otp_uri(d, key_bytes)
    print(otp_uri)
    if qrcode:
        print()
        q = qrcode.QRCode()
        q.add_data(otp_uri)
        q.print_ascii(invert=True)

