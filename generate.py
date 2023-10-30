from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import string
import secrets
import random


def encrypt_aes(message, key):
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(message)
    return (ciphertext, nonce, tag)


def decrypt_aes(encrypted_message, key):
    cipher = AES.new(key, AES.MODE_EAX, nonce=encrypted_message['nonce'])
    plaintext = cipher.decrypt(encrypted_message['ciphertext'])
    try:
        cipher.verify(encrypted_message['tag'])
        print("Decriptare AES: mesaj nemodificat")
    except ValueError:
        print("Decriptare AES: mesaj modificat")
    return plaintext


# generare cheie rsa
def generate_and_exportKey_rsa(filename):
    f = open(filename, 'wb')
    key = RSA.generate(2048)
    f.write(key.export_key('PEM'))
    f.close()
    return key


# citire cheie rsa
def importKey_rsa(filename):
    f = open(filename, 'r')
    key = RSA.import_key(f.read())
    f.close()
    return key


def importKey_rsa_from_text(message):
    return RSA.import_key(message)


def savePublicKey_rsa(key, filename):
    f = open(filename, 'wb')
    f.write(key.publickey().export_key('PEM'))
    f.close()
    return key.publickey().export_key()


def importPublicKey_rsa(filename):
    f = open(filename, 'rb')
    key = RSA.import_key(f.read())
    f.close()
    return key


def encrypt_rsa(message, key):
    cipher = PKCS1_OAEP.new(key)
    return cipher.encrypt(message)


def decrypt_rsa(message, key):
    cipher = PKCS1_OAEP.new(key)
    return cipher.decrypt(message)


def sign(message, key_file):
    key = RSA.import_key(open(key_file).read())
    h = SHA256.new(message)
    return pkcs1_15.new(key).sign(h)


def verify_signature(message, signature, key_file):
    key = importPublicKey_rsa(key_file)

    h = SHA256.new(message)
    try:
        pkcs1_15.new(key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False


def generate_ccode():
    length = random.randint(4, 10)
    alphabet = string.ascii_letters + string.digits
    random_string = ''.join(secrets.choice(alphabet) for _ in range(length))
    f = open("cCode.txt", 'w')
    f.write(random_string)
    f.close()
    return random_string
