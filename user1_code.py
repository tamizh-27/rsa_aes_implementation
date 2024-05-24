from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as padAes
from cryptography.hazmat.primitives import hashes
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
import socket
import pickle

def encrypt_data(key, message):
    # Generate a random IV (Initialization Vector)
    iv = os.urandom(16)
    
    # Create a cipher object using AES in CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    
    # Perform encryption
    encryptor = cipher.encryptor()
    padder = padAes.PKCS7(128).padder()
    padded_data = padder.update(message) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    return ciphertext, iv

def decrypt_data(key, iv, ciphertext):
    # Create a cipher object using AES in CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    
    # Perform decryption
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padAes.PKCS7(128).unpadder()
    message = unpadder.update(decrypted_data) + unpadder.finalize()
    
    return message


def generate_rsa_key_pair():
    # Generate RSA key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    
    return private_key, public_key

def rsa_encrypt(public_key, message):
    # Encrypt message using RSA public key
    ciphertext = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    return ciphertext

def rsa_decrypt(private_key, ciphertext):
    # Decrypt message using RSA private key
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    return plaintext

# Create a socket object
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Get local machine name
host = "localhost"
port = 12345  # Port to connect to

# Connect to the server
client_socket.connect((host, port))


while True:    
    # generating keys
    private_key, public_key = generate_rsa_key_pair()
    aes_key = os.urandom(32)  # AES-256 key    
    
    privatePem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

    publicPem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    # getting user2 public key
    user2_publicPem = client_socket.recv(2048).decode()
    
    # converting user2 publicPem to public key 
    user2_publicKey = serialization.load_pem_public_key(user2_publicPem.encode())
    
    # send a message to user2
    message = input("Enter the message: ").encode()
    
    # encrypt the message with aes key
    ciphertext, iv = encrypt_data(aes_key, message)
    
    # encrypting aes key with rsa public key of user2
    rsa_encrypted_aes_key = rsa_encrypt(user2_publicKey, aes_key)
    
    # data to be send to user2
    data_to_send = pickle.dumps((ciphertext, rsa_encrypted_aes_key, publicPem, iv))
    
    # sending the data
    client_socket.sendall(data_to_send)
    
    #==============================================================#

    # receive the user2 response
    response = client_socket.recv(2048)
    
    user2_ciphertext, user2_rsa_encrypted_aes_key, user2_publicPem, user2_iv = pickle.loads(response)
    print("Cipher text of user2 :",user2_ciphertext)
    
    # decrypting aes key with rsa private key of user1
    rsa_decrypted_aes_key = rsa_decrypt(private_key, user2_rsa_encrypted_aes_key)
    
    # decrypting the message with aes key
    decrypted_data = decrypt_data(rsa_decrypted_aes_key, user2_iv, user2_ciphertext)

    #print("Private Key : " , privatePem)
    #print("Encrypted AES Key : " , rsa_decrypted_aes_key)
    print("Decrypted message :",decrypted_data.decode())

    if not message:
        break

# close the connection
client_socket.close()