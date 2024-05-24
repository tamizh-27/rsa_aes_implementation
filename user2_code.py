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
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Get local machine name
host = "localhost"
port = 12345  # Port to listen on

# Bind to the port
server_socket.bind((host, port))

# Listen for incoming connections
server_socket.listen(5)

#print("Server listening on {}:{}".format(host, port))

# Accept incoming connections
client_socket, addr = server_socket.accept()
print("Connection from", addr)

print("Connection established")

while True:
    # generating keys
    private_key, public_key = generate_rsa_key_pair()
    
    privatePem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

    publicPem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
    # sharing public key to user1
    client_socket.send(publicPem)
    #print("Public key shared to user1")
    
    # receive message from user1
    message = client_socket.recv(2048)
    
    user1_ciphertext, user1_rsa_encrypted_aes_key, user1_publicPem, user1_iv = pickle.loads(message)
    print("Cipher text of user1 :",user1_ciphertext)
    
    # decrypting aes key with rsa private key of user2
    rsa_decrypted_aes_key = rsa_decrypt(private_key, user1_rsa_encrypted_aes_key)
    
    # decrypting the message with aes key
    decrypted_data = decrypt_data(rsa_decrypted_aes_key, user1_iv, user1_ciphertext)
    print("Decrypted message :",decrypted_data.decode())

    if not message:
        break
    
    #=========================================================#
    
    # converting user1 publicPem to public key 
    user1_publicKey = serialization.load_pem_public_key(user1_publicPem)
    
    # sending response to user1
    message = input("Enter the message : ").encode()
    
    # encrypt the message with aes key
    aes_key = os.urandom(32)  # AES-256 key    
    ciphertext, iv = encrypt_data(aes_key, message)
    
    # encrypting aes key with rsa public key of user1
    rsa_encrypted_aes_key = rsa_encrypt(user1_publicKey, aes_key)
    
    # message to be send to user1
    data_to_send = pickle.dumps((ciphertext, rsa_encrypted_aes_key, publicPem, iv))
    
    # sending the message
    client_socket.sendall(data_to_send)
    
# Close the connection
client_socket.close()