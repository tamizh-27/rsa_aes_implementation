Description:
RSA is an asymmetric algorithm and AES is a symmetric algorithm. A hybrid approach using both algorithms has been implemented.

Process:
The message is encrypted using AES.
The AES key is encrypted with the RSA private key.
The public keys of both users are exchanged.
The encrypted AES key is decrypted using the RSA public key.
The decrypted AES key is then used to decrypt the message.

Note:
RSA private keys are typically stored locally for security. However, since this implementation is done using Python, local storage of the RSA private keys is not necessary.
Run user2_code.py first then user1_code.py
