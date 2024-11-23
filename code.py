import ssl
import socket
from cryptography.hazmat.primitives.asymmetric import padding

# Function to sign a message using RSA private key
def sign_message(private_key, message):
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

# Function to verify signature using RSA public key
def verify_signature(public_key, message, signature):
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except:
        return False

# Generate RSA key pair for digital signatures
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
public_key = private_key.public_key()

# Serialize public key
public_key_bytes = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Simulate sending public key to other party (over insecure channel)
# Other party will deserialize this public key and use it to verify the signature

# Encrypt message
message = b"Hello, this is a secret message."
iv = os.urandom(16)
cipher = Cipher(algorithms.AES(encryption_key), modes.CFB(iv), backend=default_backend())
encryptor = cipher.encryptor()
ciphertext = encryptor.update(message) + encryptor.finalize()

# Sign the message
signature = sign_message(private_key, message)

# Create SSL context
context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.verify_mode = ssl.CERT_REQUIRED
context.check_hostname = True
context.load_verify_locations("/path/to/ca_certificate.pem")  # Specify path to CA certificate

# Connect to server
with socket.create_connection(("server_address", 443)) as sock:
    with context.wrap_socket(sock, server_hostname="server_hostname") as ssock:
        # Send ciphertext, IV, and signature to other party (over secure channel)
        ssock.sendall(ciphertext)
        ssock.sendall(iv)
        ssock.sendall(signature)

        # Receive response from other party
        response = ssock.recv(4096)

        # Decrypt response
        decryptor = cipher.decryptor()
        decrypted_response = decryptor.update(response) + decryptor.finalize()
        print("Decrypted response:", decrypted_response)
