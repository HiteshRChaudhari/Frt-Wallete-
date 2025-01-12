import os
import qrcode
from ecdsa import SigningKey, SECP256k1
import hashlib
import json
import requests
from base64 import b64encode
import cv2
from cryptography.fernet import Fernet

# Constants for Future (FTR) blockchain API
MAINNET_API = "https://api.futureblockchain.io"
TESTNET_API = "https://testnet.futureblockchain.io"

class Wallet:
def __init__(self, private_key=None, network="mainnet"):
self.network = network
self.api_url = MAINNET_API if network == "mainnet" else TESTNET_API
        if private_key:
self.private_key = SigningKey.from_string(bytes.fromhex(private_key), curve=SECP256k1)
        else:
self.private_key = SigningKey.generate(curve=SECP256k1)
self.public_key = self.private_key.get_verifying_key().to_string().hex()
self.address = self.generate_address()

def generate_address(self):
public_key_bytes = bytes.fromhex(self.public_key)
sha256_hash = hashlib.sha256(public_key_bytes).digest()
ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()
        return ripemd160_hash.hex()

def export_private_key(self):
        return self.private_key.to_string().hex()

def encrypt_private_key(self, password):
key = hashlib.sha256(password.encode()).digest()
cipher = Fernet(b64encode(key[:32]))
        return cipher.encrypt(self.private_key.to_string()).decode()

def decrypt_private_key(self, encrypted_key, password):
key = hashlib.sha256(password.encode()).digest()
cipher = Fernet(b64encode(key[:32]))
self.private_key = SigningKey.from_string(cipher.decrypt(encrypted_key.encode()), curve=SECP256k1)
self.public_key = self.private_key.get_verifying_key().to_string().hex()
self.address = self.generate_address()

def get_balance(self):
response = requests.get(f"{self.api_url}/address/{self.address}/balance")
        if response.status_code == 200:
        return response.json().get("balance", 0)
        return 0

def get_transaction_history(self):
response = requests.get(f"{self.api_url}/address/{self.address}/transactions")
        if response.status_code == 200:
        return response.json().get("transactions", [])
        return []

def send_transaction(self, to_address, amount):
transaction = {
        "from": self.address,
        "to": to_address,
        "amount": amount,
        }
transaction_bytes = json.dumps(transaction, sort_keys=True).encode('utf-8')
signature = b64encode(self.private_key.sign(transaction_bytes)).decode('utf-8')
transaction["signature"] = signature

        response = requests.post(f"{self.api_url}/transaction/send", json=transaction)
        if response.status_code == 200:
        return response.json()
        return response.text

def switch_network(self, network):
        if network not in ["mainnet", "testnet"]:
raise ValueError("Invalid network. Choose 'mainnet' or 'testnet'.")
self.network = network
self.api_url = MAINNET_API if network == "mainnet" else TESTNET_API

# QR Code Utilities
def create_qr_code(data, filename):
qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
        )
    qr.add_data(data)
    qr.make(fit=True)

img = qr.make_image(fill_color="black", back_color="white")
    img.save(filename)
print(f"QR Code saved to {filename}")

def scan_qr_code(filename):
img = cv2.imread(filename)
detector = cv2.QRCodeDetector()
data, _, _ = detector.detectAndDecode(img)
    return data if data else None

# Example Usage
if __name__ == "__main__":
        # Create a new wallet
        wallet = Wallet()
print("Wallet Address:", wallet.address)
print("Private Key:", wallet.export_private_key())

        # Encrypt private key
        encrypted_key = wallet.encrypt_private_key("password123")
print("Encrypted Private Key:", encrypted_key)

    # Decrypt private key
    wallet.decrypt_private_key(encrypted_key, "password123")
print("Decrypted Private Key:", wallet.export_private_key())

        # Check balance
balance = wallet.get_balance()
print("Wallet Balance:", balance)

    # Get transaction history
        transactions = wallet.get_transaction_history()
print("Transaction History:", transactions)

    # Send a transaction
        recipient_address = "recipient_address_here"
amount_to_send = 10
transaction_response = wallet.send_transaction(recipient_address, amount_to_send)
print("Transaction Response:", transaction_response)

    # Generate a QR code for an address
create_qr_code(wallet.address, "wallet_address_qr.png")

    # Scan a QR code
scanned_data = scan_qr_code("wallet_address_qr.png")
print("Scanned QR Code Data:", scanned_data)

    # Switch network
    wallet.switch_network("testnet")
print("Switched to Testnet. API URL:", wallet.api_url)
