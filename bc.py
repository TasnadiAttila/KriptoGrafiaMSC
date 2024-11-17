import hashlib
import json
import random
import string
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256


# Helper function to calculate hash using SHA-256
def calculate_hash(data):
    return hashlib.sha256(data.encode('utf-8')).hexdigest()


def generate_key_pair():
    key = RSA.generate(2048)
    private_key = key
    public_key = key.publickey()
    return private_key, public_key


# Function to create a digital signature using RSA
def sign_transaction(private_key, transaction_data):
    transaction_hash = SHA256.new(transaction_data.encode('utf-8'))
    signature = pkcs1_15.new(private_key).sign(transaction_hash)
    return signature.hex()  # Convert signature to hex for storage


def verify_signature(public_key, transaction_data, signature):
    transaction_hash = SHA256.new(transaction_data.encode('utf-8'))
    try:
        pkcs1_15.new(public_key).verify(transaction_hash, bytes.fromhex(signature))
        return True
    except (ValueError, TypeError):
        return False


# Function to create a Merkle root from a list of transactions
def create_merkle_root(transactions):
    if len(transactions) == 1:
        return transactions[0]

    new_level = []

    # Pair adjacent transactions, hash them together
    for i in range(0, len(transactions), 2):
        if i + 1 < len(transactions):
            combined_hash = calculate_hash(transactions[i] + transactions[i + 1])
        else:
            combined_hash = calculate_hash(transactions[i] + transactions[i])  # if odd, duplicate last one
        new_level.append(combined_hash)

    return create_merkle_root(new_level)


# Class representing a single Block
class Block:
    def __init__(self, index, transactions, previous_hash, difficulty=4):
        self.index = index
        self.transactions = transactions
        self.previous_hash = previous_hash
        self.nonce = 0
        self.difficulty = difficulty
        self.merkle_root = create_merkle_root([tx['signature'] for tx in self.transactions])
        self.hash = self.mine_block()

    def mine_block(self):
        while True:
            block_content = json.dumps(self.transactions, sort_keys=True) + self.previous_hash + str(self.nonce)
            block_hash = calculate_hash(block_content)

            if block_hash.startswith('0' * self.difficulty):
                return block_hash

            self.nonce += 1

    def __str__(self):
        return f"Block #{self.index}\nNonce: {self.nonce}\nTransactions: {self.transactions}\nPrevious Hash: {self.previous_hash}\nHash: {self.hash}\n"


# Blockchain class to hold all blocks
class Blockchain:
    def __init__(self):
        self.chain = []
        self.create_genesis_block()

    def create_genesis_block(self):
        genesis_block = Block(0, [
            {"sender": "genesis", "receiver": "genesis", "amount": 0, "signature": "genesis_signature", "public_key": "genesis_key"}], "0")
        self.chain.append(genesis_block)

    def add_block(self, transactions):
        previous_hash = self.chain[-1].hash

        # Verify each transaction's signature before adding the block
        for tx in transactions:
            transaction_data = f"{tx['sender']}->{tx['receiver']}:{tx['amount']}"
            public_key = RSA.import_key(tx['public_key'])  # Import the public key from the transaction
            if not verify_signature(public_key, transaction_data, tx['signature']):
                raise ValueError("Invalid signature for transaction!")

        new_block = Block(len(self.chain), transactions, previous_hash)
        self.chain.append(new_block)

    def is_chain_valid(self):
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]

            if current_block.hash != current_block.mine_block():
                return False

            if current_block.previous_hash != previous_block.hash:
                return False

        return True

    def print_chain(self):
        for block in self.chain:
            print(block)


def create_transaction(sender, receiver, amount, private_key, public_key):
    transaction_data = f"{sender}->{receiver}:{amount}"
    signature = sign_transaction(private_key, transaction_data)
    return {
        "sender": sender,
        "receiver": receiver,
        "amount": amount,
        "signature": signature,
        "public_key": public_key.export_key().decode('utf-8')  # Export public key as string
    }


def generate_password(length=12):
    lowercase = string.ascii_lowercase
    uppercase = string.ascii_uppercase
    digits = string.digits
    symbols = string.punctuation
    all_characters = lowercase + uppercase + digits + symbols

    password = [
        random.choice(lowercase),
        random.choice(uppercase),
        random.choice(digits),
        random.choice(symbols)
    ]

    password += random.choices(all_characters, k=length - 4)

    random.shuffle(password)
    return ''.join(password)


# Main function to run the blockchain
def main():
    # Initialize the blockchain
    blockchain = Blockchain()

    # Generate RSA key pairs for each participant
    private_keys = {}
    public_keys = {}

    for user in ["Alice", "Bob", "Charlie", "David", "Eve", "John", "Jack"]:
        private_key, public_key = generate_key_pair()
        private_keys[user] = private_key
        public_keys[user] = public_key

    # Create some transactions and add blocks
    transaction1 = create_transaction("Alice", "Bob", 10, private_keys["Alice"], public_keys["Alice"])
    transaction2 = create_transaction("Bob", "Charlie", 5, private_keys["Bob"], public_keys["Bob"])
    blockchain.add_block([transaction1, transaction2])

    transaction3 = create_transaction("Charlie", "David", 3, private_keys["Charlie"], public_keys["Charlie"])
    transaction4 = create_transaction("David", "Eve", 2, private_keys["David"], public_keys["David"])
    blockchain.add_block([transaction3, transaction4])

    transaction5 = create_transaction("Eve", "John", 3, private_keys["Eve"], public_keys["Eve"])
    transaction6 = create_transaction("John", "Jack", 2, private_keys["John"], public_keys["John"])
    blockchain.add_block([transaction5, transaction6])

    # Print out the blockchain
    blockchain.print_chain()

    # Check if the blockchain is valid
    print(f"Blockchain is valid: {blockchain.is_chain_valid()}")


if __name__ == "__main__":
    main()
