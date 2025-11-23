import hashlib
import json
import time
from ecdsa import SigningKey, SECP256k1, VerifyingKey
import random
import socket
import threading

# Transaction class
class Transaction:
    def __init__(self, sender_pubkey, recipient_pubkey, amount, fee=0, signature=None):
        self.sender = sender_pubkey  # hex string
        self.recipient = recipient_pubkey  # hex string
        self.amount = amount
        self.fee = fee  # transaction fee
        self.signature = signature  # hex string

    def to_dict(self):
        return {
            'sender': self.sender,
            'recipient': self.recipient,
            'amount': self.amount,
            'fee': self.fee,
            'signature': self.signature,
        }

    def compute_hash(self):
        tx_str = json.dumps({
            'sender': self.sender,
            'recipient': self.recipient,
            'amount': self.amount,
            'fee': self.fee
        }, sort_keys=True)
        return hashlib.sha256(tx_str.encode()).hexdigest()

    def sign(self, private_key):
        sk = SigningKey.from_string(bytes.fromhex(private_key), curve=SECP256k1)
        h = self.compute_hash()
        signature = sk.sign(h.encode())
        self.signature = signature.hex()

    def verify(self):
        if self.sender == "0":  # Mining reward (no sender)
            return True
        if not self.signature:
            return False
        vk = VerifyingKey.from_string(bytes.fromhex(self.sender), curve=SECP256k1)
        try:
            return vk.verify(bytes.fromhex(self.signature), self.compute_hash().encode())
        except:
            return False

# Block class
class Block:
    def __init__(self, index, timestamp, transactions, previous_hash='', difficulty=5):
        self.index = index
        self.timestamp = timestamp
        self.transactions = transactions  # list of Transaction objects
        self.previous_hash = previous_hash
        self.nonce = 0
        self.difficulty = difficulty
        self.hash = self.compute_hash()

    def compute_hash(self):
        block_data = {
            'index': self.index,
            'timestamp': self.timestamp,
            'transactions': [tx.to_dict() for tx in self.transactions],
            'previous_hash': self.previous_hash,
            'nonce': self.nonce,
        }
        block_string = json.dumps(block_data, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    def mine(self):
        prefix = '0' * self.difficulty
        while not self.hash.startswith(prefix):
            self.nonce += 1
            self.hash = self.compute_hash()
        print(f"Block {self.index} mined: {self.hash} (nonce: {self.nonce})")

# Blockchain class
class Blockchain:
    def __init__(self, difficulty=5, mining_reward=1, max_supply=10000000):
        self.chain = []
        self.difficulty = difficulty
        self.mining_reward = mining_reward
        self.max_supply = max_supply
        self.total_supply = 0
        self.pending_transactions = []
        self.peers = []
        self.block_time = 10  # target 5 secs per block
        self.create_genesis_block()

    # New method to adjust difficulty dynamically
    def adjust_difficulty(self, window=100, dampening=0.25, max_change=1.25):
        if len(self.chain) <= window:
            return  # Not enough blocks yet

        latest_block = self.chain[-1]
        past_block = self.chain[-window - 1]

        actual_time = latest_block.timestamp - past_block.timestamp
        expected_time = self.block_time * window

        ratio = actual_time / expected_time

        # Apply dampening so we don't overreact
        adjustment_factor = ratio ** (-dampening)

        # Cap adjustment to avoid big swings
        adjustment_factor = max(1 / max_change, min(max_change, adjustment_factor))

        # Update difficulty smoothly
        new_difficulty = self.difficulty * adjustment_factor
        self.difficulty = max(1, int(new_difficulty))

        print(f"Difficulty adjusted to {self.difficulty:.2f}")

    def create_genesis_block(self):
        genesis_block = Block(0, time.time(), [], "0", self.difficulty)
        genesis_block.mine()
        self.chain.append(genesis_block)
        self.total_supply = self.mining_reward  # Initial supply after mining genesis block

    def get_last_block(self):
        return self.chain[-1]

    def mine_pending_transactions(self, miner_pubkey):
        if self.total_supply >= self.max_supply:
            print("Max supply reached! No more coins can be mined.")
            return

        # Add mining reward tx
        reward_tx = Transaction("0", miner_pubkey, self.mining_reward)
        self.pending_transactions.append(reward_tx)

        # Add transaction fees as part of miner's reward
        total_fees = sum(tx.fee for tx in self.pending_transactions)
        reward_tx = Transaction("0", miner_pubkey, total_fees, fee=0)
        self.pending_transactions.append(reward_tx)

        block = Block(
            index=self.get_last_block().index + 1,
            timestamp=time.time(),
            transactions=self.pending_transactions,
            previous_hash=self.get_last_block().hash,
            difficulty=self.difficulty  # Use current difficulty here
        )
        block.mine()
        self.chain.append(block)
        self.pending_transactions = []

        # Update total supply after mining a block
        self.total_supply += self.mining_reward + total_fees
        if self.total_supply > self.max_supply:
            print("Warning: Total supply exceeded max supply! Something went wrong.")
            self.total_supply = self.max_supply

        print(f"Mining completed, new block added. Total supply: {self.total_supply}")

        # Adjust difficulty after adding the new block
        self.adjust_difficulty()

    def get_balance(self, pubkey):
        balance = 0
        for block in self.chain:
            for tx in block.transactions:
                if tx.sender == pubkey:
                    balance -= (tx.amount + tx.fee)
                if tx.recipient == pubkey:
                    balance += tx.amount
        # Pending tx
        for tx in self.pending_transactions:
            if tx.sender == pubkey:
                balance -= (tx.amount + tx.fee)
        return balance

    def add_transaction(self, transaction):
        if not transaction.sender or not transaction.recipient:
            raise Exception("Transaction must include sender and recipient")
        if not transaction.verify():
            raise Exception("Invalid transaction signature")
        if self.get_balance(transaction.sender) < (transaction.amount + transaction.fee):
            raise Exception("Not enough balance")
        self.pending_transactions.append(transaction)

    def is_chain_valid(self):
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            prev = self.chain[i-1]

            if current.hash != current.compute_hash():
                return False
            if current.previous_hash != prev.hash:
                return False
            # Check with block's own difficulty instead of global difficulty
            if not current.hash.startswith('0' * current.difficulty):
                return False

            for tx in current.transactions:
                if not tx.verify():
                    return False

        return True

    def add_peer(self, peer):
        self.peers.append(peer)

    def broadcast_new_block(self, block):
        for peer in self.peers:
            peer.receive_block(block)

    def receive_block(self, block):
        # Simple consensus: accept block if it's valid and the longest chain
        if block.index > len(self.chain):
            self.chain.append(block)
            self.broadcast_new_block(block)

# Wallet helpers
def generate_keys():
    sk = SigningKey.generate(curve=SECP256k1)
    vk = sk.get_verifying_key()
    return sk.to_string().hex(), vk.to_string().hex()

class PeerNode:
    def __init__(self, host, port, blockchain):
        self.host = host  # local IP address
        self.port = port  # local port
        self.peers = []  # List of peer nodes
        self.socket = None
        self.blockchain = blockchain  # Reference to the blockchain

    def start_server(self):
        """Start listening for incoming connections (peers)."""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind((self.host, self.port))
        self.socket.listen(5)
        print(f"Listening on {self.host}:{self.port}")

        while True:
            conn, addr = self.socket.accept()
            print(f"Connection received from {addr}")
            threading.Thread(target=self.handle_peer_connection, args=(conn, addr)).start()

    def handle_peer_connection(self, conn, addr):
        """Handle the connection from a peer node."""
        data = conn.recv(1024).decode()
        if data:
            message = json.loads(data)
            if message.get('type') == 'new_block':
                self.receive_block(message['block'])
        conn.close()

    def send_to_peer(self, peer_ip, peer_port, message):
        """Send a message to a specific peer."""
        peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        peer_socket.connect((peer_ip, peer_port))
        peer_socket.send(json.dumps(message).encode())
        peer_socket.close()

    def receive_block(self, block):
        """Receive and validate a new block from a peer."""
        print("Received block from peer: ", block)

        # Simple validation: make sure the block has the correct previous hash
        # (You can add more validation logic here like checking hash correctness, etc.)

        # Add block to the local chain if valid
        self.blockchain.receive_block(block)

    def broadcast_new_block(self, block):
        """Broadcast a newly mined block to all peers."""
        message = {
            'type': 'new_block',
            'block': block
        }
        for peer in self.peers:
            self.send_to_peer(peer['host'], peer['port'], message)
