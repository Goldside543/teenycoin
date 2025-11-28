import os
import hashlib, json, time, threading, socket
from ecdsa import SigningKey, VerifyingKey, SECP256k1
import binascii
from typing import List, Dict, Tuple

# ---------------------------
# Utility: base58check-like
# ---------------------------
ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()

def base58_encode(b: bytes) -> str:
    n = int.from_bytes(b, 'big')
    s = ""
    while n > 0:
        n, r = divmod(n, 58)
        s = ALPHABET[r] + s
    # leading zeros
    pad = 0
    for ch in b:
        if ch == 0:
            pad += 1
        else:
            break
    return ALPHABET[0] * pad + s

def base58check_encode(payload: bytes) -> str:
    checksum = sha256(sha256(payload))[:4]
    return base58_encode(payload + checksum)

def pubkey_to_address(pubkey_hex: str) -> str:
    pub_bytes = bytes.fromhex(pubkey_hex)
    h = hashlib.new('ripemd160', sha256(pub_bytes)).digest()
    # prefix 0x00 like Bitcoin (simple)
    return base58check_encode(b'\x00' + h)

# ---------------------------
# Transaction (UTXO model)
# ---------------------------
class TxInput:
    def __init__(self, txid: str, index: int, signature: str = None, pubkey: str = None):
        self.txid = txid  # hex string of previous tx hash
        self.index = index  # index into previous tx outputs
        self.signature = signature  # signature hex
        self.pubkey = pubkey  # public key hex (used to identify owner)

    def to_dict(self):
        return {
            'txid': self.txid,
            'index': self.index,
            'signature': self.signature,
            'pubkey': self.pubkey
        }

    @staticmethod
    def from_dict(d):
        return TxInput(d['txid'], d['index'], d.get('signature'), d.get('pubkey'))

class TxOutput:
    def __init__(self, amount: int, recipient_address: str):
        self.amount = amount
        self.recipient = recipient_address

    def to_dict(self):
        return {
            'amount': self.amount,
            'recipient': self.recipient
        }

    @staticmethod
    def from_dict(d):
        return TxOutput(d['amount'], d['recipient'])

class Transaction:
    def __init__(self, inputs: List[TxInput], outputs: List[TxOutput], timestamp=None):
        self.inputs = inputs
        self.outputs = outputs
        self.timestamp = timestamp or time.time()
        self.txid = self.compute_hash()

    def to_dict(self):
        return {
            'txid': self.txid,
            'inputs': [i.to_dict() for i in self.inputs],
            'outputs': [o.to_dict() for o in self.outputs],
            'timestamp': self.timestamp
        }

    @staticmethod
    def from_dict(d):
        inputs = [TxInput.from_dict(i) for i in d['inputs']]
        outputs = [TxOutput.from_dict(o) for o in d['outputs']]
        tx = Transaction(inputs, outputs, timestamp=d.get('timestamp'))
        tx.txid = d.get('txid') or tx.compute_hash()
        return tx

    def compute_hash(self) -> str:
        # canonical serialization excluding signatures (for signing)
        data = {
            'inputs': [{'txid': i.txid, 'index': i.index, 'pubkey': i.pubkey} for i in self.inputs],
            'outputs': [o.to_dict() for o in self.outputs],
            'timestamp': self.timestamp
        }
        return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()

    def sign_input(self, input_index: int, private_key_hex: str):
        sk = SigningKey.from_string(bytes.fromhex(private_key_hex), curve=SECP256k1)
        h = self.compute_hash().encode()
        signature = sk.sign(h).hex()
        self.inputs[input_index].signature = signature
        # include pubkey so others can verify
        self.inputs[input_index].pubkey = sk.get_verifying_key().to_string().hex()
        self.txid = self.compute_hash()

    def verify_input(self, input_index: int, utxo_set) -> bool:
        inp = self.inputs[input_index]
        key_hex = inp.pubkey
        if not key_hex or not inp.signature:
            return False
        # check that referenced UTXO exists and owned by this pubkey
        referenced = utxo_set.get_utxo(inp.txid, inp.index)
        if referenced is None:
            return False
        # check recipient of referenced UTXO corresponds to this pubkey's address
        addr = pubkey_to_address(key_hex)
        if referenced.recipient != addr:
            return False
        vk = VerifyingKey.from_string(bytes.fromhex(key_hex), curve=SECP256k1)
        try:
            return vk.verify(bytes.fromhex(inp.signature), self.compute_hash().encode())
        except:
            return False

    def verify(self, utxo_set) -> bool:
        # verify all inputs
        for idx, inp in enumerate(self.inputs):
            if inp.txid == "COINBASE":  # special coinbase input
                continue
            if not self.verify_input(idx, utxo_set):
                return False
        # check sum(inputs) >= sum(outputs)
        total_in = 0
        for inp in self.inputs:
            if inp.txid == "COINBASE":
                total_in += 0
                continue
            out = utxo_set.get_utxo(inp.txid, inp.index)
            if out is None:
                return False
            total_in += out.amount
        total_out = sum(o.amount for o in self.outputs)
        return total_in >= total_out

# ---------------------------
# UTXO Set
# ---------------------------
class UTXOSet:
    def __init__(self):
        # map (txid, index) -> TxOutput
        self.utxos: Dict[Tuple[str, int], TxOutput] = {}

    def add_utxo(self, txid: str, index: int, txout: TxOutput):
        self.utxos[(txid, index)] = txout

    def remove_utxo(self, txid: str, index: int):
        if (txid, index) in self.utxos:
            del self.utxos[(txid, index)]

    def get_utxo(self, txid: str, index: int):
        return self.utxos.get((txid, index))

    def apply_transaction(self, tx: Transaction):
        # remove inputs
        for inp in tx.inputs:
            if inp.txid == "COINBASE":
                continue
            self.remove_utxo(inp.txid, inp.index)
        # add outputs
        for i, out in enumerate(tx.outputs):
            self.add_utxo(tx.txid, i, out)

    def snapshot(self):
        # return a copy for validation attempts
        new = UTXOSet()
        new.utxos = dict(self.utxos)
        return new

# ---------------------------
# Block
# ---------------------------
class Block:
    def __init__(self, index: int, prev_hash: str, transactions: List[Transaction], difficulty=6, timestamp=None, nonce=0):
        self.index = index
        self.previous_hash = prev_hash
        self.transactions = transactions
        self.timestamp = timestamp or time.time()
        self.nonce = nonce
        self.difficulty = difficulty
        self.hash = self.compute_hash()

    def compute_hash(self) -> str:
        block_data = {
            'index': self.index,
            'previous_hash': self.previous_hash,
            'transactions': [tx.to_dict() for tx in self.transactions],
            'timestamp': self.timestamp,
            'nonce': self.nonce
        }
        return hashlib.sha256(json.dumps(block_data, sort_keys=True).encode()).hexdigest()

    def mine(self):
        prefix = '0' * self.difficulty
        while not self.hash.startswith(prefix):
            self.nonce += 1
            self.hash = self.compute_hash()
        print(f"Mined block {self.index} {self.hash} nonce={self.nonce}")

    def to_dict(self):
        return {
            'index': self.index,
            'previous_hash': self.previous_hash,
            'transactions': [tx.to_dict() for tx in self.transactions],
            'timestamp': self.timestamp,
            'nonce': self.nonce,
            'difficulty': self.difficulty,
            'hash': self.hash
        }

    @staticmethod
    def from_dict(d):
        txs = [Transaction.from_dict(t) for t in d['transactions']]
        blk = Block(d['index'], d['previous_hash'], txs, difficulty=d.get('difficulty',3), timestamp=d.get('timestamp'), nonce=d.get('nonce',0))
        blk.hash = d.get('hash') or blk.compute_hash()
        return blk

# ---------------------------
# Mempool
# ---------------------------
class Mempool:
    def __init__(self):
        # txid -> tx
        self.txs: Dict[str, Transaction] = {}
        # track UTXOs reserved by mempool to avoid double spend
        self.reserved_utxos: Dict[Tuple[str,int], str] = {}

    def add_tx(self, tx: Transaction, utxo_set: UTXOSet):
        # Basic validation: inputs exist, not reserved, and signatures valid
        for idx, inp in enumerate(tx.inputs):
            if inp.txid == "COINBASE":
                # coinbase only allowed in blocks
                raise Exception("Coinbase tx cannot be in mempool")
            k = (inp.txid, inp.index)
            if utxo_set.get_utxo(*k) is None:
                raise Exception("Referenced UTXO does not exist")
            if k in self.reserved_utxos:
                raise Exception("Referenced UTXO already reserved by mempool")
            # signature check (uses utxo_set)
            if not tx.verify_input(idx, utxo_set):
                raise Exception("Invalid signature for input")
        # mark utxos reserved
        for inp in tx.inputs:
            self.reserved_utxos[(inp.txid, inp.index)] = tx.txid
        self.txs[tx.txid] = tx

    def remove_tx(self, txid: str):
        tx = self.txs.pop(txid, None)
        if not tx:
            return
        for inp in tx.inputs:
            if (inp.txid, inp.index) in self.reserved_utxos:
                del self.reserved_utxos[(inp.txid, inp.index)]

    def get_all(self):
        return list(self.txs.values())

# ---------------------------
# Blockchain (with UTXO, mempool, reorg)
# ---------------------------
class Blockchain:
    def __init__(self, difficulty=6, mining_reward=1, max_supply=10000000, create_genesis=True):
        self.chain: List[Block] = []
        self.difficulty = difficulty
        self.mining_reward = mining_reward
        self.max_supply = max_supply
        self.total_supply = 0
        self.utxos = UTXOSet()
        self.mempool = Mempool()
        self.peers = []
        if create_genesis:
            self.create_genesis_block()

    def save_to_file(self, filename="teenycoin_chain.json"):
        data = {
            'chain': [blk.to_dict() for blk in self.chain],
            'utxos': {f"{txid}_{idx}": out.to_dict() for (txid, idx), out in self.utxos.utxos.items()},
            'total_supply': self.total_supply
        }
        with open(filename, "w") as f:
            json.dump(data, f, indent=4)
        print(f"Blockchain saved to {filename}")

    def load_from_file(self, filename="teenycoin_chain.json"):
        if not os.path.exists(filename):
            print(f"No blockchain file found at {filename}, starting fresh")
            return
        with open(filename, "r") as f:
            data = json.load(f)
        # load chain
        self.chain = [Block.from_dict(bd) for bd in data['chain']]
        # load UTXOs
        self.utxos = UTXOSet()
        for key, out_dict in data['utxos'].items():
            txid, idx = key.rsplit("_", 1)
            idx = int(idx)
            self.utxos.add_utxo(txid, idx, TxOutput.from_dict(out_dict))
        self.total_supply = data.get('total_supply', sum(o.amount for o in self.utxos.utxos.values()))
        print(f"Blockchain loaded from {filename}")

    def create_genesis_block(self):
        # Create a coinbase tx that issues some initial coins to a genesis address
        # Note: simplified coinbase uses txid "COINBASE"
        genesis_out = TxOutput(self.mining_reward, "GENESIS")
        coinbase = Transaction([TxInput("COINBASE", 0)], [genesis_out])
        coinbase.txid = "GENESIS_TX"
        blk = Block(0, "0", [coinbase], difficulty=self.difficulty)
        blk.mine()
        self.chain.append(blk)
        # update UTXO with the genesis output
        self.utxos.add_utxo(coinbase.txid, 0, genesis_out)
        self.total_supply = self.mining_reward
        self.save_to_file()

    def get_last_block(self):
        return self.chain[-1]

    def add_peer(self, peer_info):
        self.peers.append(peer_info)

    def validate_block(self, block: Block, utxo_snapshot: UTXOSet = None) -> bool:
        # validate proof-of-work
        if not block.hash.startswith('0' * block.difficulty):
            return False
        # validate previous hash
        if block.index == 0:
            return True
        prev = self.get_last_block()
        if block.previous_hash != prev.hash:
            # block doesn't attach to current tail; caller may handle reorg
            pass
        # validate transactions against a snapshot to avoid mutating main UTXO set during check
        utxo_check = (utxo_snapshot or self.utxos).snapshot()
        # coinbase must be first tx and may create new coins
        if len(block.transactions) == 0:
            return False
        # basic tx validation
        for tx in block.transactions:
            # coinbase tx handling
            if tx.inputs and tx.inputs[0].txid == "COINBASE":
                # allow coinbase; skip normal checks
                # ensure coinbase amount <= mining_reward + fees (we don't compute fees strictly here)
                # add to utxo
                for i, out in enumerate(tx.outputs):
                    utxo_check.add_utxo(tx.txid, i, out)
                continue
            # Non-coinbase tx must validate against utxo_check
            if not tx.verify(utxo_check):
                return False
            # apply tx to utxo_check
            for inp in tx.inputs:
                utxo_check.remove_utxo(inp.txid, inp.index)
            for i, out in enumerate(tx.outputs):
                utxo_check.add_utxo(tx.txid, i, out)
        return True

    def add_block(self, block: Block):
        # try to attach block: normal extension
        if block.previous_hash == self.get_last_block().hash:
            if not self.validate_block(block):
                print("Invalid block")
                return False
            # apply transactions to UTXO set
            for tx in block.transactions:
                self.utxos.apply_transaction(tx)
            self.chain.append(block)
            # remove mined txs from mempool
            for tx in block.transactions:
                if tx.txid in self.mempool.txs:
                    self.mempool.remove_tx(tx.txid)
            return True
        else:
            # possible reorg scenario: request chain from peer externally
            print("Block doesn't extend chain. Need reorg handling (incoming chain).")
            return False

    def mine_pending(self, miner_address):
        if self.total_supply + self.mining_reward > self.max_supply:
            print("Mining would exceed max supply, halting.")
            return None
        
        # create coinbase that collects fees + reward
        pending = self.mempool.get_all()
        total_fees = 0
        for tx in pending:
            # fees = inputs sum - outputs sum
            ins_sum = 0
            for inp in tx.inputs:
                out = self.utxos.get_utxo(inp.txid, inp.index)
                ins_sum += out.amount
            outs_sum = sum(o.amount for o in tx.outputs)
            total_fees += (ins_sum - outs_sum)
        coinbase_out = TxOutput(self.mining_reward + total_fees, miner_address)
        coinbase_tx = Transaction([TxInput("COINBASE", 0)], [coinbase_out])
        coinbase_tx.txid = f"COINBASE_{int(time.time())}"
        block = Block(self.get_last_block().index + 1, self.get_last_block().hash, [coinbase_tx] + pending, difficulty=self.difficulty)
        block.mine()
        # validate then apply
        if not self.validate_block(block):
            print("Mined block invalid")
            return False
        for tx in block.transactions:
            self.utxos.apply_transaction(tx)
        self.chain.append(block)
        # clear mempool
        self.mempool.txs.clear()
        self.mempool.reserved_utxos.clear()
        self.total_supply += self.mining_reward + total_fees
        return block

    def add_transaction(self, tx: Transaction):
        # attempt to add to mempool
        self.mempool.add_tx(tx, self.utxos)

    def replace_chain(self, new_chain: List[Block]):
        # naive: accept if longer and valid
        if len(new_chain) <= len(self.chain):
            return False
        # validate full chain from genesis
        utxo_temp = UTXOSet()
        # apply genesis (assumes genesis in pos 0)
        for blk in new_chain:
            if not self.validate_block(blk, utxo_temp):
                return False
            # apply to utxo_temp (mutating)
            for tx in blk.transactions:
                utxo_temp.apply_transaction(tx)
        # if we get here, adopt the new chain
        self.chain = new_chain
        self.utxos = utxo_temp
        # drop conflicting mempool transactions that spend now-nonexistent UTXOs
        for txid in list(self.mempool.txs.keys()):
            tx = self.mempool.txs[txid]
            try:
                self.mempool.add_tx(tx, self.utxos)
            except:
                self.mempool.remove_tx(txid)
        print("Chain replaced with longer valid chain.")
        return True

    def get_balance(self, address: str) -> int:
        total = 0
        for (txid, idx), out in self.utxos.utxos.items():
            if out.recipient == address:
                total += out.amount
        return total

# ---------------------------
# Simple P2P Node (JSON)
# ---------------------------
class PeerNode:
    def __init__(self, host: str, port: int, blockchain: Blockchain):
        self.host = host
        self.port = port
        self.blockchain = blockchain
        self.peers = []  # list of (host,port)
        self.sock = None
        self.running = False

    def start(self):
        self.running = True
        t = threading.Thread(target=self._server_loop, daemon=True)
        t.start()
        print(f"Node listening on {self.host}:{self.port}")

    def _server_loop(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind((self.host, self.port))
        s.listen(5)
        self.sock = s
        while self.running:
            conn, addr = s.accept()
            data = b""
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
            try:
                msg = json.loads(data.decode())
                self._handle_message(msg)
            except Exception as e:
                print("Failed to parse peer message:", e)
            conn.close()

    def _handle_message(self, msg):
        typ = msg.get('type')
        if typ == 'new_tx':
            tx = Transaction.from_dict(msg['tx'])
            try:
                self.blockchain.add_transaction(tx)
                print("Added tx from peer", tx.txid)
            except Exception as e:
                print("Rejected tx from peer:", e)
        elif typ == 'new_block':
            blk = Block.from_dict(msg['block'])
            ok = self.blockchain.add_block(blk)
            if ok:
                self.broadcast({'type': 'new_block', 'block': blk.to_dict()})
        elif typ == 'chain_request':
            # send chain
            chain_list = [b.to_dict() for b in self.blockchain.chain]
            self.broadcast({'type': 'chain_response', 'chain': chain_list})
        elif typ == 'chain_response':
            chain_list = [Block.from_dict(bd) for bd in msg['chain']]
            self.blockchain.replace_chain(chain_list)

    def broadcast(self, message):
        for (h, p) in list(self.peers):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((h, p))
                s.send(json.dumps(message).encode())
                s.close()
            except Exception as e:
                print("Failed to send to peer", (h,p), e)

    def connect_peer(self, host, port):
        self.peers.append((host, port))

# ---------------------------
# Wallet helpers
# ---------------------------
def generate_keys():
    sk = SigningKey.generate(curve=SECP256k1)
    vk = sk.get_verifying_key()
    return sk.to_string().hex(), vk.to_string().hex()

def address_from_pubkey_hex(pubkey_hex):
    return pubkey_to_address(pubkey_hex)
