import threading
import time
from teenycoinc import *

def pretty(s):
    print(f"\n>>> {s}")

def choose_host_port(default_host="127.0.0.1", default_port=5000):
    host = input(f"Host (default {default_host}): ") or default_host
    port = input(f"Port (default {default_port}): ") or str(default_port)
    return host, int(port)

if __name__ == "__main__":
    blockchain = Blockchain(create_genesis=False)            # uses UTXO backend
    blockchain.load_from_file()
    node = None

    def create_wallet():
        sk_hex, pk_hex = generate_keys()
        addr = address_from_pubkey_hex(pk_hex)
        pretty("Wallet created:")
        print("  Private key (hex):", sk_hex)
        print("  Public  key (hex):", pk_hex)
        print("  Address:", addr)
        return sk_hex, pk_hex, addr

    def create_node():
        global node
        host, port = choose_host_port()
        node = PeerNode(host, port, blockchain)
        # start() spins a server thread inside; it's already daemon-friendly
        node.start()
        pretty(f"Node started at {host}:{port}")
        return node

    def connect_peer():
        if not node:
            pretty("Start a node first.")
            return
        host, port = choose_host_port()
        node.connect_peer(host, port)
        pretty(f"Connected to peer {host}:{port}")

    def find_utxos_for_address(address):
        # returns list of (txid, idx, TxOutput)
        res = []
        for (txid, idx), out in blockchain.utxos.utxos.items():
            if out.recipient == address:
                res.append((txid, idx, out))
        return res

    def send_coins():
        if not node:
            pretty("You need to create a node first!")
            return

        sk_hex = input("Enter YOUR private key (hex): ").strip()
        try:
            sk = SigningKey.from_string(bytes.fromhex(sk_hex), curve=SECP256k1)
            sender_pub_hex = sk.get_verifying_key().to_string().hex()
        except Exception as e:
            pretty("Invalid private key format.")
            return

        sender_addr = address_from_pubkey_hex(sender_pub_hex)
        pretty(f"Using address: {sender_addr}")

        recipient_addr = input("Recipient address (base58check): ").strip()
        if not recipient_addr:
            pretty("Recipient required.")
            return

        try:
            amount = int(float(input("Amount (integer): ").strip()))
        except:
            pretty("Bad amount; use integer numbers for now.")
            return

        # find a UTXO with enough funds (simple single-input tx)
        utxos = find_utxos_for_address(sender_addr)
        if not utxos:
            pretty("No UTXOs for your address. Fund it first (mine or receive).")
            return

        chosen = None
        for txid, idx, out in utxos:
            if out.amount >= amount:
                chosen = (txid, idx, out)
                break
        if not chosen:
            pretty("No single UTXO large enough. Split-change txs not supported by CLI yet.")
            return

        txid_prev, idx_prev, prev_out = chosen
        inp = TxInput(txid_prev, idx_prev)
        outs = [TxOutput(amount, recipient_addr)]
        change = prev_out.amount - amount
        if change > 0:
            outs.append(TxOutput(change, sender_addr))

        tx = Transaction([inp], outs)
        # sign the sole input (index 0)
        tx.sign_input(0, sk_hex)

        try:
            blockchain.add_transaction(tx)
            pretty(f"Transaction added to mempool: {tx.txid}")
            # broadcast to peers
            if node:
                node.broadcast({'type': 'new_tx', 'tx': tx.to_dict()})
        except Exception as e:
            pretty(f"Failed to add transaction: {e}")

    def mine_once():
        if not node:
            pretty("You need to create a node first!")
            return
        miner_pubkey = input("Enter your PUBLIC KEY (hex) to receive the block reward: ").strip()
        if not miner_pubkey:
            pretty("Public key required.")
            return
        miner_addr = address_from_pubkey_hex(miner_pubkey)
        pretty(f"Mining to address: {miner_addr} ...")
        blk = blockchain.mine_pending(miner_addr)
        if blk:
            pretty(f"Mined block #{blk.index} {blk.hash}")
            # broadcast block
            if node:
                node.broadcast({'type': 'new_block', 'block': blk.to_dict()})
        else:
            pretty("No block mined (maybe invalid/mempool empty).")
        blockchain.save_to_file()

    def mine_hundred():
         if not node:
            pretty("You need to create a node first!")
            return
         miner_pubkey = input("Enter your PUBLIC KEY (hex) to receive the block reward: ").strip()
         if not miner_pubkey:
            pretty("Public key required.")
            return
         for i in range(100):
            miner_addr = address_from_pubkey_hex(miner_pubkey)
            pretty(f"Mining to address: {miner_addr} ...")
            blk = blockchain.mine_pending(miner_addr)
            if blk:
                pretty(f"Mined block #{blk.index} {blk.hash}")
                # broadcast block
                if node:
                    node.broadcast({'type': 'new_block', 'block': blk.to_dict()})
            else:
                pretty("No block mined (maybe invalid/mempool empty).")
            blockchain.save_to_file()

    def view_balance():
        addr = input("Enter address to check balance (base58check): ").strip()
        if not addr:
            pretty("Address required.")
            return
        bal = blockchain.get_balance(addr)
        pretty(f"Balance for {addr}: {bal}")

    def show_menu():
        print("\n--- TeenyCoin CLI ---")
        print("1) Create Wallet")
        print("2) Create Node (start server)")
        print("3) Connect to Peer")
        print("4) Send Coins")
        print("5) Mine One Block")
        print("6) Mine 100 Blocks")
        print("7) View Balance")
        print("8) Quit")
        print("--------------------")

    # CLI loop
    while True:
        show_menu()
        choice = input("Choose: ").strip()
        if choice == "1":
            create_wallet()
        elif choice == "2":
            create_node()
        elif choice == "3":
            connect_peer()
        elif choice == "4":
            send_coins()
        elif choice == "5":
            mine_once()
        elif choice == "6":
            mine_hundred()
        elif choice == "7":
            view_balance()
        elif choice == "8":
            pretty("Bye.")
            break
        else:
            pretty("Invalid choice.")
