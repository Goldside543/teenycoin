from teenycoinc import *

if __name__ == "__main__":
    blockchain = Blockchain()
    node = None

    def create_wallet():
        private_key, public_key = generate_keys()
        print(f"Private Key: {private_key}")
        print(f"Public Key: {public_key}")
        return private_key, public_key

    def create_node():
        global node
        host = input("Enter host (default: 127.0.0.1): ") or "127.0.0.1"
        port = int(input("Enter port (default: 5000): ") or 5000)
        node = PeerNode(host=host, port=port, blockchain=blockchain)
        threading.Thread(target=node.start_server, daemon=True).start()
        print(f"Node started at {host}:{port}")

    def send_coins():
        if not node:
            print("You need to create a node first!")
            return
        private_key = input("Enter your private key: ")
        recipient_pubkey = input("Enter the recipient's public key: ")
        amount = float(input("Enter the amount to send: "))
        fee = float(input("Enter the transaction fee (default: 0): ") or 0)

        tx = Transaction(sender_pubkey=private_key, recipient_pubkey=recipient_pubkey, amount=amount, fee=fee)
        tx.sign(private_key)
        try:
            blockchain.add_transaction(tx)
            print("Transaction added.")
        except Exception as e:
            print(f"Error adding transaction: {e}")

    def mine_transactions():
        if not node:
            print("You need to create a node first!")
            return
        miner_pubkey = input("Enter your public key to receive mining reward: ")

        for i in range(200):
            blockchain.mine_pending_transactions(miner_pubkey)
            node.broadcast_new_block(blockchain.chain[-1])

    def view_balance():
        pubkey = input("Enter the public key to check balance: ")
        balance = blockchain.get_balance(pubkey)
        print(f"Balance of {pubkey}: {balance} coins")

    def show_menu():
        print("\n--- Blockchain Commands ---")
        print("1. Create Wallet")
        print("2. Create Node")
        print("3. Send Coins")
        print("4. Mine Transactions")
        print("5. View Balance")
        print("6. Exit")
        print("---------------------------")

    while True:
        show_menu()
        choice = input("Choose an option: ")

        if choice == "1":
            create_wallet()
        elif choice == "2":
            create_node()
        elif choice == "3":
            send_coins()
        elif choice == "4":
            mine_transactions()
        elif choice == "5":
            view_balance()
        elif choice == "6":
            print("Exiting...")
            break
        else:
            print("Invalid option. Try again.")
