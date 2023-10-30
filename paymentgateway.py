import socket
import generate
import pickle

HOST, PORT = "localhost", 2222
privatePgKey = 'pg_private_key.pem'
publicPgKey = 'pg_public_key.pem'
publicKeyServer = 'server_public_key.pem'
publicKeyClient = 'client_public_key.pem'
key_gate = generate.generate_and_exportKey_rsa(privatePgKey)
generate.savePublicKey_rsa(key_gate, publicPgKey)
carduri = [
    {'owner': 'customer1',
     'cardN': '2378192819385938',
     'cardExp': '03/27',
     'balance': 40
     },
    {'owner': 'merchant1',
     'cardN': '3049263910103849',
     'cardExp': '10/30',
     'balance': 100
     }
]
exist_response = False


def update_Mbalance_given_owner(ownerName, sum):
    for card in carduri:
        if card['owner'] == ownerName:
            print("Balance merchant before:", card['balance'])
            card['balance'] += sum
            print("Balance merchant after", card['balance'])
            break


def update_Cbalance_given_cardN(cardN, sum):
    for card in carduri:
        if card['cardN'] == cardN:
            print("Balance customer before", card['balance'])
            card['balance'] -= sum
            print("Balance customer after", card['balance'])
            break


def find_balance_given_cardN(cardN):
    for card in carduri:
        if card['cardN'] == cardN:
            return card['balance']


def exist_card(cardN, cardExp):
    for card in carduri:
        if card['cardN'] == cardN and card['cardExp'] == cardExp:
            return True
    return False


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen(2)
    conn, addr = s.accept()
    with conn:
        print('Connected by', addr)
        while True:
            # Exchange Sub-protocol 4
            data = pickle.loads(conn.recv(10000))

            pubKM = generate.importPublicKey_rsa(publicKeyServer)

            AESkeyM = generate.decrypt_rsa(data['encryptedKey'], key_gate)
            encryptedMessage = {
                'ciphertext': data['encryptedOrder'][0],
                'nonce': data['encryptedOrder'][1],
                'tag': data['encryptedOrder'][2]
            }
            order = pickle.loads(generate.decrypt_aes(encryptedMessage, AESkeyM))
            # decrypt client message
            AESkeyC = generate.decrypt_rsa(order['encryptedPmKey'], key_gate)

            clientMessage = {
                'ciphertext': order['pm'][0],
                'nonce': order['pm'][1],
                'tag': order['pm'][2]
            }
            clientOrder = pickle.loads(generate.decrypt_aes(clientMessage, AESkeyC))
            # verify client signature
            if generate.verify_signature(clientOrder['pi'], clientOrder['signedPi'], publicKeyClient) is False:
                print("Invalid signature")
                conn.close()
            pi = pickle.loads(clientOrder['pi'])
            # verify merchant signature
            sigM = pickle.dumps({
                'sid': pi['sid'],
                'pubKC': pi['pubKC'],
                'amount': pi['amount']
            })
            if generate.verify_signature(sigM, order['signedMm'], publicKeyServer) is False:
                print("Invalid signature")
                conn.close()

            # verify client CARD
            f = open('cCode.txt', 'r')
            cCode = f.read()
            f.close()
            if exist_card(pi['cardN'], pi['cardExp']) is False or pi['cCode'] != cCode:
                resp = 'ABORT (Invalid card)'
                exist_response = True
            else:
                if find_balance_given_cardN(pi['cardN']) < pi['amount']:
                    resp = 'ABORT (Insuficient resources)'
                    exist_response = True
                else:
                    update_Cbalance_given_cardN(pi['cardN'], pi['amount'])
                    update_Mbalance_given_owner(pi['M'], pi['amount'])
                    resp = 'YES'
                    exist_response = True
            # Exchange Sub-protocol 5
            print('Exchange Sub-protocol 5')
            clientNonce = pi['nc']
            signedMessage = generate.sign(pickle.dumps(
                {'resp': resp,
                 'sid': pi['sid'],
                 'amount': pi['amount'],
                 'nc': clientNonce}
            ), privatePgKey)
            # 5. {Resp,Sid,SigPG(Resp,Sid,Amount,NC)}PubKM
            stepFive = pickle.dumps({
                'resp': resp,
                'sid': pi['sid'],
                'signedMessage': signedMessage
            })
            encrypted_stepFive = generate.encrypt_aes(stepFive, AESkeyM)
            encryptedKey = generate.encrypt_rsa(AESkeyM, pubKM)
            conn.sendall(pickle.dumps({'encrypted_stepFive': encrypted_stepFive,
                                       'encryptedKey': encryptedKey}))
            break

    s.settimeout(25)
    # receive data
    try:
        conn2, addr2 = s.accept()
        with conn2:
            print('Connected by', addr2)
            pubKC = generate.importPublicKey_rsa(publicKeyClient)
            data = pickle.loads(conn2.recv(15000))
            if exist_response is False:
                clientNonce = pi['nc']
                signedMessage = generate.sign(pickle.dumps(
                    {'resp': 'ABORT',
                     'sid': pi['sid'],
                     'amount': pi['amount'],
                     'nc': clientNonce}
                ), privatePgKey)

                stepEight = pickle.dumps({
                    'resp': resp,
                    'sid': pi['sid'],
                    'signedMessage': signedMessage
                })
            else:
                stepEight = stepFive
            encrypted_stepEight = generate.encrypt_aes(stepEight, AESkeyC)
            encryptedKey = generate.encrypt_rsa(AESkeyC, pubKC)
            conn2.sendall(pickle.dumps({'encrypted_stepEight': encrypted_stepEight,
                                       'encryptedKey': encryptedKey}))

    except socket.timeout:
        print("Timeout occurred while receiving data")
