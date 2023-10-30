import uuid
import socket
import generate
import pickle
import time

HOST, PORT = "localhost", 2111
privateServerKey = 'server_private_key.pem'
publicServerKey = 'server_public_key.pem'
publicClientKey = 'client_public_key.pem'
publicPGKey = 'pg_public_key.pem'
catalog = {"produs1": 12, "produs2": 86, "produs3": 145, "produs4": 37}
key_merchant = generate.generate_and_exportKey_rsa(privateServerKey)
generate.savePublicKey_rsa(key_merchant, publicServerKey)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen(1)
    conn, addr = s.accept()
    with conn:
        print('Connected by', addr)
        # Trimite catalog produse
        conn.sendall(pickle.dumps(catalog))

        # Setup Sub-protocol 1. ->
        data = pickle.loads(conn.recv(10000))
        AESkey = generate.decrypt_rsa(data['key'], key_merchant)
        pubKC_transmitted = generate.decrypt_aes(data, AESkey)
        pubKC = generate.importKey_rsa_from_text(pubKC_transmitted)

        # Setup Sub-protocol 2. <-
        SID = uuid.uuid4().bytes
        signedSID = generate.sign(SID, privateServerKey)
        encrypted_message = generate.encrypt_aes(pickle.dumps({'sid': SID, 'signedSid': signedSID}), AESkey)
        encryptedKey = generate.encrypt_rsa(AESkey, pubKC)

        conn.sendall(pickle.dumps({'ciphertext': encrypted_message, 'encryptedKey': encryptedKey}))

        # Exchange Sub-protocol 3 ->
        data = pickle.loads(conn.recv(20000))
        AESkey = generate.decrypt_rsa(data['encryptedKey'], key_merchant)
        message = {
            'ciphertext': data['encryptedMessage'][0],
            'nonce': data['encryptedMessage'][1],
            'tag': data['encryptedMessage'][2]
        }
        message = pickle.loads(generate.decrypt_aes(message, AESkey))
        # verify client signature on PO
        if generate.verify_signature(message['po']['poContent'], message['po']['signedPo'],
                                     publicClientKey) is False:
            print("Invalid signature, Closing the connection...")
            conn.close()
        poContent = pickle.loads(message['po']['poContent'])
        # verify SID
        if SID != poContent['sid']:
            print('Invalid SID')
        # verify amount
        if catalog[poContent['orderDesc']] != poContent['amount']:
            print('Invalid amount or product')
        print('\n')

        # Exchange Sub-protocol 4
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as spg:
            pg_HOST = 'localhost'
            pg_PORT = 2222
            spg.connect((pg_HOST, pg_PORT))
            print('M-am conectat la PaymentGateaway')

            AESkeyPG = b'\x00' * 32
            pubPG = generate.importPublicKey_rsa(publicPGKey)

            merchantMessage = pickle.dumps({
                'sid': SID,
                'pubKC': pubKC_transmitted,
                'amount': catalog[poContent['orderDesc']]
            })
            signedMessage = generate.sign(merchantMessage, privateServerKey)

            order = pickle.dumps({
                'pm': message['encrypted_pm'],
                'encryptedPmKey': message['encryptedPGkey'],
                'signedMm': signedMessage
            })
            encryptedOrder = generate.encrypt_aes(order, AESkeyPG)
            encryptedKey = generate.encrypt_rsa(AESkeyPG, pubPG)

            spg.sendall(pickle.dumps({'encryptedOrder': encryptedOrder,
                                      'encryptedKey': encryptedKey}))

            # Exchange Sub-protocol 5
            data = pickle.loads(spg.recv(10000))
            AESkeyPG = generate.decrypt_rsa(data['encryptedKey'], key_merchant)
            encrypted_stepFive = {
                'ciphertext': data['encrypted_stepFive'][0],
                'nonce': data['encrypted_stepFive'][1],
                'tag': data['encrypted_stepFive'][2]
            }
            step_Five_decrypted = generate.decrypt_aes(encrypted_stepFive, AESkeyPG)
            step_Five = pickle.loads(step_Five_decrypted)
            print('Am primit raspunsul ', step_Five['resp'], '\n')

            # Exchange Sub-protocol 6 <-
            step_Six = generate.encrypt_aes(step_Five_decrypted, AESkey)
            encryptedKey = generate.encrypt_rsa(AESkey, pubKC)
            # time.sleep(16)
            conn.sendall(pickle.dumps({'encrypted_stepSix': step_Six,
                                       'encryptedKey': encryptedKey}))
            spg.close()
            time.sleep(60)
