import os
import socket
import generate
import pickle
import random
from prettytable import PrettyTable


def display_catalog_as_table(catalog):
    # Create a PrettyTable instance
    table = PrettyTable()
    # Add the columns to the table
    table.field_names = ['Products', 'Price']
    # Add the data rows to the table
    for product, price in catalog.items():
        table.add_row([product, price])
    # Return the table as a string
    return str(table)


privateClientKey = 'client_private_key.pem'
publicClientKey = 'client_public_key.pem'
publicServerKey = 'server_public_key.pem'
publicPGKey = 'pg_public_key.pem'
# generare cheie rsa pt client
key_client = generate.generate_and_exportKey_rsa(privateClientKey)
pubKC = generate.savePublicKey_rsa(key_client, publicClientKey)

if __name__ == "__main__":
    HOST = 'localhost'
    PORT = 2111
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        print('Bine ati venit!')

        # Alegerea produsului
        data = s.recv(1024)
        produse = pickle.loads(data)
        print(display_catalog_as_table(produse))
        produs = input('Introduceti denumirea produsului pe care doriti sa-l cumparati: ')

        pubKM = generate.importPublicKey_rsa(publicServerKey)
        pubKPG = generate.importPublicKey_rsa(publicPGKey)
        AESkey = os.urandom(32)  # b'\x00' * 32
        AESkeyPG = os.urandom(32)  # b'\x00' * 32

        # Setup Sub-protocol  1
        step_One = generate.encrypt_aes(pubKC, AESkey)
        encryptedKey = generate.encrypt_rsa(AESkey, pubKM)
        s.sendall(pickle.dumps({'ciphertext': step_One[0],
                                'nonce': step_One[1],
                                'tag': step_One[2],
                                'key': encryptedKey}))
        print('Pasul 1 din Setup Sub-protocol a fost executat cu succes.')

        # Setup Sub-protocol 2
        data = pickle.loads(s.recv(10000))
        AESkey = generate.decrypt_rsa(data['encryptedKey'], key_client)
        data = {'ciphertext': data['ciphertext'][0], 'nonce': data['ciphertext'][1], 'tag': data['ciphertext'][2]}
        message = generate.decrypt_aes(data, AESkey)
        content = pickle.loads(message)
        SID = content['sid']

        if generate.verify_signature(content['sid'], content['signedSid'], publicServerKey):
            print("Valid signature\n")
            print('Pasul 2 din Setup Sub-protocol a fost executat cu succes.')
        else:
            print("Invalid signature")
            s.close()

        # Exchange Sub-protocol 3 {PM,PO}PubKM PM={PI,SigC(PI)}PubKPG
        card_number = input("Card Number: ")
        card_expire_date = input("Card Expire Date:  ")

        nc = random.randint(0, 999999)
        pi = {'cardN': card_number,
              'cardExp': card_expire_date,
              'cCode': generate.generate_ccode(),
              'sid': SID,
              'amount': produse[produs],
              'pubKC': pubKC,
              'nc': nc,
              'M': 'merchant1'}
        piBytes = pickle.dumps(pi)
        pm = {'pi': piBytes,
              'signedPi': generate.sign(piBytes, privateClientKey)}
        encrypted_pm = generate.encrypt_aes(pickle.dumps(pm), AESkeyPG)
        encryptedPGkey = generate.encrypt_rsa(AESkeyPG, pubKPG)

        poContent = pickle.dumps({
            'orderDesc': produs,
            'sid': SID,
            'amount': produse[produs]
        })
        po = {
            'poContent': poContent,
            'signedPo': generate.sign(poContent, privateClientKey)
        }

        step_Three = generate.encrypt_aes(pickle.dumps({'encrypted_pm': encrypted_pm,
                                                        'encryptedPGkey': encryptedPGkey,
                                                        'po': po}), AESkey)
        encryptedKey = generate.encrypt_rsa(AESkey, pubKM)

        s.sendall(pickle.dumps({'encryptedMessage': step_Three, 'encryptedKey': encryptedKey}))
        print('Pasul 3 din Exchange Sub-protocol a fost executat cu succes.\n')

        s.settimeout(8)
        try:
            # Exchange Sub-protocol 6
            data = pickle.loads(s.recv(1000))
            AESkey = generate.decrypt_rsa(data['encryptedKey'], key_client)
            encrypted_stepSix = {
                'ciphertext': data['encrypted_stepSix'][0],
                'nonce': data['encrypted_stepSix'][1],
                'tag': data['encrypted_stepSix'][2]
            }
            step_Six = pickle.loads(generate.decrypt_aes(encrypted_stepSix, AESkey))
            # verify PG signature
            msg = pickle.dumps({
                'resp': step_Six['resp'],
                'sid': step_Six['sid'],
                'amount': produse[produs],
                'nc': nc
            })

            if generate.verify_signature(msg, step_Six['signedMessage'], publicPGKey):
                print("Valid signature\n")
                print('Pasul 6 din Exchange Sub-protocol a fost executat cu succes.')
                if step_Six['resp'] == 'YES':
                    print('Transaction successfully finished')
                else:
                    print('Transaction failed ' + step_Six['resp'])
            else:
                print("Invalid signature")
                s.close()
        except socket.timeout:
            s.close()
            print("Timeout occurred while receiving data")
            print('Incepem pasul 7 din Resolution Sub-protocol.')
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as spg:
                pg_HOST = 'localhost'
                pg_PORT = 2222
                spg.connect((pg_HOST, pg_PORT))
                print('M-am conectat la PaymentGateaway')
                # SigC(Sid, Amount, NC, pubKC)}pubPG
                # Resolution Sub-protocol 7
                signedMessage = generate.sign(pickle.dumps(
                    {
                        'sid': pi['sid'],
                        'amount': pi['amount'],
                        'nc': nc,
                        'pubKC': pubKC
                    }
                ), privateClientKey)
                step_Seven = pickle.dumps({
                    'sid': pi['sid'],
                    'amount': pi['amount'],
                    'nc': nc,
                    'pubKC': pubKC,
                    'signedMessage': signedMessage
                })
                encrypted_step_Seven = generate.encrypt_aes(step_Seven, AESkeyPG)
                encryptedKey = generate.encrypt_rsa(AESkeyPG, pubKPG)

                spg.sendall(pickle.dumps({'encrypted_step_Seven': encrypted_step_Seven,
                                          'encryptedKey': encryptedKey}))
                # Resolution Sub-protocol 8
                data = pickle.loads(spg.recv(1000))
                AESkey = generate.decrypt_rsa(data['encryptedKey'], key_client)
                encrypted_stepEight = {
                    'ciphertext': data['encrypted_stepEight'][0],
                    'nonce': data['encrypted_stepEight'][1],
                    'tag': data['encrypted_stepEight'][2]
                }
                step_Eight = pickle.loads(generate.decrypt_aes(encrypted_stepEight, AESkey))
                # verify PG signature
                msg = pickle.dumps({
                    'resp': step_Eight['resp'],
                    'sid': step_Eight['sid'],
                    'amount': produse[produs],
                    'nc': nc
                })

                if generate.verify_signature(msg, step_Eight['signedMessage'], publicPGKey):
                    print("Valid signature (pas 8)\n")
                    if step_Eight['resp'] == 'YES':
                        print('Transaction successfully finished')
                    else:
                        print('Transaction failed ' + step_Eight['resp'])
                else:
                    print("Invalid signature")

        except ConnectionResetError:
            print("Connection reset by remote host")
