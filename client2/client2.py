import os
import socket
import json
from base64 import b64encode, b64decode
from functions import load_cert, load_private_k, sign_message, verify_signature, encrypt_asym, is_valid_cert, get_issuer, get_cert_subject

host = '127.0.0.1'
port = 12800
#!/usr/bin/python3
"""
2019-2020, Jordy Aquiteme <jordyaquiteme@gmail.com>
Ce fichier fait partit du TP PKI
"""
connexion = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
connexion.bind((host, port))
connexion.listen(5)

my_certificate = load_cert(r"pool/certs/client2_2.mrt.crt")
my_private = load_private_k(r"pool/keys/client2_2.pem")

print("Le client 2 écoute à présent sur le port {}".format(port))

con_from_another_client, infos_connexion = connexion.accept()

msg_recu = b""
while msg_recu != b"fin":
    response = json.loads(con_from_another_client.recv(2048).decode())
   
    certificate = b64decode(response['certificate'].encode())
    signature = b64decode(response['signature'].encode())
    msg_recu = response['message'].encode()

    verify = verify_signature(certificate, signature, msg_recu)
    issuer = get_issuer(certificate)
    CN, O = get_cert_subject(certificate)
    if(verify == "match" and is_valid_cert(certificate) and issuer == "SCA"):
        print("CA de ce certificat: {}".format(issuer))
        print("CN de ce certificat: {}".format(CN))
        print("({}) {}".format(O, msg_recu.decode()))

        msg_a_envoyer = input("(Moi) > ")

        my_signature = sign_message(my_private, msg_a_envoyer.encode())
        data = {}
        data['message'] = msg_a_envoyer
        data['signature'] = b64encode(my_signature).decode()
        data['certificate'] = b64encode(my_certificate).decode()

        msg_a_envoyer = json.dumps(data).encode()
        con_from_another_client.send(msg_a_envoyer)
    else:
        print("Rejected")
   

print("Fermeture de la connexion")
con_from_another_client.close()
connexion.close()