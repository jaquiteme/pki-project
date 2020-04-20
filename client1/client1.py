import os
import socket
import json
from base64 import b64encode, b64decode
from functions import load_cert, load_private_k, sign_message, verify_signature, decrypt_asym, is_valid_cert, get_issuer, get_cert_subject
host = '127.0.0.1'
port = 12800

connexion = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
connexion.connect((host, port))

my_certificate = load_cert(r"pool/certs/client1_1.mrt.crt")
my_private = load_private_k(r"pool/keys/client1_1.pem")


print("Connexion établie avec le serveur sur le port {}".format(port))

message = b"hello je veux me connecter a toi"
my_signature = sign_message(my_private, message)
data = {}
data['message'] = message.decode()
data['signature'] = b64encode(my_signature).decode()
data['certificate'] = b64encode(my_certificate).decode()

msg_recu = b""
msg_a_envoyer = json.dumps(data).encode()
connexion.send(msg_a_envoyer)
response = json.loads(connexion.recv(2048).decode())
   
certificate = b64decode(response['certificate'].encode())
signature = b64decode(response['signature'].encode())
message = response['message'].encode()

verify = verify_signature(certificate, signature, message)
issuer = get_issuer(certificate)
CN, O = get_cert_subject(certificate)
if(verify == "match" and is_valid_cert(certificate) and issuer == "SCA"):
    print("Check 1")
    msg_recu = response['message'].encode()
    if (msg_recu == b"ok"):
        while msg_recu != b"fin":
            msg_a_envoyer = input("(Moi) > ")
            # Peut planter si vous tapez des caractères spéciaux
            signature = sign_message(my_private, msg_a_envoyer.encode())
            data = {}
            data['message'] = msg_a_envoyer
            data['signature'] = b64encode(signature).decode()
            data['certificate'] = b64encode(my_certificate).decode()
            msg_a_envoyer = json.dumps(data).encode()
            # On envoie le message
            connexion.send(msg_a_envoyer)

            response = json.loads(connexion.recv(2048).decode())
    
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

                #print(msg_recu.decode()) # Là encore, peut planter s'il y a des accents
    else:
       connexion.close()

print("Fermeture de la connexion")
connexion.close()