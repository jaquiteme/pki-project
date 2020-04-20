from cryptography.hazmat.backends import default_backend
from base64 import b64encode, b64decode
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography import x509
from functions import generate_keys, extract_server_pk, _decrypt_aes, _encrypt_aes
import requests
import json
import os
import sys
import datetime

APIENDPOINT = "http://127.0.0.1:5000"

#Cette fonction permet de faire des requêtes de demande 
# de signature de certificat vers le serveur SCA
def get_certificates():
     with open("sca.crt", "rb") as crt:
        CA_PK = extract_server_pk(crt.read())

     #Génération de la clef secrète
     r_key = os.urandom(32)
     pub_key = serialization.load_pem_public_key(
        CA_PK,
        backend=default_backend()
     )

     #Chiffrement Asymétrique de la clef secrète
     ciphertext = pub_key.encrypt(
          r_key,
          padding.OAEP(
         mgf=padding.MGF1(algorithm=hashes.SHA256()),
         algorithm=hashes.SHA256(),
         label=None
          )
      )
     #Début phase de connexion au serveur pour établir un échange 
     # symétrique entre les deux acteurs
     payload = {}
     payload["data"] = b64encode(ciphertext)
     payload["host"] = sys.argv[1]
     response = requests.post("{}/connexion".format(APIENDPOINT), data=payload) 
     #print(response.text)
     data = json.loads(response.text)
     print("statut:{}".format(response.status_code))
     dec = _decrypt_aes(r_key, b64decode(data['ct'].encode()))
     #print(b64decode(dec))
     #Après les vérifications côté serveur, le serveur établit démarre une session 
     # avec le client
     if (b64decode(dec) == b"etablished"): 
          #horodatage
          _date = datetime.datetime.now()
          print("[{}] > Début de la session au SCA".format(_date.strftime("%H:%M:%S")))
          #Place reservé pour la boucle (début)
          for i in range(int(sys.argv[2])):
               _date = datetime.datetime.now()
               #Génération du csr
               csr = generate_keys(sys.argv[1], (i+1))
               
               print("[{}] > Envoie du CSR".format(_date.strftime("%H:%M:%S")))

               #Chiffrement symétrqiue des échanges
               csr_crypt = _encrypt_aes(r_key,  csr + (b"0"*(800 - len(csr))))

               #Paramètres
               payload = {}
               payload["data"] = b64encode(csr_crypt)
               payload["host"] = sys.argv[1]

               #Le client demande l'etablissement d'un certificat en envoyant son "CSR"
               response = requests.post("{}/ask_certificate".format(APIENDPOINT), data=payload)

               data = json.loads(response.text)
               #Réception et déchiffrement de la réponse du serveur qui contient 
               # le certificat
               dec_certificate = _decrypt_aes(r_key, b64decode(data['certificate'].encode()))
               _date = datetime.datetime.now()

               print("[{}] > Reception du CRT".format(_date.strftime("%H:%M:%S")))
               print("[{}] > Ecriture du CRT dans un fichier".format(_date.strftime("%H:%M:%S")))

               with open("pool/certs/{}_{}.mrt.crt".format(sys.argv[1], i+1), "wb") as fout:
                    fout.write(dec_certificate.rstrip(b"0"))

               _date = datetime.datetime.now()
               print("[{}] > Fin de l ecriture du CRT dans un fichier".format(_date.strftime("%H:%M:%S")))
          
          #Après avoir recu tous ses certificats signés par le SCA
          #Le client demande au serveur de le déconnecter
          end_message = b"deconnexion"

          end = _encrypt_aes(r_key, end_message + (b"0"*(16 - len(end_message))))
          payload = {}
          payload["data"] = b64encode(end)
          payload["host"] = sys.argv[1]
          response = requests.post("{}/deconnexion".format(APIENDPOINT), data=payload)
          data = json.loads(response.text)
          _date = datetime.datetime.now()
          print("[{}] > Fin de la session au serveur SCA".format(_date.strftime("%H:%M:%S")))
     else:
          print("Erreur")
#     with open("c1.pem", "wb") as fout:
#          fout.write(data['key'].encode('utf8'))
#     with open("c1.crt", "wb") as fout:
#          fout.write(data['certificate'].encode('utf8'))

#Fonction pour récupérer le certificat du serveur SCA
def get_sca_certificate():
    response = requests.get("{}/sca_certificate".format(APIENDPOINT)) 
    data = json.loads(response)
    print("statut:{}".format(response.status_code))

    with open("sca.crt", "wb") as fout:
         fout.write(data['sca_certificate'].encode('utf8'))

get_certificates()