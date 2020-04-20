import json
import os
import sys
import time
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from base64 import b64encode, b64decode
from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime

one_year = datetime.timedelta(days=365)
today = datetime.date.today()

end = today + one_year
yesterday = datetime.datetime(today.year, today.month, today.day)
end_licence = datetime.datetime(end.year, end.month, end.day)

KEYS = {}

with open("/home/jordy/tp-rt0802/ca.crt", "rb") as fcert:
    SUBJECT = x509.load_pem_x509_certificate(fcert.read(), default_backend())     

#Fonction qui permet de charger la clef provée du serveur SCA
def sca_private_key():
    with open("/home/jordy/tp-rt0802/ca.pem", "rb") as fkey:
        CA_KEY = serialization.load_pem_private_key(
            fkey.read(),
            password=None,
            backend=default_backend()
        )
    return CA_KEY

#Fonction qui permet de generer un certificat à partir du CSR 
def generate_certificate(csr):

    CA_KEY = sca_private_key()
    cert_s_request = x509.load_pem_x509_csr(csr,default_backend())
    #Information de l'utilisateur
    ca_name = x509.Name(cert_s_request.subject)

    # #La clef publique issue de la clef privée
    public_key = cert_s_request.public_key()

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(ca_name)
    builder = builder.issuer_name(SUBJECT.subject)
    builder = builder.not_valid_before(yesterday)
    builder = builder.not_valid_after(end_licence)
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(public_key)
    builder = builder.add_extension(
    x509.BasicConstraints(ca=False, path_length=None),
    critical=True)

    # #Signature par le SCA
    certificate = builder.sign(
        private_key=CA_KEY, algorithm=hashes.SHA256(),
        backend=default_backend()
    )

    public_bytes = certificate.public_bytes(
    encoding=serialization.Encoding.PEM)

    #Ecriture des fichiers 
    with open("ca.db.certs/{}.crt".format(cert_s_request.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value), "wb") as fout:
        fout.write(public_bytes)
    
    return public_bytes

#Fonction qui charge le certificat du serveur SCA
def sca_certificate():
    with open("/home/jordy/tp-rt0802/ca.crt", "rb") as crt:
        CA_CERTIFICATE = crt.read()
    payload = {}
    payload["sca_certificate"] =  CA_CERTIFICATE.decode('utf8').replace("'", '"')
    pk = json.dumps(payload)
    return pk

def create_certificate_from_pk(param):

    #Information de l'utilisateur
    ca_name = x509.Name([
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u'REIMS'),
        x509.NameAttribute(NameOID.COMMON_NAME, u'{}'.format(param['hostname'])),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'TP-RT0802'),
        x509.NameAttribute(NameOID.COUNTRY_NAME, u'FR')
    ])

#Fonction de déchiffrement asymétrique
def _decrypt_asymetric(param):
    private_key = sca_private_key()
    cipher = private_key.decrypt(
        param,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
         )
    )
    return cipher

#Fonction de chiffrement AES
def _encrypt_aes(key, _message):
    #iv = os.urandom(algorithms.AES.block_size // 8)
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend = default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(_message) + encryptor.finalize()

    return ct

#Fonction de déchiffrement AES
def _decrypt_aes(key, _message):
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend = default_backend())
    decryptor = cipher.decryptor()
    decoded = decryptor.update(_message) + decryptor.finalize()
    return decoded

#Fonction qui permet d enregistrer une session
def session_start(clt, key):
    global KEYS
    KEYS[clt] = key
    return KEYS

#Fonction qui permet de connaitre l etat d une session
def session(clt):
    global KEYS
    return KEYS[clt]

#Fonction qui permet de détruire une session
def session_stop(clt):
    global KEYS
    KEYS.pop(clt)
    return KEYS
    