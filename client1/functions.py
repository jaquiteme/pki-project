"""
2019-2020, Jordy Aquiteme <jordyaquiteme@gmail.com>
Ce fichier fait partit du TP PKI
"""
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime

#Fonction qui permet de générer les clefs (privée et public) et le CSR
def generate_keys(id, oid):

    #Génération de la clef publique
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=1024,
        backend=default_backend()
    )

    client_infos = x509.Name([
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u'REIMS'),
        x509.NameAttribute(NameOID.COMMON_NAME, u'{}_{}.mrt'.format(id,oid)),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'{}'.format(id)),
        x509.NameAttribute(NameOID.COUNTRY_NAME, u'FR')
    ])

    public_key = private_key.public_key()
    csr = x509.CertificateSigningRequestBuilder()
    csr = csr.subject_name(client_infos)
    csr = csr.add_extension(
    x509.BasicConstraints(ca=False, path_length=None),
    critical=False)
    csr = csr.sign(
        private_key=private_key, 
        algorithm=hashes.SHA256(),
        backend=default_backend()
        )

    private_bytes = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption())

    public_bytes = csr.public_bytes(
    encoding=serialization.Encoding.PEM)

    #Ecriture des fichiers 
    with open("pool/keys/{}_{}.csr".format(id, oid), "wb") as fout:
        fout.write(public_bytes)
    with open("pool/keys/{}_{}.pem".format(id, oid), "wb") as fout:
        fout.write(private_bytes)

    return public_bytes

#Fonction qui permet d extraire la clef public d un  certificat
def extract_server_pk(param):
    
    cert = x509.load_pem_x509_certificate(param,default_backend())
    pub_key = cert.public_key()
    return pub_key.public_bytes(
        encoding=serialization.Encoding.PEM, 
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

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

#Fonction qui permet de charger le certficat sous forme d objet
def load_cert(_path):
    with open(_path, "rb") as crt:
        cert = crt.read()
    return cert

#Fonction qui permet de charger une clef privée
def load_private_k(_path):
    with open(_path, "rb") as pvk:
        private = pvk.read()
    return private

#Fonction qui permet de signer un message
def sign_message(pvk, message):
    private_key = serialization.load_pem_private_key(pvk, 
        password=None, 
        backend=default_backend()
        )
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
     hashes.SHA256()
    )
    return signature

#Fonction qui permet de charger un certificat en
def certificate_to_byte(cert):
    _cert = x509.load_pem_x509_certificate(cert, default_backend())
    return _cert

#Fonction qui permet de vérifier une signature
def verify_signature(cert, signature, message):
    cert = certificate_to_byte(cert)
    public_key = cert.public_key()
    try:
        public_key.verify(
            signature,
            message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
        )

        return "match"
    except ValueError:
        return "problem"

#Fonction qui permet de réaliser un chiffrement asymetrique
def encrypt_asym(certificate, message):
    cert = certificate_to_byte(certificate)
    public_key = cert.public_key()
    ciphertext = public_key.encrypt(
    message,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
        )
     )
    
    return ciphertext

#Fonction qui permet de déchiffer un message chiffrer en asymetrique
def decrypt_asym(pvk, message):
    private_key = serialization.load_pem_private_key(pvk, 
        password=None, 
        backend=default_backend()
        )

    plaintext = private_key.decrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
     )
    
    return plaintext

#Fonction qui permet de vérifier la validité d un certificat
def is_valid_cert(certificate):
    today = datetime.datetime.today()
    cert = certificate_to_byte(certificate)
    
    if (today > cert.not_valid_after): 
        return False
    elif (today < cert.not_valid_after):
        return True

#Fonction qui permet d extraire les informations de l AC
def get_issuer(certificate):
    cert = certificate_to_byte(certificate)
    try:
        name = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
        return name[0].value
    except x509.ExtensionNotFound:
        return "error"
#Fonction qui permet d extraire les informations du detenteur du certificat
def get_cert_subject(certificate):
    cert = certificate_to_byte(certificate)
    CN = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    O = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value

    return CN, O
