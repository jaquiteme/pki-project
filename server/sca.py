#!/usr/bin/python3
"""
2019-2020, Jordy Aquiteme <jordyaquiteme@gmail.com>
Ce fichier fait partit du TP PKI
"""
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime

one_year = datetime.timedelta(days=365)
today = datetime.date.today()

yest = today - one_year
end = today + one_year
yesterday = datetime.datetime(yest.year, yest.month, yest.day)
end_licence = datetime.datetime(end.year, end.month, end.day)

#Génération de la clef privée du serveur
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=1024,
    backend=default_backend()
)

#Information de l'utilisateur
ca_name = x509.Name([
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u'REIMS'),
    x509.NameAttribute(NameOID.COMMON_NAME, u'SCA'),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'TP-RT0802'),
    x509.NameAttribute(NameOID.COUNTRY_NAME, u'FR')
])

#La clef publique issue de la clef privée
public_key = private_key.public_key()

builder = x509.CertificateBuilder()
builder = builder.subject_name(ca_name)
builder = builder.issuer_name(ca_name)
builder = builder.not_valid_before(yesterday)
builder = builder.not_valid_after(end_licence)
builder = builder.serial_number(12345)#x509.random_serial_number())
builder = builder.public_key(public_key)
builder = builder.add_extension(
x509.BasicConstraints(ca=True, path_length=None),
critical=True)

#Signature
certificate = builder.sign(
    private_key=private_key, algorithm=hashes.SHA256(),
    backend=default_backend()
)

private_bytes = private_key.private_bytes(
encoding=serialization.Encoding.PEM,
format=serialization.PrivateFormat.TraditionalOpenSSL,
encryption_algorithm=serialization.NoEncryption())
public_bytes = certificate.public_bytes(
encoding=serialization.Encoding.PEM)

#Ecriture des fichiers 
with open("ca.pem", "wb") as fout:
    fout.write(private_bytes)
with open("ca.crt", "wb") as fout:
    fout.write(public_bytes)