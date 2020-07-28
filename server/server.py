
#!/usr/bin/python3
"""
2019-2020, Jordy Aquiteme <jordyaquiteme@gmail.com>
Ce fichier fait partit du TP PKI
"""
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from flask import Flask, request
from base64 import b64encode, b64decode
from core import generate_certificate, sca_certificate, _decrypt_asymetric, session_start, session_stop, session, _encrypt_aes, _decrypt_aes
import json
import os

app = Flask(__name__)


@app.route('/')
def index():
    return "Hello world !"

#Route de connexion
@app.route('/connexion', methods=['POST'])
def connexion():
    data = b64decode(request.form['data'])
    key = _decrypt_asymetric(data)
    session_start(request.form.get('host'), key)
    s = session(request.form.get('host'))
    m = b"etablished"
    ct = _encrypt_aes(s, b64encode(m))
    payload = {}
    payload["ct"] = b64encode(ct).decode()
    
    return payload
#Route de demande d un certificat
@app.route('/ask_certificate', methods=['POST'])
def key_certificate():
    data = b64decode(request.form['data'])
    key = session(request.form.get('host'))
    decrypt = _decrypt_aes(key,data).rstrip(b"0")
    certificate = generate_certificate(decrypt)
    certificate_crypt = _encrypt_aes(key,  certificate + (b"0"*(800 - len(certificate))))
    payload = {}
    payload["certificate"] = b64encode(certificate_crypt).decode()
    return payload

#Route pour obtenir le certificat du serveur SCA
@app.route('/sca_certificate', methods=['GET'])
def get_sca_certificate():
    r = sca_certificate()
    return r

#Route pour se deconnecter du serveur
@app.route('/deconnexion', methods=['POST'])
def deconnect():
    data = b64decode(request.form['data'])
    key = session(request.form.get('host'))
    decrypt = _decrypt_aes(key, data).rstrip(b"0")
    if (decrypt == b"deconnexion"):
        session_stop(request.form.get('host'))
    payload = {}
    payload["stop"] = "end"
    
    return payload
    
#Addresse IP du serveur
IP_ADDRESS = '127.0.0.1'

if __name__ == "__main__":
     app.run(host=IP_ADDRESS, port=5000,debug=True)