# Projet PKI

## SERVER
Le serveur PKI (Public Key Infrastructure).
Il permet de signer les certificats (CSR) des clients, sachant que ces derniers peuvent demander un pool (ensemble).
* Le serveur tourne sous Flask.
* Une fois lancé, celui-ci est disponible pour répondre aux requêtes en chiffrant les données (chiffrement asymétrique et symétrique).

## CLIENTS

Nous avons considéré ici nos clients comme des voitures connectées, qui doivent s'échanger des messages. 
* Chaque client vérifie la validité du certificat contenu dans le message envoyé. Si celui-ci n'est pas signé par le SCA (notre autorité de certification) ou n'est plus valide, 
le message est rejeté et la connexion est interrompue. 
