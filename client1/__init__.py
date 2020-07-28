##Fichier init
from utils import get_sca_certificate, get_certificates

def certificates():
    name = input("Hostname: ")
    pool = int(input("Taille du pool: "))
    get_certificates(name, pool)

def getChoice(argument):
    switcher = { 
        1: get_sca_certificate(), 
        2: certificates(), 
        3: "two", 
    } 
    return switcher.get(argument, "nothing") 

def showMenu():
    print ("1- Requête certificat du serveur SCA")
    print ("2- Demander une signature de certificat")
    print ("3- Démarer une discussion")
    print ("4- Quitter")


if __name__ == "__main__": 
    choice = -1
    while(choice != 0):
        showMenu()
        choice = int(input("Votre choix: "))
        getChoice(choice)

    print("======== AU REVOIR ========")
