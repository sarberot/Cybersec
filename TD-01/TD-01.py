## Scanner de port
import threading
from logging import exception
from socket import socket
from threading import Thread

import sock


#Definir une fonction qui va tester un port specifique
def scan_port(host, port):
    try:
        #creaion d'un objet socket
        socket(socket.AF_INET, socket.SOCK_STREAM)
        #Definir un delais pour éviter le TIMEOUT et le blocage
        sock.settimeout(1)
        #Tentative de connexion sur le port ( 0 si la connexion a reussit)
        result = socket.connect_ex((host, port))
        # Si le port est ouvert ( result == 0), on l'affiche
        if result == 0:
            print(f"[+]Port {port} is open")
        # on ferme le socket
        sock.close()
    except exception as e:
        #Gestion des erreurs
        print(f"[-] Erreur sur le port {port}: {e}")
    #On demande a  l'utilisateur  l'adresse ip de la cible
target = input("entrez l'adresse ip a scanner")

#on demande la plage d'adresse a scanner
start_port = int(input("port de debut"))
end_port = int(input("port de fin"))
#on informe l'utilisateur qu'on commence le sca,
print(f"\n[***] Scan target {target} sur les ports {start_port} à {end_port} [***]\n")
for port in range(start_port, end_port+1):
    #on creer un thread ( execution parallele) pour chaque port
    t = threading.Thread(target=scan_port, args=(target, port))
    t.start()