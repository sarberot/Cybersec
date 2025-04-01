# On importe le module socket pour la communication réseau
import socket

# On importe threading pour exécuter plusieurs tâches en parallèle (multithreading)
import threading


# Définition de la fonction qui va tester un port spécifique sur une adresse IP donnée
def scan_port(host, port):
    try:
        # Création d'un objet socket (AF_INET = IPv4, SOCK_STREAM = TCP)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # On définit un délai de 1 seconde pour éviter les blocages (timeout si pas de réponse rapide)
        sock.settimeout(1)

        # Tentative de connexion sur le port (connect_ex retourne 0 si la connexion réussit)
        result = sock.connect_ex((host, port))

        # Si le port est ouvert (result == 0), on l'affiche
        if result == 0:
            print(f"[+] Port {port} ouvert")

        # On ferme la socket (bonne pratique)
        sock.close()

    except Exception as e:
        # Gestion d'erreurs (affichage si un problème survient)
        print(f"[-] Erreur sur le port {port}: {e}")


# On demande à l'utilisateur l'adresse IP de la cible
target = input("Entrez l'adresse IP à scanner : ")

# On demande les bornes de ports à scanner (ex : de 1 à 1024)
start_port = int(input("Port de début : "))
end_port = int(input("Port de fin : "))

# On informe l'utilisateur qu'on commence le scan
print(f"\n[***] Scan de {target} sur les ports {start_port} à {end_port} [***]\n")

# Pour chaque port dans l'intervalle choisi
for port in range(start_port, end_port + 1):
    # On crée un thread (exécution parallèle) pour chaque scan de port
    t = threading.Thread(target=scan_port, args=(target, port))

    # On démarre le thread
    t.start()