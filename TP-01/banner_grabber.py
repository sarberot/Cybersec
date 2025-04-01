import socket
import threading


# Fonction pour récupérer la bannière d'un service sur un port
def grab_banner(host, port, output_file):
    try:
        # Création d'un objet socket (AF_INET = IPv4, SOCK_STREAM = TCP)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # On définit un délai de 1 seconde pour éviter les blocages (timeout)
        sock.settimeout(1)

        # Tentative de connexion sur le port
        sock.connect((host, port))

        # Tentative de recevoir une bannière (max 1024 octets)
        banner = sock.recv(1024).decode().strip()

        # Si on récupère une bannière, on l'affiche et on l'écrit dans le fichier
        if banner:
            result = f"[+] Port {port} ouvert - Service détecté : {banner}"
        else:
            result = f"[+] Port {port} ouvert - Pas de bannière détectée"

        print(result)

        # Sauvegarde dans le fichier
        with open(output_file, "a") as file:
            file.write(result + "\n")

        # Fermeture de la socket après utilisation
        sock.close()

    except socket.timeout:
        pass  # Ignore si la connexion a échoué pour timeout
    except Exception as e:
        print(f"[-] Erreur sur le port {port}: {e}")


# Fonction pour scanner les ports et récupérer les bannières
def scan_ports(host, start_port, end_port, output_file):
    # On informe l'utilisateur que le scan commence
    print(f"\n[***] Scan de {host} sur les ports {start_port} à {end_port} [***]\n")

    # Liste des threads pour effectuer un scan parallèle
    threads = []

    # Pour chaque port dans la plage spécifiée
    for port in range(start_port, end_port + 1):
        # Création d'un thread pour effectuer le scan sur ce port
        t = threading.Thread(target=grab_banner, args=(host, port, output_file))
        t.start()  # Démarre le thread
        threads.append(t)

    # Attente de la fin de tous les threads
    for t in threads:
        t.join()


# Fonction principale
def main():
    # Demande à l'utilisateur l'adresse IP et la plage de ports à scanner
    target = input("Entrez l'adresse IP à scanner : ")
    start_port = int(input("Port de début : "))
    end_port = int(input("Port de fin : "))

    # Demande le nom du fichier de sortie
    output_file = input("Entrez le nom du fichier de résultats (ex: scan_results.txt) : ")

    # Lancement du scan des ports avec récupération des bannières
    scan_ports(target, start_port, end_port, output_file)


# Appel de la fonction principale
if __name__ == "__main__":
    main()
