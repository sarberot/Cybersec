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
        result = sock.connect_ex((host, port))

        # Si le résultat est 0, cela signifie que le port est ouvert
        if result == 0:
            # Tentative de récupérer la bannière (max 1024 octets)
            banner = sock.recv(1024).decode().strip()

            # Si une bannière est reçue, on l'affiche et on l'enregistre dans le fichier
            if banner:
                result_str = f"[+] Port {port} ouvert - Service détecté : {banner}"
            else:
                result_str = f"[+] Port {port} ouvert - Pas de bannière détectée"

            # Affichage du résultat à l'écran
            print(result_str)

            # Sauvegarde du résultat dans le fichier
            with open(output_file, "a") as file:
                file.write(result_str + "\n")

            # Si c'est un serveur web, tenter une requête HEAD (pour les ports 80 et 443)
            if port == 80 or port == 443:
                try:
                    # Envoi de la requête HEAD
                    http_request = "HEAD / HTTP/1.1\r\nHost: {}\r\n\r\n".format(host)
                    sock.sendall(http_request.encode())

                    # Récupération de la réponse HTTP (en-têtes)
                    response = sock.recv(1024).decode().strip()

                    if response:
                        # Vérification des codes de réponse pour identifier un serveur web
                        if "HTTP" in response:
                            print(f"[+] Port {port} est un serveur Web - Réponse: {response}")
                            with open(output_file, "a") as file:
                                file.write(f"[+] Port {port} est un serveur Web - Réponse: {response}\n")

                except socket.timeout:
                    pass  # Ignore si aucune réponse ou timeout sur la requête HEAD

        # Fermeture de la socket après utilisation
        sock.close()

    except socket.timeout:
        pass  # Ignore les erreurs de timeout (aucune réponse du port)
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
