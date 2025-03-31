import platform
#on demande à l'utilisateur de nous fournir l'IP
import subprocess

#demander une adresse IP à l'utilisateur
ip = input("entrez une adresse ip a ping:")
#on detecte l'os pour adapter la commande
param = "-n" if platform.system().lower() == "Windows" else "-c"
#Construction du ping dans une list
commande = ["ping", param, "1", ip]

print("ping en cours")

#on execute le ping
try:
    result = subprocess.run(commande, stdout=subprocess.DEVNULL)
    if result.returncode == 0:
        print("la cible est en ligne")
    else:
        print("la cible n'est pas en ligne")
except Exception as e:
    print(f"Erreur lors du ping{e}")
