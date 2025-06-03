Voici un plan détaillé et un exemple de code pour mettre en place ton lab d'analyse de logs serveur pour la détection d’activités suspectes en Python.
🗂️ Structure du projet

log-analyzer/
├── logs/
│   └── access.log              ← fichier de logs (Apache ou SSH)
├── analyzer.py                 ← script principal
├── utils.py                    ← fonctions de support (regex, parsing, détection)
└── report.txt                  ← rapport généré automatiquement

📦 Prérequis

    Python 3.8+

    Modules standards : re, datetime, collections

🧠 Étapes pédagogiques
🔍 1. Lire et parser les logs (Apache ici)
Exemple de ligne Apache (Common Log Format) :

127.0.0.1 - - [03/Jun/2025:13:55:36 +0000] "GET /admin HTTP/1.1" 403 199

📁 utils.py – Fonctions de support

import re
from datetime import datetime

# Regex Apache CLF
log_pattern = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<date>.+?)\] "(?P<request>.+?)" (?P<status>\d{3}) (?P<size>\d+|-)'
)

def parse_apache_log_line(line):
    match = log_pattern.match(line)
    if match:
        data = match.groupdict()
        data["datetime"] = datetime.strptime(data["date"].split()[0], "%d/%b/%Y:%H:%M:%S")
        return data
    return None

def is_suspicious(log):
    status = int(log["status"])
    if status == 403:
        return True
    if "login" in log["request"].lower() or "admin" in log["request"].lower():
        return True
    return False

🧪 analyzer.py – Script principal

from utils import parse_apache_log_line, is_suspicious
from collections import defaultdict

def analyze_log(file_path):
    suspicious_events = []
    ip_counter = defaultdict(int)

    with open(file_path, "r") as f:
        for line in f:
            log = parse_apache_log_line(line)
            if not log:
                continue

            ip = log["ip"]
            ip_counter[ip] += 1

            if is_suspicious(log):
                suspicious_events.append(log)

    return suspicious_events, ip_counter

def generate_report(suspicious_events, ip_counter, output_file="report.txt"):
    with open(output_file, "w") as f:
        f.write("=== Rapport de détection d'activités suspectes ===\n\n")

        f.write("Top IP par nombre de requêtes :\n")
        for ip, count in sorted(ip_counter.items(), key=lambda x: x[1], reverse=True)[:10]:
            f.write(f"{ip}: {count} requêtes\n")

        f.write("\nRequêtes suspectes détectées :\n")
        for event in suspicious_events:
            f.write(f"{event['datetime']} - {event['ip']} - {event['request']} - {event['status']}\n")

if __name__ == "__main__":
    log_path = "logs/access.log"
    suspicious_events, ip_counter = analyze_log(log_path)
    generate_report(suspicious_events, ip_counter)
    print("Rapport généré dans 'report.txt'.")

✅ Résultat attendu dans report.txt :

=== Rapport de détection d'activités suspectes ===

Top IP par nombre de requêtes :
192.168.1.100: 35 requêtes
10.0.0.8: 12 requêtes

Requêtes suspectes détectées :
2025-06-03 13:55:36 - 127.0.0.1 - GET /admin HTTP/1.1 - 403

🔄 À adapter facilement pour SSH :

    Changer le regex pour les logs /var/log/auth.log.

    Détecter des motifs comme "Failed password" ou "Invalid user".

Souhaites-tu une version SSH ou un dataset de test pour Apache ?