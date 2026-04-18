#!/usr/bin/env python3
"""
Port Scanner - Scanner de ports TCP
Sokhna Oumou Diouf

Petit outil pour scanner les ports ouverts sur une machine
et voir quels services tournent dessus.
"""

import socket
import sys
import time
from datetime import datetime

# les ports qu'on rencontre le plus souvent avec leur service
SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    8080: "HTTP Proxy",
    8443: "HTTPS Alt",
    27017: "MongoDB",
}

# ports qui posent des problemes de secu si ils sont ouverts
PORTS_DANGEREUX = {
    23: "Telnet envoie les mots de passe en clair",
    21: "FTP envoie aussi les identifiants en clair, mieux vaut utiliser SFTP",
    445: "SMB est souvent exploite par des ransomwares (WannaCry par ex)",
    3389: "RDP est cible par les attaques brute force",
    3306: "MySQL ne devrait pas etre expose sur internet",
    27017: "MongoDB a pas d'auth par defaut",
}


def resoudre_cible(cible):
    """Transforme un nom de domaine en adresse IP"""
    try:
        return socket.gethostbyname(cible)
    except socket.gaierror:
        print(f"\n[!] Erreur : impossible de resoudre '{cible}'")
        return None


def scan_port(ip, port, timeout=1):
    """Teste si un port est ouvert avec une connexion TCP"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((ip, port))
        s.close()
        return result == 0  # 0 = connexion reussie = port ouvert
    except socket.error:
        return False


def grab_banner(ip, port, timeout=2):
    """
    Essaye de recuperer la banniere du service (banner grabbing).
    Ca permet de savoir quelle version tourne sur le port
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        s.send(b"HEAD / HTTP/1.1\r\nHost: target\r\n\r\n")
        banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
        s.close()
        if banner:
            return banner.split("\n")[0][:80]  # juste la premiere ligne
        return None
    except:
        return None


def get_service(port):
    """Retourne le nom du service ou '?' si on connait pas"""
    return SERVICES.get(port, "?")


def afficher_progression(i, total):
    """Petite barre de progression"""
    pct = i / total
    nb = int(40 * pct)
    barre = "#" * nb + "." * (40 - nb)
    sys.stdout.write(f"\r  [{barre}] {pct:.0%}")
    sys.stdout.flush()


def lancer_scan(cible, debut=1, fin=1024, timeout=1):
    """Fonction principale qui lance le scan sur la cible"""
    ip = resoudre_cible(cible)
    if not ip:
        return []

    print(f"\n  Cible     : {cible} ({ip})")
    print(f"  Ports     : {debut} -> {fin}")
    print(f"  Debut     : {datetime.now().strftime('%H:%M:%S')}")
    print()

    ports_ouverts = []
    total = fin - debut + 1
    t0 = time.time()

    for i, port in enumerate(range(debut, fin + 1), 1):
        afficher_progression(i, total)

        if scan_port(ip, port, timeout):
            service = get_service(port)
            banner = grab_banner(ip, port)
            ports_ouverts.append({
                "port": port,
                "service": service,
                "banner": banner,
            })

    duree = time.time() - t0

    # affichage des resultats
    print(f"\n\n  === RESULTATS ===\n")

    if ports_ouverts:
        print(f"  {len(ports_ouverts)} port(s) ouvert(s) :\n")
        print(f"  {'PORT':<8} {'SERVICE':<18} {'STATUT'}")
        print(f"  {'---':<8} {'---':<18} {'---':<10}")

        for p in ports_ouverts:
            print(f"  {p['port']:<8} {p['service']:<18} OUVERT")
            if p["banner"]:
                print(f"  {'':>8} Banniere: {p['banner']}")

            # warning si le port est connu pour etre dangereux
            if p["port"] in PORTS_DANGEREUX:
                print(f"  {'':>8} /!\\ {PORTS_DANGEREUX[p['port']]}")
            print()
    else:
        print("  Aucun port ouvert trouve.")
        print("  (la cible est protegee ou les ports sont filtres)\n")

    print(f"  Duree    : {duree:.2f}s")
    print(f"  Scannes  : {total}")
    print(f"  Ouverts  : {len(ports_ouverts)}")
    print(f"  Fermes   : {total - len(ports_ouverts)}")

    # mini rapport de secu
    dangers = [p for p in ports_ouverts if p["port"] in PORTS_DANGEREUX]
    if dangers:
        print(f"\n  === ALERTES SECURITE ===\n")
        for p in dangers:
            print(f"  - Port {p['port']} ({p['service']}) : {PORTS_DANGEREUX[p['port']]}")
        print(f"\n  -> Fermer les ports inutiles et utiliser des protocoles chiffres")

    return ports_ouverts


def main():
    print("\n  === PORT SCANNER ===\n")

    cible = input("  Cible (IP ou domaine) : ").strip()
    if not cible:
        print("[!] Cible vide")
        sys.exit(1)

    print("\n  Plage de ports :")
    print("  [1] 1-100    (rapide)")
    print("  [2] 1-1024   (standard)")
    print("  [3] 1-5000   (etendu)")
    print("  [4] Custom")

    choix = input("\n  Choix : ").strip()

    plages = {"1": (1, 100), "2": (1, 1024), "3": (1, 5000)}
    if choix in plages:
        debut, fin = plages[choix]
    elif choix == "4":
        try:
            debut = int(input("  Port debut : "))
            fin = int(input("  Port fin   : "))
            if debut < 1 or fin > 65535 or debut > fin:
                raise ValueError
        except ValueError:
            print("[!] Plage invalide")
            sys.exit(1)
    else:
        debut, fin = 1, 100

    print(f"\n  Lancement du scan...")
    lancer_scan(cible, debut, fin)
    print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n  Scan interrompu.")
        sys.exit(0)
