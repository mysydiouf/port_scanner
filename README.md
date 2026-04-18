# port_scanner

Scanner de ports TCP en Python. Permet de trouver les ports ouverts sur une machine et d'identifier les services qui tournent dessus.

## Ce que ça fait

- Scan des ports TCP sur une cible (IP ou nom de domaine)
- Identification des services connus (HTTP, SSH, FTP, MySQL...)
- Banner grabbing pour récupérer la version des services
- Alerte si un port dangereux est ouvert (Telnet, RDP, SMB...)
- Barre de progression pendant le scan

## Lancer le programme

```bash
python3 port_scanner.py
```

Il suffit d'entrer l'adresse de la cible et de choisir la plage de ports. Pour tester sans risque, utiliser `scanme.nmap.org` (serveur mis à dispo par Nmap pour ça).

Python 3.8+ requis, pas de dépendance externe.

## Exemple

```
  === PORT SCANNER ===

  Cible     : scanme.nmap.org (45.33.32.156)
  Ports     : 1 -> 100

  === RESULTATS ===

  2 port(s) ouvert(s) :

  PORT     SERVICE            STATUT
  22       SSH                OUVERT
  80       HTTP               OUVERT
           /!\ HTTP non chiffre

  Duree    : 28.43s
  Scannes  : 100
  Ouverts  : 2
```

## Comment ça marche

Le scanner utilise des sockets TCP. Pour chaque port, il tente une connexion avec `connect_ex()` : si ça retourne 0, le port est ouvert. C'est un scan TCP connect classique.

Le banner grabbing envoie une requête HTTP basique et lit la réponse du serveur pour identifier la version du service.

## Avertissement

A utiliser uniquement sur des machines qu'on a le droit de scanner. Scanner des machines sans autorisation c'est illégal.

## Auteur

Sokhna Oumou Diouf - L2 Informatique, Sorbonne Université
