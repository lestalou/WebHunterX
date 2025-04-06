# WebHunterX

![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.6%2B-green.svg)
![License](https://img.shields.io/badge/license-MIT-yellow.svg)

Framework avancé de test d'intrusion web, spécialisé dans la détection et l'exploitation de vulnérabilités de sécurité web.

## 🌟 Caractéristiques

- **Modules d'exploitation avancés** : XSS, SQLi, et plus
- **Détection intelligente** des points d'injection
- **Contournement de WAF** : Techniques avancées d'évasion
- **Rapports détaillés** : Exportation en HTML, JSON, CSV, Markdown
- **Preuves de concept interactives** pour démontrer les vulnérabilités
- **Interface en ligne de commande intuitive**
- **Architecture modulaire extensible**

## 📋 Modules disponibles

| Module | Description |
|--------|-------------|
| XSS | Détection et exploitation de vulnérabilités Cross-Site Scripting |
| SQLi | Injection SQL avec support pour MySQL, PostgreSQL, Oracle, SQLite et MSSQL |
| JWT | Analyse et exploitation de faiblesses dans les JSON Web Tokens |
| SSRF | Détection et exploitation de Server-Side Request Forgery |
| *Plus à venir...* | |

## 🔧 Installation

```bash
# Cloner le dépôt
git clone https://github.com/lestalou/WebHunterX.git
cd WebHunterX

# Installer les dépendances
pip install -r requirements.txt

# Installation en mode développement
pip install -e .
```

## 🚀 Utilisation rapide

### Scanner un site pour les vulnérabilités XSS

```bash
python webhunterx.py --module xss --url "https://exemple.com" --crawl
```

### Tester une URL pour l'injection SQL

```bash
python webhunterx.py --module sqli --url "https://exemple.com/page?id=1" --param id
```

### Générer un rapport complet

```bash
python webhunterx.py --module xss --url "https://exemple.com" --report html,json
```

## 📊 Exemple de sortie

```
[+] Analyse démarrée : https://exemple.com
[+] Mode de crawling activé
[+] 15 points d'injection potentiels identifiés
[+] Test de vulnérabilités XSS...
[!] Vulnérabilité XSS détectée dans le paramètre 'search' (POST)
    URL: https://exemple.com/recherche
    Payload: <script>alert(1)</script>
    Type: Reflected
[!] Vulnérabilité XSS détectée dans le paramètre 'id' (GET)
    URL: https://exemple.com/profile
    Payload: "><svg/onload=alert(document.domain)>
    Type: DOM-based
[+] Génération du rapport...
[+] Rapport enregistré dans output/xss_report_1617293456.html
```

## 📚 Documentation

Pour une documentation complète, consultez [docs/README.md](docs/README.md).

### Options disponibles

| Option | Description |
|--------|-------------|
| `--url` | URL cible à analyser |
| `--module` | Module à utiliser (xss, sqli, etc.) |
| `--crawl` | Activer le crawling automatique |
| `--depth` | Profondeur de crawling (défaut: 2) |
| `--threads` | Nombre de threads pour les tests parallèles |
| `--timeout` | Délai d'attente des requêtes en secondes |
| `--headers` | En-têtes HTTP personnalisés (format JSON) |
| `--cookies` | Cookies à utiliser pour l'authentification |
| `--proxy` | Proxy à utiliser (format: http://user:pass@host:port) |
| `--report` | Format de rapport (html,json,csv,md) |
| `--output` | Répertoire de sortie pour les rapports |
| `--verbose` | Activer le mode verbeux |

## 🛠️ Contribution

Les contributions sont les bienvenues ! Consultez [CONTRIBUTING.md](CONTRIBUTING.md) pour les directives de contribution.

1. Forkez le projet
2. Créez votre branche de fonctionnalité (`git checkout -b feature/nouvelle-fonctionnalite`)
3. Committez vos changements (`git commit -m 'Ajout de nouvelle fonctionnalité'`)
4. Poussez à la branche (`git push origin feature/nouvelle-fonctionnalite`)
5. Ouvrez une Pull Request

## 📝 Licence

Ce projet est sous licence MIT - voir le fichier [LICENSE](LICENSE) pour plus de détails.

## 🔗 Liens

- [Changelog](CHANGELOG.md)
- [Guide de développement](docs/development.md)
- [Documentation API](docs/api.md)

## ✨ Remerciements

- Tous les contributeurs qui ont participé à ce projet
- Communauté de la sécurité informatique pour leur retour et suggestions

---

Créé avec ❤️ par l'équipe WebHunterX
