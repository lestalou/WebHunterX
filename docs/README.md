# Documentation WebHunterX

Bienvenue dans la documentation officielle de WebHunterX, un framework avancé de test d'intrusion web spécialisé dans la détection et l'exploitation de vulnérabilités de sécurité web.

## Guides

- [Guide d'installation](installation.md)
- [Guide de démarrage rapide](quickstart.md)
- [Guide du développeur](development.md)
- [API Reference](api.md)

## Modules

WebHunterX est conçu avec une architecture modulaire permettant d'ajouter facilement de nouvelles fonctionnalités. Voici les modules actuellement disponibles :

### Module XSS

Le module XSS (Cross-Site Scripting) permet de détecter et d'exploiter les vulnérabilités XSS dans les applications web.

- [Documentation du module XSS](modules/xss.md)
- Capacités :
  - Détection de XSS réfléchi, persistant et basé sur le DOM
  - Techniques avancées de contournement de WAF
  - Génération de preuves de concept interactives
  - Analyse complète des points d'injection

### Module SQLi

Le module SQLi (SQL Injection) permet de détecter et d'exploiter les vulnérabilités d'injection SQL.

- [Documentation du module SQLi](modules/sqli.md)
- Capacités :
  - Support pour MySQL, PostgreSQL, Oracle, SQLite et MSSQL
  - Techniques d'injection basées sur les erreurs, en aveugle et temporelles
  - Extraction automatisée de données
  - Fingerprinting de base de données

### Module Command Injection

Le module Command Injection permet de détecter et d'exploiter les vulnérabilités d'injection de commandes.

- [Documentation du module Command Injection](modules/cmdi.md)
- Capacités :
  - Détection multi-OS (Windows, Unix)
  - Techniques de contournement avancées
  - Upload de shells web
  - Exécution de commandes personnalisées

### Modules supplémentaires

- [Documentation du module JWT](modules/jwt.md)
- [Documentation du module SSRF](modules/ssrf.md)

## Architecture

WebHunterX est construit autour d'une architecture modulaire qui facilite l'extension et la maintenance du code.

- [Vue d'ensemble de l'architecture](architecture/overview.md)
- [Flux de données](architecture/data-flow.md)
- [Système de plugins](architecture/plugin-system.md)

## Référence des commandes

WebHunterX propose une interface en ligne de commande complète. Voici les principales options disponibles :

```
Utilisation: webhunterx [options] --url <target>

Options générales:
  --url URL               URL cible à analyser
  --module MODULE         Module à utiliser (xss, sqli, cmdi, etc.)
  --crawl                 Activer le crawling automatique
  --depth N               Profondeur de crawling (défaut: 2)
  --threads N             Nombre de threads pour les tests parallèles
  --timeout N             Délai d'attente des requêtes en secondes
  --headers JSON          En-têtes HTTP personnalisés (format JSON)
  --cookies STR           Cookies à utiliser pour l'authentification
  --proxy URL             Proxy à utiliser (format: http://user:pass@host:port)
  --report FORMAT         Format de rapport (html,json,csv,md)
  --output DIR            Répertoire de sortie pour les rapports
  --verbose               Activer le mode verbeux
  --help                  Afficher l'aide et quitter

Options spécifiques aux modules:
  --param PARAM           Paramètre cible pour l'injection
  --data DATA             Données POST à envoyer
  --method METHOD         Méthode HTTP à utiliser (GET, POST)
  --custom-payloads FILE  Fichier de payloads personnalisés
  --risk LEVEL            Niveau de risque (1-3)
```

## Guides avancés

- [Contournement de WAF](advanced/waf-bypass.md)
- [Création de payloads personnalisés](advanced/custom-payloads.md)
- [Intégration avec d'autres outils](advanced/integration.md)
- [Automatisation avec WebHunterX](advanced/automation.md)

## Contribuer

WebHunterX est un projet open-source et les contributions sont les bienvenues !

- [Guide de contribution](../CONTRIBUTING.md)
- [Roadmap du projet](roadmap.md)
- [Signaler un bug](https://github.com/lestalou/WebHunterX/issues/new?template=bug_report.md)
- [Proposer une fonctionnalité](https://github.com/lestalou/WebHunterX/issues/new?template=feature_request.md)

## FAQ

- [Questions fréquemment posées](faq.md)

## Licence

WebHunterX est distribué sous la [licence MIT](../LICENSE).

---

**Note** : Cette documentation est mise à jour régulièrement. Si vous constatez des erreurs ou des omissions, n'hésitez pas à [contribuer](../CONTRIBUTING.md) ou à [ouvrir une issue](https://github.com/lestalou/WebHunterX/issues/new). 