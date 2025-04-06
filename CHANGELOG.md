# Changelog

Toutes les modifications notables apportées à ce projet seront documentées dans ce fichier.

Le format est basé sur [Keep a Changelog](https://keepachangelog.com/fr/1.0.0/),
et ce projet adhère au [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-04-06

### Ajouté
- Module XSS complet avec détection avancée des vulnérabilités
- Système de crawling pour identifier les points d'injection (formulaires, URL, DOM)
- Bibliothèque de payloads XSS organisée par catégories
- Techniques de bypass WAF pour Cloudflare, Akamai et ModSecurity
- Obfuscation des payloads avec 3 niveaux de complexité
- Génération de rapports au format JSON
- Preuves de concept HTML interactives pour chaque vulnérabilité
- Base de données SQLite pour stocker les résultats
- Recommandations de mitigation personnalisées
- Documentation complète (usage, architecture, développement)

### Changé
- Structure du projet réorganisée pour plus de modularité
- Amélioration des performances de crawling

### Corrigé
- Problèmes d'importation des modules
- Gestion des chemins de fichiers pour les payloads
- Affichage des payloads personnalisés

## [0.1.0] - 2025-03-15

### Ajouté
- Version initiale du framework
- Structure de base du projet
- Modules scaffolding 