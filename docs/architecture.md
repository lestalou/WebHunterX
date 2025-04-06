# Architecture du Module XSS

Ce document décrit l'architecture technique du module de détection et d'exploitation des vulnérabilités XSS (Cross-Site Scripting) de WebHunterX.

## Aperçu

Le module XSS est conçu selon un modèle de pipeline avec les étapes suivantes:

1. **Crawling** - Exploration du site cible et identification des points d'injection
2. **Analyse** - Test des points d'injection avec différents payloads
3. **Exploitation** - Vérification des vulnérabilités et génération de preuves de concept
4. **Reporting** - Génération de rapports et recommandations de mitigation

## Structure des classes

### Classe principale: `XSSScanner`

La classe `XSSScanner` orchestre l'ensemble du processus de scan et contient les méthodes principales:

```
XSSScanner
├── __init__(target, options, http_config)
├── _load_payloads()
├── _init_database()
├── crawl()
│   ├── _extract_forms()
│   ├── _extract_url_parameters()
│   └── _extract_dom_events()
├── scan()
│   ├── test_injection_point()
│   ├── _test_url_parameter()
│   └── _test_form_input()
├── generate_report()
│   └── generate_poc()
├── generate_custom_payloads()
│   ├── _load_bypass_techniques()
│   └── _apply_bypass_techniques()
├── _test_browser_security_features()
├── generate_mitigation_recommendations()
└── run()
```

## Flux de données

1. Le crawling identifie les points d'injection potentiels et les stocke dans la liste `injection_points`.
2. Chaque point d'injection est testé avec les payloads chargés depuis `payloads/xss.txt`.
3. Les vulnérabilités détectées sont stockées dans la liste `vulnerabilities` et dans la base SQLite.
4. Un rapport est généré en JSON avec les détails de chaque vulnérabilité.

## Composants clés

### Système de crawling

Le système de crawling est responsable de:
- Scanner les pages web à la recherche de formulaires
- Analyser les paramètres d'URL
- Détecter les événements DOM potentiellement vulnérables

### Base de payloads

La bibliothèque de payloads est organisée par catégories:
- `basic`: Payloads XSS simples (`<script>alert(1)</script>`)
- `img`: Payloads basés sur la balise image (`<img src=x onerror=alert(1)>`)
- `svg`: Exploitation via SVG (`<svg onload=alert(1)>`)
- `dom`: Exploits spécifiques au DOM
- `waf_bypass`: Techniques pour contourner les WAFs
- *etc.*

### Système de bypass WAF

Le module implémente diverses techniques pour contourner les protections WAF:
- Encodage d'entités HTML
- Manipulation de casse
- Double encodage
- Techniques spécifiques par WAF (Cloudflare, Akamai, ModSecurity)

### Générateur de PoC

Le générateur de preuves de concept (PoC) crée des fichiers HTML interactifs pour chaque vulnérabilité:
- Interface utilisateur pour tester le payload
- Formulaire pré-rempli pour les vulnérabilités dans les formulaires
- URL pré-construite pour les vulnérabilités dans les paramètres

### Base de données

Une base SQLite est utilisée pour stocker:
- Points d'injection analysés
- Vulnérabilités détectées
- Détails techniques des exploits

## Diagramme de flux

```
┌─────────────┐       ┌───────────────┐       ┌──────────────┐       ┌───────────────┐
│             │       │               │       │              │       │               │
│   Crawling  ├──────►│  Analyse des  ├──────►│ Exploitation │──────►│    Rapport    │
│             │       │ vulnérabilités│       │              │       │               │
└─────────────┘       └───────────────┘       └──────────────┘       └───────────────┘
      │                      │                       │                       │
      ▼                      ▼                       ▼                       ▼
┌─────────────┐       ┌───────────────┐       ┌──────────────┐       ┌───────────────┐
│  Extraction │       │  Génération   │       │ Génération   │       │ Recommandations│
│  des points │       │  de payloads  │       │    de PoC    │       │ de mitigation  │
│ d'injection │       │ personnalisés │       │              │       │               │
└─────────────┘       └───────────────┘       └──────────────┘       └───────────────┘
```

## Extension du module

Le module XSS est conçu pour être facilement extensible:

1. **Ajout de nouveaux payloads**: Éditer le fichier `payloads/xss.txt`
2. **Nouvelles techniques de bypass**: Ajouter des transformations dans `_load_bypass_techniques()`
3. **Support de nouveaux WAFs**: Ajouter une entrée dans le dictionnaire `bypass_techniques`
4. **Types d'analyses supplémentaires**: Étendre la méthode `test_injection_point()`

## Algorithmes clés

### Détection des points d'injection

Le module utilise BeautifulSoup pour:
- Extraire les formulaires et leurs champs
- Identifier les gestionnaires d'événements JavaScript
- Analyser les paramètres d'URL

### Détection de réflexion XSS

L'algorithme de détection vérifie si:
1. Le payload brut apparaît dans la réponse
2. Une version décodée/nettoyée du payload est présente
3. Des fragments spécifiques (ex: valeurs d'alerte) apparaissent

### Classification des vulnérabilités

Les vulnérabilités sont classées par:
- Type de payload réussi
- Emplacement (URL, formulaire, DOM)
- Sévérité (déterminée par le type de payload et l'impact potentiel)

## Limites actuelles

- Support limité pour les applications SPA/JavaScript avancées
- Pas d'analyse JavaScript complète
- Détection incomplète des vulnérabilités DOM-based XSS
- Pas de support pour les applications nécessitant une authentification complexe

## Améliorations futures

- Intégration d'un moteur de rendu JavaScript (Playwright/Puppeteer)
- Support amélioré des frameworks JavaScript modernes
- Détection plus avancée des DOM XSS
- Émulation de navigateur pour tester des payloads en contexte réel 