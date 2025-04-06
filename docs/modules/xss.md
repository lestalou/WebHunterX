# Module XSS

Le module XSS (Cross-Site Scripting) de WebHunterX permet de détecter et d'exploiter les vulnérabilités XSS dans les applications web. Ce module identifie divers types de vulnérabilités XSS et fournit des payloads adaptés pour le contournement des mesures de sécurité courantes.

## Types de XSS supportés

WebHunterX détecte trois types principaux de XSS :

- **XSS Réfléchi** : Les payloads injectés dans une requête sont immédiatement renvoyés dans la réponse
- **XSS Stocké** : Les payloads sont stockés sur le serveur et affichés ultérieurement à d'autres utilisateurs
- **XSS basé sur le DOM** : Les payloads sont exécutés via des manipulations du DOM côté client

## Caractéristiques principales

- **Détection intelligente des points d'injection** : Analyse automatique des points d'injection potentiels
- **Contournement de WAF** : Techniques avancées pour éviter les protections des WAFs courants (ModSecurity, Cloudflare, etc.)
- **Classification des contextes** : Détection du contexte d'exécution (HTML, attributs, JavaScript, CSS)
- **Génération de preuves de concept** : Création automatique de PoC pour démontrer l'impact des vulnérabilités
- **Obfuscation adaptative** : Encodage et obfuscation en fonction du contexte détecté
- **Évaluation de la gravité** : Calcul du niveau de risque en fonction de l'impact potentiel

## Utilisation de base

```bash
# Analyse de base d'une URL
python webhunterx.py --module xss --url "https://exemple.com"

# Analyse avec authentification
python webhunterx.py --module xss --url "https://exemple.com" --cookies "PHPSESSID=abc123; auth=xyz789"

# Analyse ciblée d'un paramètre spécifique
python webhunterx.py --module xss --url "https://exemple.com/search?q=test" --param q

# Analyse avec contournement de WAF
python webhunterx.py --module xss --url "https://exemple.com" --waf cloudflare
```

## Options spécifiques

| Option | Description |
|--------|-------------|
| `--param` | Paramètre spécifique à tester |
| `--waf` | Type de WAF à contourner (cloudflare, akamai, modsecurity, etc.) |
| `--obfuscation` | Niveau d'obfuscation (0-3) |
| `--context` | Contexte d'injection à cibler (html, js, attr, etc.) |
| `--poc` | Type de preuve de concept à générer (alert, cookie, ajax, etc.) |
| `--custom-payloads` | Fichier de payloads personnalisés |

## Techniques avancées

### Contournement de filtres

Le module XSS implémente plusieurs techniques de contournement des filtres de sécurité :

```python
# Payload bypass examples
"<svg/onload=alert(1)>"                    # SVG event handler
"<img src=x onerror=alert(1)>"             # Error event handlers
"<script>eval(atob('YWxlcnQoMSk='))</script>" # Base64 encoding
"<script>setTimeout('ale'+'rt(1)',0)</script>" # String splitting
"jav&#x61;script:alert(1)"                 # HTML entity encoding
"<a href=javascript:&#x61;lert(1)>click</a>" # URL encoding bypass
```

### Détection de contexte

Le module peut détecter automatiquement le contexte de l'injection et adapter ses payloads :

- **Contexte HTML** : `<img src=x onerror=alert(1)>`
- **Contexte d'attribut** : `" onmouseover="alert(1)`
- **Contexte JavaScript** : `';alert(1)//`
- **Contexte URL** : `javascript:alert(1)`
- **Contexte CSS** : `</style><script>alert(1)</script>`

### PoC avancés

Pour les vulnérabilités confirmées, le module peut générer des preuves de concept avancées :

- **Vol de cookies** : Exfiltration des cookies vers un serveur contrôlé
- **Keyloggers** : Enregistrement des frappes au clavier
- **Capture de formulaires** : Extraction des données saisies dans les formulaires
- **Pivotage interne** : Exploitation pour les attaques sur le réseau interne

## Exemple de rapport

Le module XSS génère des rapports détaillés dans différents formats :

```json
{
  "timestamp": "2023-06-30T14:22:45",
  "target": "https://exemple.com/search?q=test",
  "vulnerabilities": [
    {
      "type": "XSS_REFLECTED",
      "parameter": "q",
      "method": "GET",
      "context": "html_body",
      "payload": "<img src=x onerror=alert(1)>",
      "proof": "Payload exécuté dans la réponse HTTP",
      "severity": "medium",
      "poc": "https://exemple.com/search?q=%3Cimg%20src%3Dx%20onerror%3Dalert%281%29%3E",
      "remediation": "Échapper les caractères spéciaux HTML avec htmlspecialchars()"
    }
  ],
  "scan_details": {
    "params_tested": 4,
    "payloads_sent": 32,
    "scan_duration": "00:02:45",
    "waf_detected": false
  }
}
```

## Architecture interne

Le module XSS est composé de plusieurs sous-modules :

1. **Détecteur de points d'injection** : Analyse la structure des pages et identifie les points d'injection potentiels
2. **Analyseur de contexte** : Détermine le contexte d'exécution du code injecté
3. **Générateur de payloads** : Crée des payloads adaptés au contexte détecté
4. **Moteur d'exploitation** : Exploite les vulnérabilités identifiées
5. **Générateur de rapports** : Produit des rapports détaillés sur les vulnérabilités trouvées

## Intégration avec d'autres modules

Le module XSS peut s'intégrer avec d'autres modules de WebHunterX :

- **Module de crawling** : Pour explorer automatiquement l'application
- **Module d'authentification** : Pour tester les zones protégées par authentification
- **Module de reporting** : Pour générer des rapports consolidés

## Bonnes pratiques de correction

Le rapport inclut des recommandations de correction personnalisées en fonction du contexte :

- Utilisation de fonctions d'échappement appropriées (`htmlspecialchars()`, `encodeURIComponent()`)
- Implémentation d'une politique de sécurité du contenu (CSP)
- Validation côté serveur des entrées utilisateur
- Utilisation de frameworks qui échappent automatiquement les sorties

## Outils complémentaires

WebHunterX inclut des outils complémentaires pour le module XSS :

- **XSS Fuzzer** : Pour identifier des vecteurs XSS moins connus
- **CSP Analyzer** : Pour évaluer les politiques de sécurité du contenu
- **Proxy d'exploitation** : Pour faciliter l'exploitation manuelle des vulnérabilités détectées

## Références

- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [OWASP XSS Filter Evasion Cheat Sheet](https://owasp.org/www-community/xss-filter-evasion-cheatsheet)
- [PortSwigger XSS Cheat Sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet) 