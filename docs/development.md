# Guide de développement

Ce document fournit des informations pour les développeurs qui souhaitent contribuer au module XSS de WebHunterX.

## Environnement de développement

### Prérequis

- Python 3.6 ou supérieur
- Modules Python requis :
  - requests
  - beautifulsoup4
  - colorama
  - urllib3
  
### Installation de l'environnement de développement

```bash
# Cloner le dépôt
git clone https://github.com/webhunterx/webhunterx.git
cd webhunterx

# Créer un environnement virtuel (recommandé)
python -m venv venv
source venv/bin/activate  # Linux/Mac
# ou
venv\Scripts\activate  # Windows

# Installer en mode développement
pip install -e ".[dev]"
```

### Structure des tests

Les tests sont organisés dans le répertoire `tests/` :

```
tests/
├── unit/             # Tests unitaires
│   ├── test_xss.py
│   └── ...
├── integration/      # Tests d'intégration
│   ├── test_xss_scanner.py
│   └── ...
└── payloads/         # Payloads de test
```

### Exécution des tests

```bash
# Exécuter tous les tests
pytest

# Exécuter une suite de tests spécifique
pytest tests/unit/test_xss.py

# Exécuter un test spécifique
pytest tests/unit/test_xss.py::test_bypass_techniques
```

## Conventions de codage

### Style de code

- Suivez [PEP 8](https://www.python.org/dev/peps/pep-0008/) pour le style de code Python
- Limitez les lignes à 100 caractères
- Utilisez des docstrings au format [Google Style](https://sphinxcontrib-napoleon.readthedocs.io/en/latest/example_google.html)
- Utilisez des annotations de type (type hints)

### Structure des commits

- Un commit par fonctionnalité ou correction
- Messages de commit clairs et concis
- Format : `[type]: sujet` où `type` est `feat`, `fix`, `docs`, `style`, `refactor`, `test`, ou `chore`

### Processus de développement

1. Créez une branche à partir de `main` pour votre fonctionnalité
2. Implémentez votre code avec des tests
3. Assurez-vous que tous les tests passent
4. Créez une pull request vers `main`

## Ajouter de nouvelles fonctionnalités au module XSS

### Ajouter de nouveaux payloads

Les payloads sont stockés dans `payloads/xss.txt` et organisés par catégories :

```
[section_name]
payload1
payload2
```

Pour ajouter une nouvelle catégorie de payloads :

1. Ajoutez une section au fichier `payloads/xss.txt`
2. Mettez à jour la méthode `_load_payloads()` pour prendre en compte cette catégorie

### Ajouter une nouvelle technique de bypass WAF

1. Identifiez le type de WAF et la technique de contournement
2. Ajoutez la technique dans `_load_bypass_techniques()` :

```python
bypass_techniques = {
    'waf_type': [
        {
            'description': 'Description de la technique',
            'transform': lambda p: p.replace('x', 'y')  # Fonction de transformation
        }
    ]
}
```

### Étendre le système de détection

Pour ajouter un nouveau type de détection :

1. Créez une méthode `_extract_new_injection_points()` dans la classe `XSSScanner`
2. Mettez à jour la méthode `crawl()` pour appeler votre nouvelle méthode
3. Implémentez un nouveau type de test dans `test_injection_point()`

### Améliorer le système de reporting

1. Ajoutez de nouvelles données dans la structure `vuln_info` dans `generate_report()`
2. Mettez à jour le modèle HTML dans `generate_poc()` pour afficher ces informations

## Débogage

### Utilisation du mode verbeux

```bash
python -m webhunterx.xss https://exemple.com -v
```

### Journalisation

Le module utilise le logger intégré. Pour modifier le niveau de journalisation :

```python
logger.setLevel(logging.DEBUG)
```

### Outils de débogage

- Utilisez `pdb` pour le débogage interactif : `import pdb; pdb.set_trace()`
- Utilisez la méthode `_test_browser_security_features()` pour inspecter les comportements des navigateurs

## Documentation

### Documentation du code

Assurez-vous que chaque fonction et classe a une docstring complète :

```python
def function_name(param1, param2):
    """
    Description de la fonction.
    
    Args:
        param1: Description du paramètre 1
        param2: Description du paramètre 2
        
    Returns:
        Description de la valeur de retour
        
    Raises:
        ExceptionType: Quand/pourquoi l'exception est levée
    """
```

### Documentation utilisateur

La documentation utilisateur se trouve dans le répertoire `docs/` :

1. Mettez à jour `usage.md` pour les nouvelles fonctionnalités
2. Mettez à jour `architecture.md` si vous modifiez l'architecture

## Publication

### Préparation d'une nouvelle version

1. Mettez à jour le fichier `webhunterx/__init__.py` avec le nouveau numéro de version
2. Mettez à jour `CHANGELOG.md` avec les modifications
3. Créez un tag Git pour la version

### Construction du package

```bash
python setup.py sdist bdist_wheel
```

### Publication sur PyPI (pour les mainteneurs)

```bash
twine upload dist/*
```

## Questions fréquentes

### Comment implémenter un test pour une nouvelle fonctionnalité ?

1. Créez un test dans `tests/unit/` ou `tests/integration/` selon le cas
2. Utilisez un serveur HTTP de test pour simuler les vulnérabilités
3. Vérifiez que votre fonctionnalité détecte correctement les vulnérabilités

### Comment déboguer un problème d'exploitation ?

1. Utilisez le mode verbeux `-v`
2. Vérifiez la réponse HTTP brute avec `--debug-responses`
3. Testez le payload directement dans le navigateur pour confirmer l'exploitation 